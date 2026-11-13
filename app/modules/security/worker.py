"""The detection worker: inspect request copies after the answer, and record what matched.

The detection layer (app/modules/security/layer.py) hands each request's copy to
submit(), which never waits (rule DE11, threat D5):
- The queue holds at most 200 copies. When it is full, the new copy is dropped and only
  counted; each minute the count is written as one `detection.dropped` row. Dropping is
  safe because detection is a record, not a protection.

One worker thread (start()) then takes the copies one at a time, after the answers have
gone out (rule DE2), so detection never makes a request slower:
1. Run the detector (app/detection) on the copy's values.
2. Turn each finding into an Event: in the session's company and naming the person when
   the request carried a valid session, otherwise a platform event (rule DE9). The rate
   cap counts it against the session, or the address when nobody was signed in.
3. Hand the events to the writer (app/modules/security/writer.py), which applies the
   rate cap (DE6) and inserts the rows. If some rows could not be saved, the writer
   names exactly those events (EventWriteError.unsaved); they are written again with the
   next copy, so nothing saved is written twice and nothing unsaved is lost, up to
   MAX_RETRY events (beyond that the oldest are let go and the loss is logged, so a long
   database outage cannot grow memory without bound).
4. Each time it takes a copy, and at least every 10 seconds, ask the writer to write the
   summary rows of minutes that have ended, and once a minute write the drop count.

The application runs one server process, so the queue and the caps are for the whole
API. Tests call run_once() themselves instead of starting the thread.
"""

import contextlib
import logging
import queue
import threading
import time
from collections.abc import Callable

from app.detection import inspect
from app.modules.security.layer import RequestCopy
from app.modules.security.writer import Event, EventWriteError, EventWriter

logger = logging.getLogger(__name__)

QUEUE_SIZE = 200  # request copies waiting at most (DE11)
WAKE_EVERY = 10.0  # seconds: the longest the worker waits before checking the minute
DROPS_EVERY = 60.0  # seconds between two `detection.dropped` rows
MAX_RETRY = 1_000  # unsaved events kept to write again


def events_for(copy: RequestCopy) -> list[Event]:
    """The events for one request copy: one per pattern matched per value."""
    identity = copy.identity
    # Who the rate cap counts it against (DE6): the session, or the address.
    if identity is not None:
        source = f"session:{identity.session_id}"
    else:
        source = f"address:{copy.client_address or 'unknown'}"
    return [
        Event(
            kind=f"detection.{finding.kind}",
            source=source,
            occurred_at=copy.occurred_at,
            pattern_id=finding.pattern_id,
            field=finding.field,
            method=copy.method,
            route=copy.route,
            client_address=copy.client_address,
            request_id=copy.request_id,
            excerpt=finding.excerpt,  # at most 200 characters of the original (DE7)
            # Both from the verified session, or neither (DE9).
            company_id=identity.company_id if identity else None,
            user_id=identity.user_id if identity else None,
        )
        for finding in inspect(copy.values)
    ]


class DetectionWorker:
    """The queue between the requests and the worker thread, and the thread itself.

    `make_writer` builds the EventWriter on first use, so creating the application does
    not open a database connection. Tests replace `writer` with their own.
    """

    def __init__(
        self,
        make_writer: Callable[[], EventWriter],
        *,
        size: int = QUEUE_SIZE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._make_writer = make_writer
        self._writer: EventWriter | None = None
        self.clock = clock  # replaceable in tests, so a minute of drops can end on demand
        self.queue: queue.Queue[RequestCopy | None] = queue.Queue(maxsize=size)
        # The drop counter is changed by requests (any thread) and read by the worker.
        self._drops_lock = threading.Lock()
        self._drops = 0
        self._drops_since = clock()
        self._retry: list[Event] = []
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    @property
    def writer(self) -> EventWriter:
        if self._writer is None:
            self._writer = self._make_writer()
        return self._writer

    @writer.setter
    def writer(self, writer: EventWriter) -> None:
        self._writer = writer

    @property
    def dropped(self) -> int:
        """Copies dropped and not yet written as a `detection.dropped` row."""
        with self._drops_lock:
            return self._drops

    # --- The request side: never waits ---------------------------------------------

    def submit(self, copy: RequestCopy) -> None:
        """Queue a copy for inspection, or drop and count it if the queue is full."""
        try:
            self.queue.put_nowait(copy)
        except queue.Full:
            with self._drops_lock:
                self._drops += 1

    # --- The worker side ------------------------------------------------------------

    def run_once(self, *, timeout: float | None = 0.0) -> bool:
        """Take one copy (waiting at most `timeout` seconds; None waits up to
        WAKE_EVERY), inspect it, and record its events. Then do the minute's chores.
        Returns whether a copy was taken."""
        wait = WAKE_EVERY if timeout is None else timeout
        try:
            copy = self.queue.get(block=wait > 0, timeout=wait if wait > 0 else None)
        except queue.Empty:
            copy = None
        if copy is not None:
            try:
                self._write(events_for(copy))
            except Exception:
                # A bug here must not stop the worker. Never log the values.
                logger.error("Detection could not inspect a request copy")
        self._chores()
        return copy is not None

    def drain(self) -> None:
        """Handle every copy waiting now (tests, and the last step of stop())."""
        while self.run_once(timeout=0.0):
            pass

    def _write(self, events: list[Event]) -> None:
        """Hand events to the writer, with any earlier unsaved ones first."""
        batch, self._retry = self._retry + events, []
        if not batch:
            return
        try:
            self.writer.write(batch)
        except EventWriteError as error:
            # Only the unsaved ones go again; none of them used up a place under the cap.
            unsaved = error.unsaved
            if len(unsaved) > MAX_RETRY:
                logger.error(
                    "Detection let go of unsaved security events",
                    extra={"fields": {"events": len(unsaved) - MAX_RETRY}},
                )
                unsaved = unsaved[-MAX_RETRY:]
            self._retry = unsaved
            logger.warning(
                "Security events not saved yet; trying again",
                extra={"fields": {"events": len(unsaved)}},
            )

    def _chores(self) -> None:
        """Summaries of ended minutes (DE6), and the drop count once a minute (DE11)."""
        # Before anything is written there is no counter waiting, and no connection opened.
        if self._writer is not None:
            try:
                self._writer.flush_due()
            except EventWriteError:
                logger.warning("Security event summaries not saved yet; trying again")
        if self.clock() - self._drops_since >= DROPS_EVERY:
            self._write_drops()

    def _write_drops(self) -> None:
        """Write the drop count as one row; on failure keep the count for next time."""
        with self._drops_lock:
            count, self._drops = self._drops, 0
            self._drops_since = self.clock()
        if count == 0:
            return
        try:
            self.writer.record_dropped(count)
        except EventWriteError:
            with self._drops_lock:
                self._drops += count
            logger.warning("Detection drop count not saved yet; trying again")

    # --- Starting and stopping, from the application's lifespan ----------------------

    def start(self) -> None:
        """Start the worker thread (the application is starting)."""
        if self._thread is not None:
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._loop, name="detection", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                self.run_once(timeout=None)
            except Exception:
                # The thread must outlive any one failure; never log the values.
                logger.error("Detection worker step failed")

    def stop(self) -> None:
        """Stop the thread, handle what is still queued, and write every count still
        held (the application is stopping), so a clean stop loses nothing."""
        if self._thread is not None:
            self._stopping.set()
            # Wake the thread at once. If the queue is full, it is busy with the queue
            # anyway and sees the flag soon.
            with contextlib.suppress(queue.Full):
                self.queue.put_nowait(None)
            self._thread.join(timeout=WAKE_EVERY * 2)
            self._thread = None
        try:
            self.drain()
            self._write_drops()
            if self._writer is not None:
                self._writer.close()
        except Exception:
            logger.error("Detection could not write its last counts")
