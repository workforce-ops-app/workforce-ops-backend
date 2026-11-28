"""The ELF reader behind scripts/check_native_hardening.py (threat E10, #107).

The real check reads the container images and needs Docker; these tests build small ELF
files by hand, each with or without one defense, so the reader is shown to tell them
apart. An ELF file is a header, a list of program headers (how it is laid out in memory),
and sections; the reader looks at the program headers, the dynamic section (the loader's
flags), and the dynamic symbols (the functions it calls).
"""

import struct

import pytest

from scripts import check_native_hardening as check

# Program header types and flags, as in the script.
PT_LOAD = 1
READ_WRITE, READ_WRITE_EXECUTE = 6, 7


def make_elf(
    *,
    program: bool = True,
    fixed_address: bool = False,
    stack: int | None = READ_WRITE,
    relro: bool = True,
    bind_now: bool = True,
    symbols: tuple[str, ...] = ("__stack_chk_fail", "__memcpy_chk"),
    needed: tuple[str, ...] = (),
    runpath: str | None = None,
    property_note: bytes | None = None,
) -> bytes:
    """A minimal 64-bit little-endian x86-64 ELF file with the given properties."""
    # The strings: library names and symbol names, each ending in a zero byte.
    strings = b"\0"
    offsets = {}
    for name in (*needed, *([runpath] if runpath else []), *symbols):
        offsets[name] = len(strings)
        strings += name.encode() + b"\0"

    # The dynamic section: needed libraries, BIND_NOW if asked, and the end marker.
    dynamic = b"".join(struct.pack("<qQ", check.DT_NEEDED, offsets[n]) for n in needed)
    if runpath:
        dynamic += struct.pack("<qQ", check.DT_RUNPATH, offsets[runpath])
    if bind_now:
        dynamic += struct.pack("<qQ", check.DT_FLAGS, check.DF_BIND_NOW)
    dynamic += struct.pack("<qQ", check.DT_NULL, 0)

    # The dynamic symbols: the first entry is always empty.
    symbol_table = bytes(24) + b"".join(
        struct.pack("<IBBHQQ", offsets[name], 0x12, 0, 0, 0, 0) for name in symbols
    )

    # Which program headers there are (their contents are placed after them).
    note = property_note or b""
    headers = [(PT_LOAD, 5)]
    if program:
        headers.append((check.PT_INTERP, 4))
    if stack is not None:
        headers.append((check.PT_GNU_STACK, stack))
    if relro:
        headers.append((check.PT_GNU_RELRO, 4))
    headers.append((check.PT_DYNAMIC, 6))
    if note:
        headers.append((check.PT_GNU_PROPERTY, 4))

    # Layout: header (64 bytes), program headers (56 each), then the pieces.
    start = 64 + 56 * len(headers)
    dynamic_at = start
    strings_at = dynamic_at + len(dynamic)
    symbols_at = strings_at + len(strings)
    note_at = symbols_at + len(symbol_table)
    sections_at = note_at + len(note)

    program_headers = b""
    for p_type, flags in headers:
        offset, size = 0, 0
        if p_type == check.PT_DYNAMIC:
            offset, size = dynamic_at, len(dynamic)
        if p_type == check.PT_GNU_PROPERTY:
            offset, size = note_at, len(note)
        program_headers += struct.pack("<IIQQQQQQ", p_type, flags, offset, 0, 0, size, size, 8)

    # Section headers: the empty one, the string table, and the symbol table linked to it.
    sections = bytes(64)
    sections += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, strings_at, len(strings), 0, 0, 1, 0)
    sections += struct.pack(
        "<IIQQQQIIQQ", 0, check.SHT_DYNSYM, 0, 0, symbols_at, len(symbol_table), 1, 1, 8, 24
    )

    e_type = check.ET_EXEC if fixed_address else check.ET_DYN
    header = (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            e_type,
            check.EM_X86_64,
            1,
            0,
            64,
            sections_at,
            0,
            64,
            56,
            len(headers),
            64,
            3,
            0,
        )
    )
    return header + program_headers + dynamic + strings + symbol_table + note + sections


def read(data: bytes, musl: bool = False) -> check.Hardening:
    result = check.read_elf("/test", data, musl)
    assert result is not None
    return result


def test_a_fully_hardened_program_has_every_defense() -> None:
    result = read(make_elf(needed=("libc.so.6",)))
    assert (result.kind, result.pie, result.nx, result.relro) == ("program", "yes", "yes", "full")
    assert (result.canary, result.fortify, result.cfi) == ("yes", "yes (1)", "none")
    assert result.needed == ["libc.so.6"]


def test_a_program_at_a_fixed_address_is_not_pie() -> None:
    # ASLR cannot move it, so its code is where an attacker expects it.
    assert read(make_elf(fixed_address=True)).pie == "NO"


def test_a_library_is_position_independent_by_definition() -> None:
    assert read(make_elf(program=False)).pie == "n/a"


@pytest.mark.parametrize("stack", [READ_WRITE_EXECUTE, None])
def test_an_executable_stack_or_no_stack_header_is_not_nx(stack: int | None) -> None:
    # Without the header, older loaders make the stack executable.
    assert read(make_elf(stack=stack)).nx == "NO"


@pytest.mark.parametrize(
    ("relro", "bind_now", "expected"),
    [(True, True, "full"), (True, False, "partial"), (False, False, "NO")],
)
def test_relro_is_full_only_with_bind_now(relro: bool, bind_now: bool, expected: str) -> None:
    assert read(make_elf(relro=relro, bind_now=bind_now)).relro == expected


@pytest.mark.parametrize(
    ("symbols", "musl", "canary", "fortify"),
    [
        (("__stack_chk_fail", "memcpy", "__memcpy_chk"), False, "yes", "yes (1)"),
        (("memcpy", "strlen"), False, "NO", "NO (memcpy)"),  # could be checked, is not
        (("strlen",), False, "NO", "none needed"),  # nothing FORTIFY could check
        (("memcpy",), True, "NO", "unseen"),  # musl checks in its headers
    ],
)
def test_canaries_and_fortify_are_seen_in_the_functions_called(
    symbols: tuple[str, ...], musl: bool, canary: str, fortify: str
) -> None:
    result = read(make_elf(symbols=symbols), musl=musl)
    assert (result.canary, result.fortify) == (canary, fortify)


def test_the_hardware_control_flow_marks_are_read() -> None:
    # A GNU property note: name "GNU", one x86 feature property with IBT (1) and SHSTK (2).
    description = struct.pack("<III", check.GNU_PROPERTY_X86_FEATURE_1_AND, 4, 3) + bytes(4)
    note = struct.pack("<III", 4, len(description), check.NT_GNU_PROPERTY_TYPE_0)
    note += b"GNU\0" + description
    assert read(make_elf(property_note=note)).cfi == "IBT+SHSTK"


def test_a_file_that_is_not_a_64_bit_elf_is_not_read() -> None:
    assert check.read_elf("/test", b"#!/bin/sh\n", musl=False) is None
    assert check.read_elf("/test", b"\x7fELF\x01\x01" + bytes(60), musl=False) is None


def test_partial_relro_counts_as_missing() -> None:
    assert check.is_missing("RELRO", "partial")
    assert not check.is_missing("RELRO", "full")
    assert check.is_missing("FORTIFY", "NO (memcpy)")
    assert not check.is_missing("FORTIFY", "none needed")


def _package(name: str, tag: str, compiled: bool) -> dict[str, bytes]:
    folder = f"/usr/local/lib/python3.13/site-packages/{name}-1.0.dist-info"
    record = f"{name}/_speedups.so,sha256=x,1\n" if compiled else f"{name}/__init__.py,,\n"
    return {f"{folder}/WHEEL": f"Tag: {tag}\n".encode(), f"{folder}/RECORD": record.encode()}


@pytest.mark.parametrize(
    ("name", "tag", "compiled", "refused"),
    [
        ("markupsafe", "cp313-cp313-manylinux2014_x86_64", True, True),  # PyPI's build
        ("markupsafe", "cp313-cp313-linux_x86_64", True, False),  # built in the image
        ("pydantic_core", "cp313-cp313-manylinux2014_x86_64", True, False),  # Rust, allowed
        ("idna", "py3-none-any", False, False),  # pure Python
    ],
)
def test_compiled_packages_must_be_built_in_the_image(
    name: str, tag: str, compiled: bool, refused: bool
) -> None:
    assert bool(check.prebuilt_problems("backend", _package(name, tag, compiled))) is refused


# --- Libraries a checked file loads (review of #204) -----------------------------------

SITE = "/usr/local/lib/python3.13/site-packages"


def test_the_folders_a_file_names_for_itself_are_read() -> None:
    result = read(make_elf(program=False, needed=("libz.so.1",), runpath="$ORIGIN/../pkg.libs"))
    assert result.needed == ["libz.so.1"]
    assert result.search == ["$ORIGIN/../pkg.libs"]


@pytest.mark.parametrize(
    ("name", "search", "found"),
    [
        # In the loading file's own folder list, with $ORIGIN as its folder.
        ("libz.so.1", ("$ORIGIN/../pkg.libs",), f"{SITE}/pkg.libs/libz.so.1"),
        # In a system folder, here the one glibc's loader itself lives in on amd64.
        ("ld-linux-x86-64.so.2", (), "/lib64/ld-linux-x86-64.so.2"),
        # Nowhere: not guessed.
        ("libgone.so.1", ("$ORIGIN",), None),
    ],
)
def test_a_needed_library_is_looked_for_where_the_loader_would(
    name: str, search: tuple[str, ...], found: str | None
) -> None:
    files = {f"{SITE}/pkg.libs/libz.so.1": b"", "/lib64/ld-linux-x86-64.so.2": b""}
    assert check._library_path(files, name, f"{SITE}/pkg", search) == found


def test_a_library_that_is_not_in_the_image_is_a_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    """A library left out would be missing from the table without a word, so the check
    would look complete while it was not."""
    files = {
        f"{SITE}/pkg/_speedups.so": make_elf(program=False, needed=("libgone.so.1",)),
        f"{SITE}/other/_fast.so": make_elf(program=False, needed=("libz.so.1",), runpath="$ORIGIN"),
        f"{SITE}/other/libz.so.1": make_elf(program=False),
    }
    monkeypatch.setattr(check, "image_files", lambda image: files)
    _rows, problems = check.check_image("backend", "any")
    loading = [problem for problem in problems if " loads " in problem]
    assert loading == [
        f"backend: pkg ({SITE}/pkg/_speedups.so) loads libgone.so.1, not found in the image"
    ]


def test_a_documented_missing_library_is_not_a_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {f"{SITE}/pkg/_speedups.so": make_elf(program=False, needed=("libgone.so.1",))}
    monkeypatch.setattr(check, "image_files", lambda image: files)
    monkeypatch.setitem(check.KNOWN_UNRESOLVED, "libgone.so.1", "a reason on the page")
    _rows, problems = check.check_image("backend", "any")
    assert not [problem for problem in problems if " loads " in problem]
