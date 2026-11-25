"""Check the compiled (native) programs in the container images for memory-safety defenses.

Threat E10 (docs/security/threat-model.md), backend #107. Our own code is Python and
JavaScript, where buffer overflows cannot happen. The programs underneath are written in
C (CPython, nginx, OpenSSL, libargon2) and could have such bugs, so they must be built
with the defenses that make an overflow hard to turn into running an attacker's code:

    PIE      the program itself is loaded at a random address, so ASLR moves all of it
             and an attacker cannot know where its code is (return-oriented programming
             needs those addresses). Shared libraries are always position-independent.
    NX       the stack is not executable, so code written onto it by an overflow cannot
             run (the PT_GNU_STACK header has no X flag).
    RELRO    after loading, the table of library addresses (the GOT) is made read-only,
             so an overflow cannot redirect calls through it. "full" also needs
             BIND_NOW, which fills the whole table at start-up.
    canary   functions with buffers put a secret value before the return address and
             check it on return (-fstack-protector): a stack overflow is noticed and the
             program stops. Seen as a call to __stack_chk_fail.
    FORTIFY  copies and formats with a size known at compile time are checked when they
             run (-D_FORTIFY_SOURCE): seen as calls such as __memcpy_chk.
    CET/BTI  hardware control flow integrity: on x86 the IBT and SHSTK marks (indirect
             branch tracking, shadow stack), on ARM BTI and PAC. Reported, not required:
             the hardware and kernel must support it too.

It needs only Docker and this file's standard library: each image's files are read from
`docker export`, and the ELF headers are parsed here (the slim images have no readelf).

    python scripts/check_native_hardening.py BACKEND_IMAGE FRONTEND_IMAGE

for example workforce-ops-backend:local and workforce-ops-frontend:local.

Prints a table per image and exits 1 if a required defense is missing from a file that
must have it (REQUIRED below), unless docs/security/native-hardening.md states the limit
(KNOWN_LIMITS below). It also prints the container's ASLR setting, which must be 2.
"""

import io
import posixpath
import struct
import subprocess  # noqa: S404 (runs docker with fixed arguments)
import sys
import tarfile
from dataclasses import dataclass, field

# --- ELF constants (the System V ABI and the GNU extensions) ---------------------------

ELF_MAGIC = b"\x7fELF"
ET_EXEC, ET_DYN = 2, 3  # a fixed-address program, or position-independent code
PT_DYNAMIC, PT_INTERP, PT_NOTE = 2, 3, 4
PT_GNU_STACK, PT_GNU_RELRO, PT_GNU_PROPERTY = 0x6474E551, 0x6474E552, 0x6474E553
PF_X = 1  # the segment's "executable" permission
DT_NULL, DT_NEEDED, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 0, 1, 24, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x8, 0x1, 0x08000000
SHT_DYNSYM = 11
# The C library functions FORTIFY_SOURCE can replace with a checked __*_chk version. A
# file that calls none of them has nothing to fortify, whatever flags it was built with.
FORTIFIABLE = {
    "memcpy",
    "memmove",
    "mempcpy",
    "memset",
    "stpcpy",
    "stpncpy",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "dprintf",
    "read",
    "pread",
    "pread64",
    "recv",
    "recvfrom",
    "fgets",
    "fread",
    "getcwd",
    "realpath",
    "readlink",
    "wcscpy",
    "wmemcpy",
    "wmemset",
    "gets",
    "confstr",
    "getgroups",
    "ttyname_r",
    "ptsname_r",
    "mbstowcs",
    "wcstombs",
    "wctomb",
    "longjmp",
    "poll",
    "ppoll",
    "syslog",
    "vsyslog",
    "explicit_bzero",
}
EM_X86_64, EM_AARCH64 = 62, 183
NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_X86_FEATURE_1_AND, GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000002, 0xC0000000

# --- What must be checked, and what is allowed to be missing --------------------------

# The native parts the issue names, by image: (a short name, the path in the image). A
# path ending in "/" means "the file under this folder whose name starts with the rest".
REQUIRED = {
    "backend": [
        ("python", "/usr/local/bin/python3.13"),
        ("libpython", "/usr/local/lib/libpython3.13.so.1.0"),
        (
            "cryptography",
            "/usr/local/lib/python3.13/site-packages/cryptography/hazmat/bindings/_rust",
        ),
        ("argon2-cffi", "/usr/local/lib/python3.13/site-packages/_argon2_cffi_bindings/_ffi"),
        ("cffi", "/usr/local/lib/python3.13/site-packages/_cffi_backend"),
        ("ssl", "/usr/local/lib/python3.13/lib-dynload/_ssl"),
    ],
    "frontend": [("nginx", "/usr/sbin/nginx")],
}

# Defenses a file is known to lack, with the reason; each is written up in
# docs/security/native-hardening.md. Keyed by (short name, defense).
# The official Python image compiles CPython with Debian's CFLAGS and LDFLAGS (canaries,
# partial RELRO) but not its CPPFLAGS, where -D_FORTIFY_SOURCE is, and without -z now.
_CPYTHON = "CPython as the official python:3.13-slim image builds it"
# Rust checks every array access itself; canaries and FORTIFY guard C code, so a Rust
# library has neither, and needs neither for its own code.
_RUST = "Rust code, which checks its own bounds"
_SIZED_AT_RUN_TIME = "copies into buffers sized at run time, which FORTIFY cannot check"
KNOWN_LIMITS: dict[tuple[str, str], str] = {
    # The launcher is one function, main, with no buffer; -fstack-protector-strong only
    # guards functions that have one. The interpreter itself is libpython (canaries).
    ("python", "canary"): "a 14 KB launcher without buffers",
    ("python", "FORTIFY"): _CPYTHON,
    ("python", "RELRO"): _CPYTHON,
    ("libpython", "FORTIFY"): _CPYTHON,
    ("libpython", "RELRO"): _CPYTHON,
    ("ssl", "FORTIFY"): _CPYTHON,
    ("ssl", "RELRO"): _CPYTHON,
    # cryptography's C part is OpenSSL, which it now loads from Debian (libcrypto.so.3 in
    # the table, with FORTIFY); what is left in the file is Rust.
    ("cryptography", "FORTIFY"): _RUST,
    ("pydantic_core", "canary"): _RUST,
    ("pydantic_core", "FORTIFY"): _RUST,
    # Built in the Dockerfile with FORTIFY (the wheel check below proves they were built
    # there). FORTIFY can only check a copy whose destination size the compiler knows;
    # these copy into buffers sized as they run, so the calls stay unchecked.
    ("markupsafe", "FORTIFY"): _SIZED_AT_RUN_TIME,
    ("sqlalchemy", "FORTIFY"): _SIZED_AT_RUN_TIME,
    # Also built with -fstack-protector-strong: no function in it keeps an array on the
    # stack, so there is nothing to guard (cffi and sqlalchemy, built the same way, have
    # canaries).
    ("markupsafe", "canary"): "no function with a buffer on the stack",
}

# Packages whose compiled code may come from PyPI as it is (every other package with
# compiled code must be built in the Dockerfile's first stage, with the defenses).
PREBUILT_ALLOWED = {"pydantic_core": _RUST}

# Defenses every required file must have, and the values that count as missing. RELRO
# must be full. FORTIFY is checked only where it can be seen: musl (Alpine) fortifies in
# its headers, which leaves no __*_chk calls to find ("unseen" in the table).
MUST_HAVE = ("PIE", "NX", "RELRO", "canary", "FORTIFY")


def is_missing(defense: str, value: str) -> bool:
    """Whether a table value means the defense is missing."""
    return value.startswith("NO") or (defense == "RELRO" and value == "partial")


# --- Reading one ELF file -------------------------------------------------------------


@dataclass
class Hardening:
    """What one ELF file has. Each value is a short word for the table."""

    path: str
    kind: str  # "program" or "library"
    pie: str
    nx: str
    relro: str
    canary: str
    fortify: str  # "yes (n)" checked calls, "none needed", "unseen" (musl), or "NO (...)"
    cfi: str
    needed: list[str] = field(default_factory=list)  # the libraries it loads (DT_NEEDED)

    def value(self, defense: str) -> str:
        return {
            "PIE": self.pie,
            "NX": self.nx,
            "RELRO": self.relro,
            "canary": self.canary,
            "FORTIFY": self.fortify,
        }[defense]


def read_elf(path: str, data: bytes, musl: bool) -> Hardening | None:
    """Parse the headers of one ELF file; None if it is not a 64-bit little-endian ELF."""
    # 1. The file header: 64-bit (class 2), little-endian (data 1), as on amd64 and arm64.
    if data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1:
        return None
    (e_type, e_machine) = struct.unpack_from("<HH", data, 16)
    (e_phoff, e_shoff) = struct.unpack_from("<QQ", data, 32)
    (e_phentsize, e_phnum, e_shentsize, e_shnum) = struct.unpack_from("<HHHH", data, 54)

    # 2. The program headers: how the file is laid out in memory.
    segments = []
    for number in range(e_phnum):
        p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from(
            "<IIQQQQ", data, e_phoff + number * e_phentsize
        )
        segments.append((p_type, p_flags, p_offset, p_filesz))
    types = {segment[0] for segment in segments}

    # 3. The dynamic section: the libraries it needs and the loader's flags.
    needed_offsets, bind_now, flags_1 = [], False, 0
    for p_type, _flags, offset, size in segments:
        if p_type != PT_DYNAMIC:
            continue
        for entry in range(offset, offset + size, 16):
            tag, value = struct.unpack_from("<qQ", data, entry)
            if tag == DT_NULL:
                break
            if tag == DT_NEEDED:
                needed_offsets.append(value)
            if tag == DT_BIND_NOW or (tag == DT_FLAGS and value & DF_BIND_NOW):
                bind_now = True
            if tag == DT_FLAGS_1:
                flags_1 = value
                bind_now = bind_now or bool(value & DF_1_NOW)

    # 4. The dynamic symbol table, from the section headers: which functions it calls.
    symbols, needed = set(), []
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + number * e_shentsize)
        for number in range(e_shnum if e_shoff else 0)
    ]
    for _name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, *_ in sections:
        if sh_type != SHT_DYNSYM:
            continue
        strings_offset = sections[sh_link][4]  # the string table it points to

        def name_at(offset: int, base: int = strings_offset) -> str:
            end = data.index(b"\0", base + offset)
            return data[base + offset : end].decode("ascii", "replace")

        for entry in range(sh_offset, sh_offset + sh_size, 24):
            (st_name,) = struct.unpack_from("<I", data, entry)
            symbols.add(name_at(st_name))
        needed = [name_at(offset) for offset in needed_offsets]

    # 5. The answers. A program with an interpreter is an executable; ET_DYN without one
    #    is a shared library, which is position-independent by definition.
    is_program = PT_INTERP in types
    if not is_program:
        pie = "n/a"
    elif e_type == ET_DYN or flags_1 & DF_1_PIE:
        pie = "yes"
    else:
        pie = "NO"
    stack = [flags for p_type, flags, *_ in segments if p_type == PT_GNU_STACK]
    nx = "yes" if stack and not stack[0] & PF_X else "NO"
    relro = ("full" if bind_now else "partial") if PT_GNU_RELRO in types else "NO"
    canary = "yes" if {"__stack_chk_fail", "__stack_chk_guard"} & symbols else "NO"
    fortified = sorted(s for s in symbols if s.startswith("__") and s.endswith("_chk"))
    unchecked = sorted(FORTIFIABLE & symbols)
    if fortified:
        fortify = f"yes ({len(fortified)})"
    elif musl:
        fortify = "unseen"
    elif unchecked:
        # Calls FORTIFY could check, and not one checked version: built without it.
        fortify = "NO (" + ", ".join(unchecked[:3]) + (", ..." if len(unchecked) > 3 else "") + ")"
    else:
        fortify = "none needed"
    return Hardening(
        path=path,
        kind="program" if is_program else "library",
        pie=pie,
        nx=nx,
        relro=relro,
        canary=canary,
        fortify=fortify,
        cfi=_control_flow_marks(data, segments, e_machine),
        needed=needed,
    )


def _control_flow_marks(data: bytes, segments: list, machine: int) -> str:
    """The hardware control flow integrity marks in the GNU property note, if any."""
    for p_type, _flags, offset, size in segments:
        if p_type not in (PT_GNU_PROPERTY, PT_NOTE):
            continue
        at = offset
        while at + 12 <= offset + size:
            namesz, descsz, note_type = struct.unpack_from("<III", data, at)
            name_end = at + 12 + ((namesz + 3) & ~3)
            desc = data[name_end : name_end + descsz]
            at = name_end + ((descsz + 7) & ~7)
            if note_type != NT_GNU_PROPERTY_TYPE_0:
                continue
            # The description is a list of (type, size, value) properties, 8-byte aligned.
            inner = 0
            while inner + 8 <= len(desc):
                pr_type, pr_size = struct.unpack_from("<II", desc, inner)
                value = struct.unpack_from("<I", desc, inner + 8)[0] if pr_size >= 4 else 0
                inner += 8 + ((pr_size + 7) & ~7)
                if machine == EM_X86_64 and pr_type == GNU_PROPERTY_X86_FEATURE_1_AND:
                    marks = [n for n, bit in (("IBT", 1), ("SHSTK", 2)) if value & bit]
                    return "+".join(marks) or "none"
                if machine == EM_AARCH64 and pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND:
                    marks = [n for n, bit in (("BTI", 1), ("PAC", 2)) if value & bit]
                    return "+".join(marks) or "none"
    return "none"


# --- Reading an image -----------------------------------------------------------------


def _docker(*arguments: str, stdin: bytes | None = None) -> bytes:
    """Run docker and return its output; stop with its message if it fails."""
    done = subprocess.run(["docker", *arguments], capture_output=True, input=stdin)  # noqa: S603, S607
    if done.returncode != 0:
        sys.exit(f"docker {arguments[0]} failed: {done.stderr.decode(errors='replace')}")
    return done.stdout


def image_files(image: str) -> dict[str, bytes]:
    """Every regular file in the image, by absolute path, and symlinks resolved to the
    file they point to. The image is created as a stopped container and exported; the
    container never runs and is removed afterwards."""
    container = _docker("create", image).decode().strip()
    try:
        files, links = {}, {}
        with tarfile.open(fileobj=io.BytesIO(_docker("export", container))) as archive:
            for member in archive.getmembers():
                path = "/" + member.name.removeprefix("./")
                if member.isfile():
                    files[path] = archive.extractfile(member).read()  # type: ignore[union-attr]
                elif member.issym():
                    # A relative link points from its own folder; an absolute one from /.
                    links[path] = posixpath.normpath(
                        posixpath.join(posixpath.dirname(path), member.linkname)
                    )
        # A library is usually found by a link name (libssl.so.3 -> libssl.so.3.0.x).
        for path, target in links.items():
            for _ in range(10):  # links to links, a few levels at most
                target = links.get(target, target)
            if target in files:
                files[path] = files[target]
        return files
    finally:
        _docker("rm", container)


def _find(files: dict[str, bytes], path: str) -> str | None:
    """The image path a REQUIRED entry names: the file itself, or the first file in its
    folder whose name starts with the entry's last part (extension modules carry the
    Python version and platform in their names)."""
    if path in files:
        return path
    folder, start = posixpath.split(path)
    matches = sorted(
        f
        for f in files
        if posixpath.dirname(f) == folder and posixpath.basename(f).startswith(start)
    )
    return matches[0] if matches else None


def _library_path(files: dict[str, bytes], name: str) -> str | None:
    """Where the loader would find a needed library, in the usual folders."""
    for folder in (
        "/usr/local/lib",
        "/lib",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ):
        if f"{folder}/{name}" in files:
            return f"{folder}/{name}"
    return None


def check_image(role: str, image: str) -> tuple[list[tuple[str, Hardening]], list[str]]:
    """Read the required files of one image and every library they load, directly or
    through others. Returns the rows for the table and the problems found."""
    files = image_files(image)
    problems = prebuilt_problems(role, files)
    musl = any(posixpath.basename(path).startswith("ld-musl") for path in files)
    rows, seen = [], set()
    queue = []
    for short, wanted in REQUIRED[role]:
        found = _find(files, wanted)
        if found is None:
            problems.append(f"{role}: {short} not found at {wanted}")
            continue
        queue.append((short, found, True))
    # Every other compiled file among the installed Python packages, required too: a new
    # dependency with C code must be built in the Dockerfile's first stage.
    for path in sorted(files):
        if "/site-packages/" in path and files[path][:4] == ELF_MAGIC:
            queue.append((path.split("/site-packages/")[1].split("/")[0], path, True))
    while queue:
        short, path, required = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        result = read_elf(path, files[path], musl)
        if result is None:
            problems.append(f"{role}: {path} is not a 64-bit ELF file")
            continue
        rows.append((short, result))
        # Only the defenses of the files that must have them can fail the check; the
        # system libraries they load are listed so the table shows the whole picture.
        if required:
            for defense in MUST_HAVE:
                value = result.value(defense)
                if is_missing(defense, value) and (short, defense) not in KNOWN_LIMITS:
                    problems.append(f"{role}: {short} ({path}) has no {defense}")
        for name in result.needed:
            library = _library_path(files, name)
            if library is not None:
                queue.append((name, library, False))
    return rows, problems


def prebuilt_problems(role: str, files: dict[str, bytes]) -> list[str]:
    """Packages with compiled code installed from a PyPI wheel instead of being built here.

    A wheel's WHEEL file names the platform it was built for: "manylinux" (or
    "musllinux") for PyPI's, plain "linux" for one built on this machine, which is how the
    Dockerfile's first stage builds them, with the defenses.
    """
    problems = []
    for path, content in files.items():
        if not (path.endswith(".dist-info/WHEEL") and "/site-packages/" in path):
            continue
        record = files.get(path.removesuffix("WHEEL") + "RECORD", b"")
        if b".so," not in record:
            continue  # pure Python: nothing compiled
        name = posixpath.basename(posixpath.dirname(path)).split("-")[0]
        tags = [line for line in content.decode().splitlines() if line.startswith("Tag:")]
        prebuilt = any("manylinux" in tag or "musllinux" in tag for tag in tags)
        if prebuilt and name not in PREBUILT_ALLOWED:
            problems.append(f"{role}: {name} is a PyPI wheel; build it in the Dockerfile")
    return problems


def aslr_setting(image: str) -> str:
    """The kernel's ASLR setting as a container from this image sees it (the host's
    kernel: containers share it). 2 means full: stack, libraries, and the heap move."""
    return (
        _docker("run", "--rm", "--entrypoint", "cat", image, "/proc/sys/kernel/randomize_va_space")
        .decode()
        .strip()
    )


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print(__doc__)
        return 2
    problems = []
    for role, image in zip(("backend", "frontend"), arguments, strict=True):
        rows, found = check_image(role, image)
        problems += found
        print(f"\n{role} ({image})\n")
        print("| File | Kind | PIE | NX | RELRO | Canary | FORTIFY | CET/BTI |")
        print("|---|---|---|---|---|---|---|---|")
        for short, row in rows:
            cells = [row.kind, row.pie, row.nx, row.relro, row.canary, row.fortify, row.cfi]
            print(f"| {short} (`{row.path}`) | " + " | ".join(cells) + " |")
        aslr = aslr_setting(image)
        print(f"\nASLR (randomize_va_space) seen from the {role} container: {aslr}")
        if aslr != "2":
            problems.append(f"{role}: ASLR is {aslr}, not 2 (full)")
    print()
    for problem in problems:
        print(f"problem: {problem}")
    print("all required defenses present" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
