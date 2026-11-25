# Memory-safety defenses of the compiled code

**In short:** our own code is Python and JavaScript, where buffer overflows cannot happen. The programs underneath it are partly written in C, and could have them: the Python interpreter, nginx, OpenSSL, and the compiled parts of some Python packages. This page records which defenses each of those files was built with, how we checked, what we fixed, and what we accept as a limit. Threat E10 in the [threat model](threat-model.md); backend #107.

- **Status:** checked 2026-11-25 on images built from `main`; all required defenses present after the fix below
- **Check:** `scripts/check_native_hardening.py` (needs Docker; its ELF reader is tested in `tests/unit/test_native_hardening.py`)
- **Related:** [threat model](threat-model.md) E10, [security controls](security-controls.md), [findings log](findings-log.md), `Dockerfile`

## The defenses

A buffer overflow writes past the end of an array. In C nothing stops it, so an attacker who controls the extra bytes can overwrite what comes next: the function's return address, or a table of function addresses. To turn that into running their own code, they must know where code is in memory and must be able to jump to it. Each defense takes away one of those steps.

| Defense | What it stops | How the check sees it |
|---|---|---|
| **ASLR** (address space layout randomization) | the kernel loads the stack, the heap, and the libraries at a new random address every run, so an attacker cannot know where anything is | `/proc/sys/kernel/randomize_va_space` is 2 |
| **PIE** (position-independent executable) | the program's own code moves with ASLR too. Without it, its code stays at a fixed address, which is what return-oriented programming (chaining short pieces of existing code) needs | the ELF type is `ET_DYN` and the file has an interpreter. Shared libraries are always position-independent ("n/a") |
| **NX** (non-executable stack) | code written onto the stack by an overflow cannot run | the `PT_GNU_STACK` header has no execute flag |
| **RELRO** (relocation read-only) | the table of library addresses (the GOT) is made read-only after loading, so an overflow cannot redirect calls through it. "Full" also needs `BIND_NOW`, which fills the whole table at start-up | a `PT_GNU_RELRO` header, plus `BIND_NOW` for "full" |
| **Stack canary** (`-fstack-protector-strong`) | a secret value sits before the return address in every function with a buffer, and is checked on return: a stack overflow changes it and the program stops | a call to `__stack_chk_fail` |
| **FORTIFY_SOURCE** | copies and formatting whose destination size the compiler knows are checked as they run | calls such as `__memcpy_chk` |
| **CET / BTI** (hardware control flow integrity) | the processor refuses jumps to places that are not marked as jump targets (IBT on x86, BTI on ARM), and keeps a second copy of return addresses (shadow stack) | the GNU property note; reported, not required (see limits) |

The check reads the same marks as `checksec`, from the files themselves: it exports each image with `docker export`, finds the required files and every library they load (looked for where the loader would look: the folders the file names for itself, `DT_RUNPATH` or `DT_RPATH` with `$ORIGIN`, then the system's folders), and parses their ELF headers (the slim images have no `readelf`). Like `checksec`, it can only see a canary or FORTIFY where the code calls the checking functions. A file that has no function with a buffer on the stack has no canary to see, and FORTIFY cannot check a copy whose size is only known as the program runs. The table says "none needed" when a file calls nothing FORTIFY could check.

## How to run it

```sh
docker build -t workforce-ops-backend:local .
docker build -t workforce-ops-frontend:local ../workforce-ops-frontend
python scripts/check_native_hardening.py workforce-ops-backend:local workforce-ops-frontend:local
```

It prints a table per image and the ASLR setting, and exits 1 if a required file lacks a defense that is not a stated limit below, if a package with compiled code was installed from PyPI's build instead of being built in the image, or if a file it checks loads a library it cannot find in the image. A library that is not found would be left out of the table without a word, so the check would look complete while it was not (review of #204). A library may be missing only with its reason in `KNOWN_UNRESOLVED` in the script and here; there are none: every library either image loads was found (2026-11-25).

The frontend image is optional: `python scripts/check_native_hardening.py workforce-ops-backend:local` checks the backend only.

**In CI:** the `native-hardening` operation in `ci.toml` builds the backend image as it ships and runs the check on it, on every pull request and push, so a dependency update that brings an unhardened binary fails CI before it reaches an image. It needs Docker and takes several minutes, so it runs in CI only (`local = false`); run the commands above to check by hand. The frontend image is built in the frontend repository; checking it there in the same way is a follow-up.

## Results (2026-11-25)

Images built from `main`: the backend from `python:3.13-slim` (Python 3.13.18, Debian 13 "trixie", x86-64), the frontend from `nginx:1.31-alpine3.24` (nginx 1.31.10). Required files are in the first part of each table; the system libraries after them are what those files load, listed for the whole picture.

### Backend, after the fix

| File | Kind | PIE | NX | RELRO | Canary | FORTIFY |
|---|---|---|---|---|---|---|
| `python3.13` (the launcher) | program | yes | yes | partial (limit 1) | none to see (limit 2) | none needed |
| `libpython3.13.so.1.0` (the interpreter) | library | n/a | yes | partial (limit 1) | yes | NO (limit 1) |
| `_ssl` (Python's TLS module) | library | n/a | yes | partial (limit 1) | yes | NO (limit 1) |
| `cryptography` `_rust.abi3.so` | library | n/a | yes | full | yes | Rust (limit 3) |
| `argon2-cffi-bindings` `_ffi.abi3.so` | library | n/a | yes | full | yes | yes (3) |
| `cffi` `_cffi_backend` | library | n/a | yes | full | yes | yes (5) |
| `sqlalchemy` (8 Cython files) | library | n/a | yes | full | yes | 1 of 8 checked; sizes known at run time (limit 4) |
| `markupsafe` `_speedups` | library | n/a | yes | full | none to see (limit 4) | sizes known at run time (limit 4) |
| `pydantic-core` | library | n/a | yes | full | Rust (limit 3) | Rust (limit 3) |
| Debian `libc`, `libssl`, `libcrypto`, `libzstd`, `libm` | library | n/a | yes | full | yes | yes |
| Debian `libz`, `libffi` | library | n/a | yes | partial | yes | yes / sizes at run time |
| Debian `ld-linux`, `libpthread`, `libdl`, `librt`, `libgcc_s` | library | n/a | yes | full (`libgcc_s` partial) | no buffers / set-up code | none needed |

ASLR seen from the container: **2** (full).

### Backend, before the fix

The same image built the old way (`pip install .`, PyPI's wheels):

| File | RELRO | Canary | FORTIFY |
|---|---|---|---|
| `argon2-cffi-bindings` `_ffi.abi3.so` (holds libargon2, which hashes every password) | partial | **NO** | **NO** |
| `cffi` `_cffi_backend` | partial | **NO** | **NO** |
| `cryptography` `_rust.abi3.so` (holds its own copy of OpenSSL) | full | **NO** | **NO** |
| `sqlalchemy` (8 Cython files) | partial | **NO** | **NO** |
| `markupsafe` `_speedups` | partial | **NO** | **NO** |

### Frontend

| File | Kind | PIE | NX | RELRO | Canary | FORTIFY |
|---|---|---|---|---|---|---|
| `nginx` | program | yes | yes | full | yes | musl (limit 5) |
| `libssl`, `libcrypto`, `libpcre2-8`, `libz`, musl `libc` | library | n/a | yes | full | yes | musl (limit 5) |

ASLR seen from the container: **2** (full). The frontend needs no change.

## What we fixed

**Compiled Python packages without canaries or FORTIFY** (finding, severity low). The wheels PyPI offers for Linux are built in a deliberately old build environment ("manylinux") so they run on many distributions, and the five packages with C code in our image were built there without stack canaries or FORTIFY and, for four of them, with only partial RELRO. The worst was `argon2-cffi-bindings`, whose compiled file contains libargon2, which handles every password at sign-in, and `cryptography`, which carried its own copy of OpenSSL.

The fix is a first stage in the `Dockerfile` that builds those five from source with the defenses:

- `-fstack-protector-strong` (canaries), `-D_FORTIFY_SOURCE=3`, and `-Wl,-z,relro,-z,now` (full RELRO);
- `cryptography` is linked to Debian's OpenSSL (`libssl.so.3` and `libcrypto.so.3` in the table, built with every defense), so OpenSSL is patched with the base image instead of waiting for a new `cryptography` release;
- the versions are the pinned ones from `pyproject.toml`, so a Dependabot update builds the new version the same way;
- the final image installs only from those wheels (`--no-index`) and has no compiler.

The check now fails if a package with compiled code arrives as a PyPI wheel, so a new C dependency cannot slip in unhardened. The cost is build time: the first build compiles `cryptography`'s Rust code, about six more minutes. The first stage builds the dependencies from `pyproject.toml` alone, before the app's code is copied in, and the app's own wheel in a step after it, so Docker's cache skips the compiling until `pyproject.toml` changes (a pin, or anything else in that file); a change to the app's code rebuilds only its own wheel (review of #204).

We confirmed the rebuilt image works: it ran the migrations on MySQL 8.4 with Docker Compose, signed in to MySQL as the application user (MySQL 8's sign-in method goes through `cryptography`), answered `/api/health`, and checked a password with Argon2 at sign-in.

## Stated limits

1. **CPython is built without FORTIFY and with partial RELRO.** The official `python` image compiles the interpreter with Debian's `CFLAGS` and `LDFLAGS` (canaries yes) but not its `CPPFLAGS`, where `-D_FORTIFY_SOURCE` is, and without `-z now`. Fixing it means building CPython ourselves or switching to Debian's own `python3.13` package, which changes the base image and where every package is installed. We accept it: the interpreter has canaries, NX, PIE, and ASLR; HTTP requests are parsed by h11, which is written in Python (the image has no compiled HTTP parser); and Python's security releases arrive with each rebuilt base image. Revisit if the project moves to a Debian-built Python.
2. **The `python3.13` launcher shows no canary.** It is a 14 KB file with one function, `main`, which calls into `libpython`. It has no buffer on the stack, so `-fstack-protector-strong` adds no canary to it. The interpreter itself (`libpython`) has them.
3. **Rust code has no canaries or FORTIFY** (`pydantic-core`, and what is left in `cryptography`'s file after OpenSSL moved out). Both defenses guard C; Rust checks every array access itself, so the overflow they catch cannot happen in safe Rust. `pydantic-core` is used as PyPI builds it for that reason.
4. **Copies sized at run time are not checked by FORTIFY** (`sqlalchemy`, `markupsafe`). Both were built here with FORTIFY on, and one SQLAlchemy file shows a checked call, but FORTIFY can only check a copy whose destination size the compiler knows, and these copy into buffers sized as they run. `markupsafe` also has no function with a buffer on the stack, so it has no canary to see.
5. **FORTIFY cannot be seen in the Alpine image.** musl, Alpine's C library, does not provide `__*_chk` functions; Alpine fortifies in its headers instead, which leaves nothing in the file to find ("unseen" in the script's table). nginx and every library it loads have the other defenses.
6. **No hardware control flow integrity (CET, BTI).** No file in either image carries the marks: Debian and Alpine do not build their start-up files with them, and a program only gets them if every part it is linked from has them. It also needs processor and kernel support. ASLR, PIE, NX, RELRO, and canaries stay the defenses against return-oriented programming.
7. **ASLR is the host's setting.** Containers share the host's kernel, so the value the container sees is the host's. It was 2 on the Docker Desktop machine we checked; the script checks it again on whatever machine it runs on, so it must be run on the production host after deployment.
8. **Not fuzzed or attacked.** This checks how the compiled code was built, not whether it has bugs; fuzzing or exploiting the libraries is out of scope (#107). Known vulnerabilities in them are covered by pip-audit, npm audit, and Dependabot.
