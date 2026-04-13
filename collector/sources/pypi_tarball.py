"""PyPI sdist inspector for install-script detection.

PyPI's JSON API doesn't expose whether a package's setup.py does anything
beyond the conventional `setuptools.setup(**read_from_config)` wrapper. The
only way to know is to look inside. This module downloads the sdist for one
version, extracts setup.py and pyproject.toml, and classifies:

- True  → non-conventional install path. Any of:
            * pyproject.toml declares a build-backend not on the whitelist
            * setup.py imports a networking/subprocess module
            * setup.py calls os.system / os.popen / os.exec* / exec / eval
            * setup.py passes cmdclass= to setup() (install-command override)
            * setup.py is unparseable (conservative default)
- False → safe pattern. Any of:
            * Wheel-only release (no sdist, nothing executes at install)
            * Standard build-backend + no setup.py (PEP 517 pure config)
            * Standard build-backend + trivial setup.py that none of the
              above checks fire on
- None  → inspection failed (download error, archive corrupt). Caller logs
          and leaves has_install_scripts NULL.

"Conservative over False" is the rule: when unsure, return True so the
scope-boundary gate over-warns rather than under-warns. A false positive
costs a developer five seconds to override; a false negative costs a breach.

This does NOT attempt static taint tracking or sandbox execution. It's a
cheap structural check over the AST, designed to catch the common shapes
of malicious setup.py in the wild (network fetch + exec; os.system of
curl|sh; subclassed install command that steals tokens).
"""
from __future__ import annotations

import ast
import io
import logging
import tarfile
import zipfile
from typing import Any

import httpx

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

log = logging.getLogger("pypi_tarball")


# Build backends treated as standard — they run their own build logic but
# don't execute user code beyond what setup.py / pyproject config declares.
STANDARD_BUILD_BACKENDS = frozenset(
    {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "flit_core.buildapi",
        "flit.buildapi",
        "poetry.core.masonry.api",
        "poetry_core.masonry.api",
        "hatchling.build",
        "pdm.backend",
        "pdm.pep517.api",
        "maturin",
        "scikit_build_core.build",
        "mesonpy",
        "meson_python",
    }
)


# Whole-module imports that have no legitimate reason to appear in setup.py
# for a well-behaved package. `os` is deliberately NOT here — os.path is used
# legitimately for file path construction in thousands of setup.py files;
# we flag only specific dangerous os.* calls below.
DANGEROUS_MODULE_IMPORTS = frozenset(
    {
        "subprocess",
        "socket",
        "ctypes",
        "shutil",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "urllib.error",
        "http",
        "http.client",
        "requests",
        "httpx",
        "paramiko",
        "pycurl",
    }
)


# Specific `os.*` attributes that indicate command execution or process
# spawning. `os.path.*` and `os.environ[...]` do not match.
DANGEROUS_OS_ATTRS = frozenset(
    {
        "system",
        "popen",
        "popen2",
        "popen3",
        "popen4",
        "exec",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "fork",
    }
)


def _select_sdist(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    for f in files or []:
        if f.get("packagetype") == "sdist":
            return f
    return None


async def inspect_version(
    client: httpx.AsyncClient,
    package_name: str,
    version: str,
    files: list[dict[str, Any]],
    *,
    max_bytes: int = 150_000_000,
) -> bool | None:
    """Determine `has_install_scripts` for one version.

    `files` is the per-version file listing (same shape as `releases[ver]`
    in the bulk PyPI JSON). We select the sdist, stream-download it into
    a memory buffer, and classify. Wheel-only versions return False
    without any network IO.

    Streaming (rather than `resp.content`) means we can bail the moment a
    hostile or gigantic sdist exceeds `max_bytes`, without first pulling
    the whole body into RAM. 150MB is a deliberately generous cap: scipy,
    numpy, pandas, pillow, pyarrow all publish multi-tens-of-MB sdists
    under 100MB each; anything larger than 150MB is almost certainly a
    bundled binary blob and is skipped with a warning (returns None, the
    caller leaves has_install_scripts NULL for that row).
    """
    sdist = _select_sdist(files)
    if sdist is None:
        return False  # wheel-only: nothing runs at install

    url = sdist.get("url")
    filename = sdist.get("filename") or ""
    if not url:
        return None

    buf = io.BytesIO()
    bytes_read = 0
    try:
        async with client.stream("GET", url, timeout=120.0) as resp:
            if resp.status_code != 200:
                log.warning(
                    "sdist_fetch_status: pkg=%s ver=%s status=%s",
                    package_name,
                    version,
                    resp.status_code,
                )
                return None
            async for chunk in resp.aiter_bytes():
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    log.warning(
                        "sdist_too_big: pkg=%s ver=%s bytes=%s",
                        package_name,
                        version,
                        bytes_read,
                    )
                    return None
                buf.write(chunk)
    except httpx.HTTPError as e:
        log.warning(
            "sdist_fetch_failed: pkg=%s ver=%s err=%s", package_name, version, e
        )
        return None

    try:
        return _classify_archive(buf.getvalue(), filename)
    except Exception as e:
        log.warning(
            "sdist_parse_failed: pkg=%s ver=%s err=%s", package_name, version, e
        )
        return None


def _classify_archive(data: bytes, filename: str) -> bool | None:
    setup_py_source, pyproject_text = _extract_candidates(data, filename)

    # 1. Non-standard build backend? Treat as scripts.
    if pyproject_text:
        backend = _read_build_backend(pyproject_text)
        if backend and backend not in STANDARD_BUILD_BACKENDS:
            return True

    # 2. No setup.py at all means no code beyond the build backend's own
    #    logic, and we've already confirmed the backend is standard (or
    #    absent, which defaults to setuptools legacy — still standard).
    if setup_py_source is None:
        return False

    # 3. Walk setup.py AST looking for the red flags.
    return _analyze_setup_py(setup_py_source)


def _extract_candidates(
    data: bytes, filename: str
) -> tuple[str | None, str | None]:
    """Pull setup.py and pyproject.toml text out of a sdist archive.

    Only the shallowest match wins — setup.py under a nested `tests/`
    directory doesn't run at install time, so we ignore it.
    """
    setup_py: str | None = None
    pyproject: str | None = None
    setup_depth = 10**9
    pyproject_depth = 10**9

    def _consider(path: str, read_fn):
        nonlocal setup_py, pyproject, setup_depth, pyproject_depth
        parts = path.strip("/").split("/")
        depth = len(parts)
        tail = parts[-1]
        if tail == "setup.py" and depth < setup_depth:
            try:
                setup_py = _decode(read_fn())
                setup_depth = depth
            except Exception:
                pass
        elif tail == "pyproject.toml" and depth < pyproject_depth:
            try:
                pyproject = _decode(read_fn())
                pyproject_depth = depth
            except Exception:
                pass

    buf = io.BytesIO(data)
    lower = filename.lower()

    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        try:
            with tarfile.open(fileobj=buf, mode="r:*") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    _consider(member.name, lambda m=member, t=tar: t.extractfile(m).read())
        except tarfile.ReadError:
            pass
    elif lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(buf) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    _consider(info.filename, lambda i=info, z=zf: z.read(i))
        except zipfile.BadZipFile:
            pass

    return setup_py, pyproject


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _read_build_backend(pyproject_text: str) -> str | None:
    try:
        doc = tomllib.loads(pyproject_text)
    except Exception:
        return None
    build = doc.get("build-system") or {}
    backend = build.get("build-backend")
    if isinstance(backend, str):
        return backend.strip()
    return None


def _analyze_setup_py(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True  # unparseable → conservative

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in DANGEROUS_MODULE_IMPORTS:
                    return True
                root = alias.name.split(".")[0]
                if root in {"urllib", "http", "requests", "httpx"}:
                    return True

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                if node.module in DANGEROUS_MODULE_IMPORTS:
                    return True
                root = node.module.split(".")[0]
                if root in {"urllib", "http", "requests", "httpx"}:
                    return True

        elif isinstance(node, ast.Call):
            # bare exec(...) / eval(...)
            if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"}:
                return True

            # os.system / os.popen / os.exec* / os.spawn* / os.fork
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                if (
                    node.func.value.id == "os"
                    and node.func.attr in DANGEROUS_OS_ATTRS
                ):
                    return True

            # setup(cmdclass={...}) → someone overrode the install command.
            callee = node.func
            callee_name = (
                callee.id
                if isinstance(callee, ast.Name)
                else (callee.attr if isinstance(callee, ast.Attribute) else "")
            )
            if callee_name == "setup":
                for kw in node.keywords:
                    if kw.arg == "cmdclass":
                        return True

    return False
