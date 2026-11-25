"""Getting something to check before it is installed: a folder, a file, a .zip, an https git address or `owner/repo[/path]` for GitHub.

Nothing of the target is run, imported or sourced. A folder or a file is used where it lies. A zip is unpacked into a fresh 0700 folder
under `work` with every member's name checked (no way out of the folder, no link made, no name twice, no executable bit), with caps on
the number of files and the bytes really written (a header may lie about its size); an encrypted zip is not unpacked at all but
handed over as the file, which the rules call `encrypted-archive` (critical). A git address is cloned shallow and without
submodules, hooks, templates, LFS, credentials, prompts, or any system or user git config, only over https, with a timeout; the only
exception is the test-only seam `ALLOW_LOCAL_REPOS`. The temp folder goes when the block ends, however it ends.

This is the one place that runs git, and it never puts what git says into an error: a message can carry an address with a login."""

import ntpath
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from boxed import platform
from boxed.errors import UserError

CLONE_TIMEOUT = 120.0  # seconds for a whole clone
MAX_ZIP_FILES = 10_000
MAX_ZIP_BYTES = 256 * 1024 * 1024  # of unpacked data, counted while writing
ALLOW_LOCAL_REPOS = False  # test-only seam: lets a file:// address through so a test can clone a local bare repo

_OWNER_REPO = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})((?:/[^/\s]+)*)")
_REF = re.compile(r"[A-Za-z0-9._-]{1,200}")
_GITHUB_HOSTS = ("github.com", "www.github.com")
NOT_ADDRESS = "the target is not a folder, a file, a .zip or an https git address: check the spelling or give owner/repo"
NOT_HTTPS = "only https git addresses are fetched: give an https address or clone it yourself and scan the folder"
CLONE_FAILED = "the address could not be fetched: check it, and that git is installed and the repository is public"
DAMAGED = "the archive is damaged or has conflicting names: it is not unpacked"
OUTSIDE = "the archive has a path that leaves its folder: it is not unpacked"
NOT_IN_REPO = "that path is not in the repository: check the address"


def _clean_path(parts: list[str]) -> list[str]:
    """The path parts of an address, or a refusal: no empty, dot or climbing part, and nothing a file system reads differently."""
    for part in parts:
        if part in ("", ".", "..") or "\\" in part or "\x00" in part or ":" in part:
            raise UserError(NOT_IN_REPO)
    return parts


def _github(owner: str, repo: str, extra: list[str], *, tree: bool) -> tuple[str, str | None, list[str], str]:
    """(clone url, ref, path inside the repo, label) of a GitHub address."""
    repo = repo.removesuffix(".git")
    if not repo or repo in (".", ".."):
        raise UserError(NOT_ADDRESS)
    ref = None
    if tree:  # /tree/<ref>/<path>: the ref is one name (a branch with a slash in it cannot be told from the path)
        if len(extra) < 2 or extra[0] != "tree":
            raise UserError(NOT_IN_REPO)
        ref, extra = extra[1], extra[2:]
        if not _REF.fullmatch(ref) or ref.startswith("-") or ".." in ref:
            raise UserError(NOT_ADDRESS)
    sub = _clean_path(extra)
    label = "/".join([owner, repo, *sub]) + (f"@{ref}" if ref else "")
    return f"https://github.com/{owner}/{repo}.git", ref, sub, label


def _parse_address(spec: str) -> tuple[str, str | None, list[str], str]:
    """(clone url, ref, path inside the repo, label) of an https address; anything else is a refusal that quotes nothing."""
    if ALLOW_LOCAL_REPOS and spec.lower().startswith("file://"):
        return spec, None, [], "local repository"
    try:
        parts = urlsplit(spec)
        host = parts.hostname
    except ValueError:
        raise UserError(NOT_ADDRESS) from None
    if parts.scheme.lower() != "https":
        raise UserError(NOT_HTTPS)
    if not host or "@" in parts.netloc or parts.query or parts.fragment:
        raise UserError("the address must be a plain https address: no login, query or fragment")
    segments = parts.path.strip("/").split("/") if parts.path.strip("/") else []
    if host.lower() in _GITHUB_HOSTS:
        if len(segments) < 2:
            raise UserError(NOT_ADDRESS)
        return _github(segments[0], segments[1], segments[2:], tree=len(segments) > 2)
    return spec, None, [], f"{host}{parts.path}"


def _env(home: Path) -> dict[str, str]:
    """A bare environment for git: none of the person's variables except the ones that find git and a proxy, and no config file."""
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(
        HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GCM_INTERACTIVE="never", LC_ALL="C",
        GIT_ALLOW_PROTOCOL="https:file" if ALLOW_LOCAL_REPOS else "https",
    )
    return env


def _clone(url: str, ref: str | None, folder: Path) -> Path:
    """Clones into folder/repo and returns it. git's own folder is removed: it is not part of what was published."""
    (folder / "home").mkdir()
    (folder / "template").mkdir()
    dest = folder / "repo"
    protocols = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    if ALLOW_LOCAL_REPOS:
        protocols += ["-c", "protocol.file.allow=always"]
    argv = [
        "git", "-c", "core.hooksPath=" + os.devnull, *protocols, "-c", "credential.helper=",
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules", "--template", str(folder / "template"),
        *([f"--branch={ref}"] if ref else []), "--", url, str(dest),
    ]
    try:
        done = subprocess.run(argv, env=_env(folder / "home"), stdin=subprocess.DEVNULL, capture_output=True, timeout=CLONE_TIMEOUT, check=False)
    except FileNotFoundError:
        raise UserError("git is not installed: install it, or download the repository and scan the folder") from None
    except (subprocess.TimeoutExpired, OSError):
        raise UserError(CLONE_FAILED) from None
    if done.returncode != 0 or not dest.is_dir():
        raise UserError(CLONE_FAILED)
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return dest


def _inside(repo: Path, sub: list[str]) -> Path:
    """repo/sub when every step is a real folder or file of the clone, never a link."""
    here = repo
    for part in sub:
        here = here / part
        try:
            info = os.lstat(here)
        except OSError:
            raise UserError(NOT_IN_REPO) from None
        if stat.S_ISLNK(info.st_mode):
            raise UserError(NOT_IN_REPO)
    return here


_WINDOWS_FORBIDDEN = frozenset('<>:"|?*') | frozenset(chr(c) for c in range(32))
# Device names by our own rule, beside ntpath.isreserved, which lets COM0 and LPT0 through: each refuses a name the other does not.
_WINDOWS_RESERVED = re.compile(r"(?i)(?:con|prn|aux|nul|conin\$|conout\$|(?:com|lpt)[0-9¹²³])(?:\.[^.]*)*")


def _member_parts(name: str) -> list[str]:
    """The path parts of a zip member, or a refusal when the name could leave the folder or mean something else on another system.
    Every part is judged by the rules of POSIX and of Windows alike, whatever runs the scan: no root, drive, UNC or device prefix, no
    `..`, no colon (a drive in the middle of a path, or an NTFS stream), no reserved device name as Windows itself judges it
    (`ntpath.isreserved`: `CON`, `nul.txt`, `COM1`, `con .txt` with spaces before the extension) or by our own rule (`COM0`,
    `lpt0.md`, which `ntpath.isreserved` lets through), no character Windows refuses and
    no trailing dot or space (Windows drops them, so two names could land on one file)."""
    text = name.replace("\\", "/")
    if text.startswith("/") or "\x00" in text or re.match(r"[A-Za-z]:", text):
        raise UserError(OUTSIDE)
    parts = [p for p in PurePosixPath(text).parts if p != "."]
    for part in parts:
        if (part == ".." or not _WINDOWS_FORBIDDEN.isdisjoint(part) or part.endswith((".", " "))
                or ntpath.isreserved(part) or _WINDOWS_RESERVED.fullmatch(part)):
            raise UserError(OUTSIDE)
    return parts


def _member_path(folder: Path, name: str) -> Path | None:
    """Where a zip member is written: inside `folder`, never anywhere else; None for the folder itself. Checked before anything is
    written, by the parts (_member_parts) and again on the joined path, as this system joins it."""
    parts = _member_parts(name)
    if not parts:
        return None
    dest = folder.joinpath(*parts)
    base = os.path.abspath(folder)
    joined = os.path.abspath(dest)
    if os.path.commonpath([base, joined]) != base or joined == base:
        raise UserError(OUTSIDE)
    return dest


class Fetched(tuple):
    """(folder to scan, label), which is all most callers unpack, and `links`: the links an archive held, as (path inside the folder,
    target text). They are not made on disk, so the scan cannot see them there; the command hands them to the rules (check_link)."""

    links: tuple[tuple[str, str], ...]

    def __new__(cls, folder: Path, label: str, links: tuple[tuple[str, str], ...] = ()) -> "Fetched":
        self = super().__new__(cls, (folder, label))
        self.links = tuple(links)
        return self


LINK_TARGET_MAX = 4096  # bytes of a link's target text that are read from an archive


def _unzip(archive: Path, folder: Path) -> tuple[bool, tuple[tuple[str, str], ...]]:
    """Unpacks into folder: (True, the links of the archive). (False, ()) when the archive is to be handed over as a file (encrypted, or
    not a zip after all)."""
    try:
        z = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError):
        return False, ()
    with z:
        infos = z.infolist()
        if any(i.flag_bits & 1 for i in infos):
            return False, ()
        if len(infos) > MAX_ZIP_FILES:
            raise UserError("the archive holds too many files to check here: unpack it yourself and scan the folder")
        links: list[tuple[str, str]] = []
        total = 0
        places = [_member_path(folder, info.filename) for info in infos]  # every name is judged before the first write
        for info, dest in zip(infos, places, strict=True):
            if stat.S_ISLNK(info.external_attr >> 16):  # never made: a link in an archive is how a file outside is reached; it is reported instead
                with z.open(info) as src:
                    links.append(("/".join(_member_parts(info.filename)), src.read(LINK_TARGET_MAX).decode("utf-8", "replace")))
                continue
            if dest is None:
                continue
            if info.is_dir():
                try:
                    dest.mkdir(parents=True, exist_ok=True)
                except (FileExistsError, NotADirectoryError):  # a file already holds this name
                    raise UserError(DAMAGED) from None
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                fd = platform.open_nofollow(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                raise UserError("the archive uses the same name twice: it is not unpacked") from None
            except OSError:
                raise UserError("the archive cannot be unpacked here: scan the folder after unpacking it yourself") from None
            try:
                with os.fdopen(fd, "wb") as out, z.open(info) as src:
                    while chunk := src.read(65536):
                        total += len(chunk)
                        if total > MAX_ZIP_BYTES:
                            raise UserError("the archive unpacks to too much data to check here: unpack it yourself and scan the folder")
                        out.write(chunk)
            except (zipfile.BadZipFile, zlib.error, EOFError):  # a bad CRC or a cut-off member
                raise UserError(DAMAGED) from None
    if links:
        print(f"boxed: {len(links)} link{'' if len(links) == 1 else 's'} in the archive {'was' if len(links) == 1 else 'were'} not unpacked, and will be reported", file=sys.stderr)
    return True, tuple(links)


@contextmanager
def target_folder(spec: str, *, work: Path) -> Iterator[Fetched]:
    """(what to scan, the label shown in the report) for a target. Folders and files are used in place; a zip or a clone lives in a
    0700 temp folder under `work` that is removed afterwards, also when the scan raises."""
    local = Path(spec).expanduser()
    if os.path.lexists(local):
        path = local.resolve()
        if path.is_file() and path.suffix.lower() in (".zip", ".skill"):
            temp = Path(tempfile.mkdtemp(prefix=".boxed-skills-", dir=work))
            try:
                unpacked, links = _unzip(path, temp)
                yield Fetched(temp, path.name, links) if unpacked else Fetched(path, path.name)
            finally:
                shutil.rmtree(temp, ignore_errors=True)
            return
        yield Fetched(path, path.name)
        return
    announce = None
    match = _OWNER_REPO.fullmatch(spec)
    if "://" in spec or spec.startswith("git@"):  # an address, whatever else it looks like
        url, ref, sub, label = _parse_address(spec)
    elif match:  # owner/repo of any owner, also one whose name starts like a scheme (httpie, sshuttle, filecoin-project)
        owner, repo, tail = match.groups()
        url, ref, sub, label = _github(owner, repo, tail.split("/")[1:], tree=False)
        announce = f"boxed: no folder of that name here, taking https://github.com/{owner}/{repo}"
    else:
        raise UserError(NOT_ADDRESS)
    if announce:
        print(announce, file=sys.stderr)
    temp = Path(tempfile.mkdtemp(prefix=".boxed-skills-", dir=work))
    try:
        repo_folder = _clone(url, ref, temp)
        yield Fetched(_inside(repo_folder, sub), label)
    finally:
        shutil.rmtree(temp, ignore_errors=True)
