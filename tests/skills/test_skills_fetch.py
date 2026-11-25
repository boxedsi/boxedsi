"""Getting something to check before it is installed: a folder, a file, a zip or a git address. Nothing of the target is ever run.
Git runs only for an https address; the tests clone a local bare repo through the test-only seam (fetch.ALLOW_LOCAL_REPOS) and
look at the command line of git for everything else."""

import ntpath
import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

from boxed.skills import fetch, rules
from boxed.skills.fetch import target_folder


@pytest.fixture
def work(tmp_path):
    folder = tmp_path / "work"
    folder.mkdir()
    return folder


def leftovers(work: Path) -> list[str]:
    return sorted(p.name for p in work.iterdir())


def make_zip(path: Path, members: dict[str, bytes | str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


def listing(folder: Path) -> list[str]:
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())


# ---- folders, files, zips ----


def test_a_folder_is_scanned_where_it_is_under_its_own_name(tmp_path, work):
    skill = tmp_path / "my-skill"
    (skill).mkdir()
    (skill / "SKILL.md").write_text("hi\n")
    with target_folder(str(skill), work=work) as (folder, label):
        assert folder == skill.resolve() and label == "my-skill"
    assert leftovers(work) == [] and (skill / "SKILL.md").exists()


def test_a_single_file_is_scanned_as_it_is(tmp_path, work):
    one = tmp_path / "notes.md"
    one.write_text("hi\n")
    with target_folder(str(one), work=work) as (path, label):
        assert path == one.resolve() and label == "notes.md"


def test_a_zip_is_unpacked_into_a_private_temp_folder_that_goes_afterwards(tmp_path, work):
    archive = make_zip(tmp_path / "pack.zip", {"my-skill/SKILL.md": "hi\n", "my-skill/scripts/run.sh": "echo hi\n"})
    with target_folder(str(archive), work=work) as (folder, label):
        assert label == "pack.zip" and listing(folder) == ["my-skill/SKILL.md", "my-skill/scripts/run.sh"]
        assert folder.parent == work and stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert not os.access(folder / "my-skill/scripts/run.sh", os.X_OK)  # nothing is made executable
    assert leftovers(work) == []


def test_the_temp_folder_goes_when_the_check_fails_too(tmp_path, work):
    archive = make_zip(tmp_path / "pack.zip", {"a.md": "hi\n"})
    with pytest.raises(RuntimeError):
        with target_folder(str(archive), work=work):
            raise RuntimeError("the scan broke")
    assert leftovers(work) == []


@pytest.mark.parametrize("name", ["../escape.md", "/abs.md", "a/../../escape.md", "C:/win.md", "..\\escape.md", "a\\..\\..\\escape.md"])
def test_a_member_that_leaves_the_folder_refuses_the_archive_and_writes_nothing(tmp_path, work, name):
    archive = make_zip(tmp_path / "evil.zip", {"ok.md": "fine\n", name: "x\n"})
    with pytest.raises(ValueError, match="leaves its folder"):
        with target_folder(str(archive), work=work):
            pass
    assert leftovers(work) == [] and not (tmp_path / "escape.md").exists() and not (tmp_path / "abs.md").exists()


WINDOWS_ONLY_ESCAPES = [
    "a/C:evil.md", "a\\D:\\x.md", "c:x.md", "\\\\server\\share\\x.md", "//server/share/x.md", "\\\\?\\C:\\x.md", "\\\\.\\pipe\\x",
    "dir\\..\\..\\x.md", "SKILL.md:hidden", "a/file.txt::$DATA", "CON", "a/nul.txt", "Aux.tar.gz", "COM1", "lpt9.md", "com\u00b9",
    "conin$", "a/name.", "a/name ", "a/b<c", "a/b|c", "a/b?c", "a/b*c", 'a/b"c', "a/b\x01c",
    "con .txt", "a/NUL  .md", "LPT3 .log", "aux .tar.gz", "prn .d/x.md",  # spaces before the extension: Windows still opens the device
    "COM0", "lpt0.md", "a/Com0.tar.gz", "LPT².log",  # ntpath.isreserved lets COM0 and LPT0 through: the own rule refuses them
]


def test_both_judges_of_a_reserved_name_are_needed():
    """ntpath.isreserved and the own rule each refuse a name the other lets through: neither alone is the whole check."""
    assert not ntpath.isreserved("COM0") and fetch._WINDOWS_RESERVED.fullmatch("COM0")
    assert ntpath.isreserved("con .txt") and not fetch._WINDOWS_RESERVED.fullmatch("con .txt")


@pytest.mark.parametrize("name", WINDOWS_ONLY_ESCAPES)
def test_a_member_name_is_judged_by_the_rules_of_windows_too_on_any_system(name):
    with pytest.raises(ValueError, match="leaves its folder"):
        fetch._member_parts(name)


@pytest.mark.parametrize("name", ["my-skill/SKILL.md", "a/.hidden/b.md", "console.md", "com10.md", "auxiliary/x.md", "v1.2/x", "./a.md"])
def test_ordinary_member_names_still_unpack(name, tmp_path):
    dest = fetch._member_path(tmp_path, name)
    assert dest is not None and dest.is_relative_to(tmp_path) and dest != tmp_path


def test_a_member_whose_joined_path_leaves_the_folder_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "_member_parts", lambda name: ["..", "x.md"])  # as if a part slipped past the name rules
    with pytest.raises(ValueError, match="leaves its folder"):
        fetch._member_path(tmp_path / "unpack", "x")


def test_every_member_name_is_judged_before_the_first_write(tmp_path):
    archive = make_zip(tmp_path / "evil.zip", {"first.md": "fine\n", "second/x.md": "fine\n", "a/C:evil.md": "x\n"})
    folder = tmp_path / "unpack"
    folder.mkdir()
    with pytest.raises(ValueError, match="leaves its folder"):
        fetch._unzip(archive, folder)
    assert list(folder.iterdir()) == []


def test_a_device_name_with_spaces_before_its_extension_refuses_the_archive_before_the_first_write(tmp_path):
    archive = make_zip(tmp_path / "evil.zip", {"first.md": "fine\n", "skill/SKILL.md": "fine\n", "skill/con .txt": "x\n"})
    folder = tmp_path / "unpack"
    folder.mkdir()
    with pytest.raises(ValueError, match="leaves its folder"):
        fetch._unzip(archive, folder)
    assert list(folder.iterdir()) == []


def test_links_in_an_archive_are_not_created_but_handed_on_with_their_targets(tmp_path, work, capsys):
    path = tmp_path / "links.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("sk/SKILL.md", "hi\n")
        for name, target in (("sk/link", "/etc/hosts"), ("sk/docs/up", "../../../.ssh")):
            link = zipfile.ZipInfo(name)
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(link, target)
    with target_folder(str(path), work=work) as fetched:
        folder, label = fetched  # still a pair to unpack
        assert listing(folder) == ["sk/SKILL.md"] and not (folder / "sk/link").is_symlink() and not (folder / "sk/link").exists()
        assert fetched.links == (("sk/link", "/etc/hosts"), ("sk/docs/up", "../../../.ssh"))
    assert "2 links in the archive were not unpacked, and will be reported" in capsys.readouterr().err


def test_an_encrypted_zip_is_handed_over_as_a_file_and_the_rules_call_it_critical(tmp_path, work):
    path = make_zip(tmp_path / "locked.zip", {"payload.bin": "secret stuff\n"})
    raw = bytearray(path.read_bytes())
    for header in (b"PK\x03\x04", b"PK\x01\x02"):  # set the "encrypted" flag in the local and the central header
        at = raw.index(header)
        raw[at + (6 if header == b"PK\x03\x04" else 8)] |= 1
    path.write_bytes(bytes(raw))
    with target_folder(str(path), work=work) as (target, label):
        assert target == path.resolve() and label == "locked.zip"  # nothing is unpacked
        report = rules.check_file(target, label)
    assert any(f.rule == "encrypted-archive" and f.severity == "critical" for f in report.findings)


def test_a_zip_with_too_many_files_or_too_many_bytes_is_refused(tmp_path, work, monkeypatch):
    many = make_zip(tmp_path / "many.zip", {f"f{i}.md": "x\n" for i in range(5)})
    monkeypatch.setattr(fetch, "MAX_ZIP_FILES", 4)
    with pytest.raises(ValueError, match="too many files"):
        with target_folder(str(many), work=work):
            pass
    big = make_zip(tmp_path / "big.zip", {"zeros.txt": "0" * 50_000})  # packs tiny, unpacks large
    monkeypatch.setattr(fetch, "MAX_ZIP_FILES", 100)
    monkeypatch.setattr(fetch, "MAX_ZIP_BYTES", 10_000)
    with pytest.raises(ValueError, match="too much data"):
        with target_folder(str(big), work=work):
            pass
    assert leftovers(work) == []


@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_a_name_used_twice_in_an_archive_is_refused(tmp_path, work):
    path = tmp_path / "twice.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.md", "one\n")
        z.writestr("a.md", "two\n")
    with pytest.raises(ValueError, match="same name"):
        with target_folder(str(path), work=work):
            pass
    assert leftovers(work) == []


@pytest.mark.parametrize("kind", ["file-then-folder", "bad-crc"])
def test_a_damaged_or_conflicting_zip_is_refused_without_quoting_a_path(tmp_path, work, capsys, kind):
    path = tmp_path / "odd.zip"
    if kind == "file-then-folder":
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("a", "one\n")
            z.writestr("a/", "")
    else:
        make_zip(path, {"secret-name.md": "hello\n"})
        data = bytearray(path.read_bytes())
        data[data.index(b"hello")] ^= 0xFF  # stored, not deflated: the CRC no longer matches
        path.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="damaged or has conflicting names"):
        with target_folder(str(path), work=work):
            pass
    assert leftovers(work) == []
    from boxed.cli import main

    assert main(["skills", "scan", str(path)]) == 2
    err = capsys.readouterr().err
    assert "damaged or has conflicting names" in err and "secret-name" not in err


def test_a_zip_that_cannot_be_read_is_scanned_as_a_file(tmp_path, work):
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"PK\x03\x04 this is not an archive")
    with target_folder(str(broken), work=work) as (target, label):
        assert target == broken.resolve() and label == "broken.zip"


# ---- addresses ----


@pytest.mark.parametrize(
    "spec",
    ["http://github.com/o/r", "git@github.com:o/r.git", "ssh://git@github.com/o/r.git", "git://github.com/o/r", "file:///tmp/x.git", "ftp://h/x", "just-a-word"],
)
def test_an_address_that_is_not_https_is_refused_before_git_runs(spec, tmp_path, work, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: pytest.fail("git must not run"))
    with pytest.raises(ValueError, match="https"):
        with target_folder(spec, work=work):
            pass


@pytest.mark.parametrize("spec", ["https://user:pw@github.com/o/r", "https://github.com/o/r?token=abc", "https://github.com/o/r#frag"])
def test_an_address_with_a_login_a_query_or_a_fragment_is_refused(spec, work, monkeypatch):
    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: pytest.fail("git must not run"))
    with pytest.raises(ValueError) as caught:
        with target_folder(spec, work=work):
            pass
    assert "pw" not in str(caught.value) and "abc" not in str(caught.value)


class FakeGit:
    """Stands in for subprocess.run: remembers the call and lays down a checkout where git was told to put it."""

    def __init__(self, files=None, code=0, error=None):
        self.calls = []
        self.files = files if files is not None else {"SKILL.md": "hi\n", "sub/dir/SKILL.md": "inner\n"}
        self.code, self.error = code, error

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error:
            raise self.error
        dest = Path(argv[-1])
        for name, text in self.files.items():
            (dest / name).parent.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(text)
        (dest / ".git").mkdir()
        (dest / ".git" / "config").write_text("x\n")
        return subprocess.CompletedProcess(argv, self.code, b"", b"fatal: https://user:pw@host/x\n")


@pytest.fixture
def git(monkeypatch):
    fake = FakeGit()
    monkeypatch.setattr(fetch.subprocess, "run", fake)
    return fake


def test_the_clone_is_shallow_hardened_and_bound_by_a_timeout(git, work):
    with target_folder("https://github.com/acme/tool", work=work) as (folder, label):
        assert label == "acme/tool" and (folder / "SKILL.md").exists()
        assert not (folder / ".git").exists()  # git's own folder is not part of what was published
    argv, kwargs = git.calls[0]
    assert argv[0] == "git" and argv[argv.index("clone") + 1:][:1] == ["--depth"] and "1" in argv
    assert "--no-recurse-submodules" in argv and "--single-branch" in argv and "--no-tags" in argv
    assert argv.index("--") < argv.index("https://github.com/acme/tool.git")
    assert "core.hooksPath=" + os.devnull in argv and "protocol.allow=never" in argv and "protocol.https.allow=always" in argv
    env = kwargs["env"]
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_GLOBAL"] == os.devnull and env["GIT_CONFIG_SYSTEM"] == os.devnull
    assert env["GIT_LFS_SKIP_SMUDGE"] == "1" and env["GIT_ALLOW_PROTOCOL"] == "https"
    assert Path(env["HOME"]).parent == work or str(work) in env["HOME"]  # no user git config is found
    assert kwargs["timeout"] == fetch.CLONE_TIMEOUT and kwargs["stdin"] == subprocess.DEVNULL
    assert leftovers(work) == []


def test_a_github_tree_address_takes_the_ref_and_the_path(git, work):
    with target_folder("https://github.com/acme/tool/tree/v2/sub/dir", work=work) as (folder, label):
        assert label == "acme/tool/sub/dir@v2" and (folder / "SKILL.md").read_text() == "inner\n"
    argv = git.calls[0][0]
    assert "--branch=v2" in argv and "https://github.com/acme/tool.git" in argv


@pytest.mark.parametrize("tail", ["tree/main/../../escape", "tree/main/a//b", "tree"])
def test_a_tree_address_with_a_path_that_climbs_is_refused(git, work, tail):
    with pytest.raises(ValueError):
        with target_folder("https://github.com/acme/tool/" + tail, work=work):
            pass
    assert leftovers(work) == []


def test_a_path_that_is_not_in_the_repository_is_an_error(git, work):
    with pytest.raises(ValueError, match="not in the repository"):
        with target_folder("https://github.com/acme/tool/tree/main/nope", work=work):
            pass
    assert leftovers(work) == []


def test_a_path_that_goes_through_a_link_in_the_clone_is_refused(work, monkeypatch):
    class Linked(FakeGit):
        def __call__(self, argv, **kwargs):
            result = super().__call__(argv, **kwargs)
            os.symlink("/etc", Path(argv[-1]) / "out")
            return result

    monkeypatch.setattr(fetch.subprocess, "run", Linked())
    with pytest.raises(ValueError, match="not in the repository"):
        with target_folder("https://github.com/acme/tool/tree/main/out", work=work):
            pass
    assert leftovers(work) == []


def test_owner_repo_is_taken_for_github_only_without_such_a_folder_and_says_so(git, tmp_path, work, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with target_folder("acme/tool/sub/dir", work=work) as (folder, label):
        assert label == "acme/tool/sub/dir" and (folder / "SKILL.md").exists()
    assert "https://github.com/acme/tool" in capsys.readouterr().err
    assert "https://github.com/acme/tool.git" in git.calls[0][0]


@pytest.mark.parametrize("spec", ["httpie/cli", "HTTPie/cli", "sshuttle/sshuttle", "filecoin-project/lotus"])
def test_owner_repo_is_taken_whatever_the_owner_starts_with(git, tmp_path, work, monkeypatch, capsys, spec):
    monkeypatch.chdir(tmp_path)  # no folder of that name here
    with target_folder(spec, work=work) as (folder, label):
        assert label == spec and (folder / "SKILL.md").exists()
    assert f"taking https://github.com/{spec}" in capsys.readouterr().err
    assert f"https://github.com/{spec}.git" in git.calls[0][0]


def test_owner_repo_that_is_a_local_folder_is_the_folder(tmp_path, work, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "acme" / "tool").mkdir(parents=True)
    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: pytest.fail("git must not run"))
    with target_folder("acme/tool", work=work) as (folder, label):
        assert folder == (tmp_path / "acme" / "tool").resolve()
    assert capsys.readouterr().err == ""


def test_a_failed_clone_is_a_fixed_error_that_quotes_nothing_and_leaves_no_temp(work, monkeypatch):
    for fake in (FakeGit(code=128), FakeGit(error=subprocess.TimeoutExpired("git", 1)), FakeGit(error=FileNotFoundError("git"))):
        monkeypatch.setattr(fetch.subprocess, "run", fake)
        with pytest.raises(ValueError) as caught:
            with target_folder("https://github.com/acme/tool", work=work):
                pass
        assert "pw" not in str(caught.value) and "host" not in str(caught.value) and leftovers(work) == []


# ---- a real clone, of a local bare repo, through the test-only seam ----

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}


def git_run(*args, cwd=None):
    subprocess.run(["git", *args], check=True, cwd=cwd, env=GIT_ENV, capture_output=True)


@pytest.fixture
def bare(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    git_run("init", "-q", "-b", "main", cwd=source)
    (source / "SKILL.md").write_text("---\nname: s\n---\nhi\n")
    (source / "scripts").mkdir()
    (source / "scripts" / "run.sh").write_text("echo hi\n")
    git_run("add", ".", cwd=source)
    git_run("commit", "-q", "-m", "first", cwd=source)
    repo = tmp_path / "repo.git"
    git_run("clone", "-q", "--bare", str(source), str(repo))
    return repo


def test_a_real_clone_of_a_local_bare_repo_through_the_seam(bare, work, monkeypatch):
    monkeypatch.setattr(fetch, "ALLOW_LOCAL_REPOS", True)
    with target_folder(bare.as_uri(), work=work) as (folder, label):
        assert listing(folder) == ["SKILL.md", "scripts/run.sh"]
    assert leftovers(work) == []


def test_without_the_seam_a_file_address_is_refused(bare, work):
    with pytest.raises(ValueError, match="https"):
        with target_folder(bare.as_uri(), work=work):
            pass
