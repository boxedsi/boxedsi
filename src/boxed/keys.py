"""Symmetric and signing key material, kept in the OS keyring."""

import base64
import os
import threading
from pathlib import Path
from typing import Protocol

from .errors import UserError
from .locks import file_lock
from .platform import open_nofollow, replace_file

SERVICE = "boxed.si"
KEYCHAIN_TIMEOUT = 30.0
# fixed words: the error of a keyring backend names no fix and may quote the key it was given
KEYCHAIN_MISSING = (
    "the system keychain cannot be used, and boxed keeps its keys there: on linux, run a secret service such as gnome keyring "
    "or kwallet in your session"
)
KEYCHAIN_TIMED_OUT = (
    "the system keychain did not answer: it may be locked or have no desktop session; unlock it, or use the insecure-file keystore "
    "only in a throwaway home with made-up data"
)
LOCK_FOLDER_UNSAFE = (
    "the folder for the keychain lock in the temporary folder is not a private folder of this user: remove it, or make the home "
    "folder writable"
)


class KeychainTimeout(UserError):
    """The keychain did not answer before the caller's deadline."""


class KeyStore(Protocol):
    def get_or_create(self, name: str, size: int) -> bytes: ...


def _decode(value: str, size: int, name: str) -> bytes:
    key = base64.b64decode(value)
    if len(key) != size:
        raise ValueError(f"key {name!r} has {len(key)} bytes, expected {size}")
    return key


def _lock_folder() -> Path:
    """Where the lock of the first key lives: ~/.boxed, the default data folder (the user's, not the one BOXED_HOME names). When it
    cannot be made (no home folder, a read-only one), a folder of the user in the system's temporary folder: one per user too, so
    two processes still meet there. Another user could make that folder first, or a link in its place: it is used only when it is
    a folder, not a link, of this user, closed to others (platform.private_folder); else LOCK_FOLDER_UNSAFE."""
    folder = Path.home() / ".boxed"
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        return folder
    except OSError:
        pass
    import tempfile

    from .platform import private_folder, user_temp_name

    folder = Path(tempfile.gettempdir()) / user_temp_name("boxed")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if not private_folder(os.lstat(folder)):
        raise UserError(LOCK_FOLDER_UNSAFE)
    return folder


class KeyringKeyStore:
    """macOS Keychain, Windows Credential Manager or Secret Service, via the keyring library.

    A key that is not there yet is made under a lock and read again under it: two processes that start at once would otherwise
    each make a key, and the one written last would leave the other's vault map or journal signature unreadable. The keychain
    entry is one per user (SERVICE and the name of the key), whatever BOXED_HOME says, so the lock is one per user too:
    ~/.boxed/keychain.lock (see _lock_folder). A key that is there is read without the lock, which a process in the boxed run
    sandbox could not take."""

    def __init__(self, lock: Path | None = None) -> None:
        self.lock = lock  # None: ~/.boxed/keychain.lock, the one of the user (see _lock_folder)

    def get_or_create(self, name: str, size: int) -> bytes:
        """Bound the wait for the whole operation. A blocked backend cannot be cancelled, so its worker is a daemon and keeps
        the first-key lock until its write finishes; the caller must not release that lock when it stops waiting."""
        outcome: list[bytes | BaseException] = []

        def run() -> None:
            try:
                outcome.append(self._get_or_create(name, size))
            except BaseException as error:  # return even an invariant failure; never print a late backend error from the thread
                outcome.append(error)

        worker = threading.Thread(target=run, name="boxed-keychain", daemon=True)
        worker.start()
        worker.join(KEYCHAIN_TIMEOUT)
        if worker.is_alive():
            raise KeychainTimeout(KEYCHAIN_TIMED_OUT) from None
        result = outcome[0]
        if isinstance(result, BaseException):
            raise result
        return result

    def _get_or_create(self, name: str, size: int) -> bytes:
        import keyring

        try:
            value = keyring.get_password(SERVICE, name)
        except AssertionError:  # a broken invariant (or the guard of the tests) is no missing keychain
            raise
        except Exception:  # no backend, a locked keychain, a backend's own error
            raise UserError(KEYCHAIN_MISSING) from None
        if value is None:
            if self.lock is None:
                self.lock = _lock_folder() / "keychain"
            with file_lock(self.lock):
                try:
                    value = keyring.get_password(SERVICE, name)
                    if value is None:
                        value = base64.b64encode(os.urandom(size)).decode()
                        keyring.set_password(SERVICE, name, value)
                except AssertionError:
                    raise
                except Exception:
                    raise UserError(KEYCHAIN_MISSING) from None
        return _decode(value, size, name)


class InsecureFileKeyStore:
    """Keys in plain files. For tests only."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def get_or_create(self, name: str, size: int) -> bytes:
        """A new key is made under a lock and read again under it, then written whole through a part file: a second process
        never makes a key of its own, and never reads half of one."""
        path = self.directory / f"{name}.key"
        if not path.exists():
            self.directory.mkdir(parents=True, exist_ok=True)
            with file_lock(path):
                if not path.exists():
                    part = path.with_name(path.name + ".part")
                    part.unlink(missing_ok=True)
                    with os.fdopen(open_nofollow(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                        f.write(base64.b64encode(os.urandom(size)).decode())
                        f.flush()
                        os.fsync(f.fileno())
                    replace_file(part, path)
        return _decode(path.read_text(), size, name)


def default_keystore() -> KeyStore:
    mode = os.environ.get("BOXED_KEYSTORE", "keyring")
    if mode == "keyring":
        return KeyringKeyStore()
    if mode == "insecure-file":
        from .paths import boxed_home

        return InsecureFileKeyStore(boxed_home() / "insecure-keys")
    raise UserError("unknown BOXED_KEYSTORE: it takes keyring or insecure-file")
