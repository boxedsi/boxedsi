"""A keychain that never answers must not keep the command alive."""

import base64
import os
import subprocess
import sys
import threading

import keyring
import pytest
from keyring.backend import KeyringBackend

from boxed import keys
from boxed.errors import UserError
from boxed.locks import file_lock
from boxed.platform import LockTimeout


BLOCKED_COMMAND = r"""
import io, sys, threading
from pathlib import Path

import keyring
from keyring.backend import KeyringBackend

from boxed import keys
from boxed.cli import main

keys.KEYCHAIN_TIMEOUT = 0.1
keys._lock_folder = lambda: Path(sys.argv[2])

class BlockedKeychain(KeyringBackend):
    priority = 1
    reads = 0

    def get_password(self, service, username):
        self.reads += 1
        if sys.argv[1] == "get" or (sys.argv[1] == "locked-get" and self.reads == 2):
            threading.Event().wait()
        return None

    def set_password(self, service, username, password):
        threading.Event().wait()

    def delete_password(self, service, username):
        raise AssertionError("the command must not remove a key")

keyring.set_keyring(BlockedKeychain())
sys.stdin = io.StringIO("mail user@example.com")
args = ["mask", "-"]
if sys.argv[3] == "audit":
    args = ["audit", "--claude-dir", str(Path(sys.argv[2]) / "records"), "--codex-dir", str(Path(sys.argv[2]) / "other-records")]
raise SystemExit(main(args))
"""


@pytest.mark.parametrize("stage,command", [("get", "mask"), ("locked-get", "mask"), ("set", "mask"), ("get", "audit")])
def test_a_blocked_keychain_ends_the_cli_process_with_fixed_text(tmp_path, stage, command):
    result = subprocess.run(
        [sys.executable, "-c", BLOCKED_COMMAND, stage, str(tmp_path), command],
        cwd=tmp_path,
        env={**os.environ, "BOXED_KEYSTORE": "keyring"},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 2 and result.stdout == ""
    assert result.stderr == f"boxed: error: {keys.KEYCHAIN_TIMED_OUT}\n"


@pytest.mark.parametrize("late_failure", [False, True])
def test_a_timed_out_write_keeps_the_lock_until_it_finishes_without_logging(late_failure, tmp_path, monkeypatch):
    class SlowKeychain(KeyringBackend):
        priority = 1
        worker = None
        value = None

        def get_password(self, service, username):
            return self.value

        def set_password(self, service, username, password):
            self.worker = threading.current_thread()
            entered.set()
            release.wait(2)
            if late_failure:
                raise RuntimeError(f"backend details: {username} {password}")
            self.value = password

        def delete_password(self, service, username):
            raise AssertionError("the command must not remove a key")

    entered, release = threading.Event(), threading.Event()
    backend = SlowKeychain()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    failures = []
    monkeypatch.setattr(threading, "excepthook", failures.append)
    monkeypatch.setattr(keys, "KEYCHAIN_TIMEOUT", 0.1, raising=False)
    lock = tmp_path / "keychain"
    try:
        with pytest.raises(UserError) as error:
            keys.KeyringKeyStore(lock=lock).get_or_create("sample-key", 32)
        assert str(error.value).startswith("the system keychain did not answer:")
        assert entered.is_set()
        with pytest.raises(LockTimeout), file_lock(lock, timeout=0.01):
            pass
    finally:
        release.set()
        if backend.worker is not None and backend.worker is not threading.current_thread():
            backend.worker.join(5)
            assert not backend.worker.is_alive()
        keyring.set_keyring(previous)
    assert failures == []
    if not late_failure:
        assert len(base64.b64decode(backend.value)) == 32
