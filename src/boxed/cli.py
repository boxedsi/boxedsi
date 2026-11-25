"""Command line interface: `boxed <command>`."""

import argparse
import csv
import getpass
import hashlib
import io
import json
import os
import re
import stat
import sys
import unicodedata
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from . import platform as plat
from .config import load_config, to_detect_config
from .journal import Journal, JournalEntry
from .keys import default_keystore
from .locks import file_lock
from .detect import KINDS_BY_LEVEL, detect
from .errors import UserError
from .mask import MarkerMap, dictionary_kinds, mask_text, restore
from .outputs import Target
from .paths import boxed_home, boxed_home_path
from .platform import LockTimeout, make_private, open_nofollow, refuse_on_windows, utf8_console
from .vault import Vault

EXIT_OK, EXIT_FAIL, EXIT_ERROR, EXIT_ANOMALY, EXIT_POLICY, EXIT_DUE = 0, 1, 2, 3, 4, 5
# the categories the person names: strategy, hr and health have no detector, and finance only finds the amounts
# of level 3; the others (secrets, personal data, clients, code) come from what the detectors find
NAMED_CATEGORIES = ("finance", "strategy", "hr", "health")
NEEDS_MACOS_OR_HOOKS = ("run", "workspace", "mcp", "hook")  # the sandbox and the guard of the hooks: refused on Windows for now
DELIMITERS = {"comma": ",", "semicolon": ";", "tab": "\t", "pipe": "|"}  # --delimiter of a csv file, by name: ; and | mean things to a shell
# fixed words where the message of an error is not shown: it may quote a path, a setting or a value
HOOK_LOG_NOTE = "the hook failed; the message of the error is not kept"
UNEXPECTED = "an unexpected error; its message is not shown, it may quote a path or a value"
VAULT_UNREADABLE = "a marker map of the vault cannot be decrypted: wrong key or tampered data"
LOCK_BUSY = "boxed: error: another process holds a lock of boxed for too long; try again, or stop that process"
OWN_OS_WORDS = ("a link or another reparse point", "a folder")  # the fixed words of the OSErrors of platform.open_nofollow
DATE_FORMAT = "a date is written YYYY-MM-DD, for example 2026-12-31"
UNKNOWN_SCOPE = "unknown scope: boxed journal show lists the scopes in use (the scope field)"
NEEDS_TARGET = {
    "create": "create needs the project folder",
    "sync": "sync needs the workspace id (boxed workspace list shows them)",
    "drop": "drop needs the workspace id (boxed workspace list shows them)",
}


class Context:
    def __init__(self) -> None:
        self.home = boxed_home()
        self.keys = default_keystore()
        self.vault = Vault(self.home / "vault.db", self.keys)
        self.journal = Journal(self.home / "journal.jsonl", self.keys)


def _read_input(name: str) -> str:
    """The text of a file or of stdin. Python's own error for a byte that is not UTF-8 names that byte and its place: a piece of
    the input, which no error text may carry."""
    try:
        if name == "-":
            stream = getattr(sys.stdin, "buffer", None)
            return stream.read().decode("utf-8") if stream else sys.stdin.read()
        return Path(name).read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise UserError("the input is not UTF-8") from None


def _read_table(name: str) -> tuple[list[str], list[list[str]], str]:
    """A CSV table as header, data rows without blank lines and its delimiter; UTF-8 only."""
    text = _read_input(name).lstrip("\ufeff")
    if "\x00" in text:
        raise UserError("the table is not UTF-8 text")
    sample = text[:65536]
    if plat.IS_WINDOWS:  # a table from Excel has \r\n line ends there, and Python up to 3.13.14 cannot sniff such a text when its last line is blank
        sample = sample.replace("\r\n", "\n")
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        delimiter = ","
    rows = [row for row in csv.reader(io.StringIO(text), delimiter=delimiter) if any(cell.strip() for cell in row)]
    if not rows:
        raise UserError("the table is empty")
    return rows[0], rows[1:], delimiter


def _date(text: str | None):
    try:
        return datetime.strptime(text, "%Y-%m-%d").date() if text else None
    except ValueError:  # Python's own message quotes the text it was given
        raise UserError(DATE_FORMAT) from None


def _day_argument(text: str):
    """--since and --until, checked while the arguments are read: a wrong date gets the fixed words of _date, never the text."""
    try:
        return _date(text)
    except ValueError:
        raise argparse.ArgumentTypeError(DATE_FORMAT) from None


def _print_report(report, output: str) -> None:
    print(f"{report.format}: {report.source} -> {output}")
    print("checked: " + ("; ".join(report.checked) or "nothing"))
    if report.dropped:
        print("left out: " + "; ".join(report.dropped))
    print("markers: " + (", ".join(f"{k} {n}" for k, n in sorted(report.markers_by_kind.items())) or "none"))
    print("complete: yes" if report.complete else "complete: no - check what was left out before you send it")


def _journal_file(ctx: "Context", scope: str, status: str, level: int, report, payload: bytes) -> None:
    ctx.journal.append(
        JournalEntry(
            channel="manual",
            provider="unknown",
            account_type="unknown",
            level=level,
            markers_by_kind=report.markers_by_kind,
            status=status,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            coverage=f"{report.format} file, {'complete' if report.complete else 'incomplete'}",
            scope=scope,
            versions={"boxed": __version__},
        )
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _refuse_plan_level(level: int) -> None:
    """Level 4 is a plan (the task and the table schema, boxed plan), not a masked text: the detector reads it as 3, so a text
    masked here would go out at 3 and the journal would call it 4. Refused in the words ask uses, before anything is written."""
    if level >= max(KINDS_BY_LEVEL):
        from .channels import _PLAN_REFUSAL

        raise UserError(_PLAN_REFUSAL)


def cmd_mask(args: argparse.Namespace) -> int:
    config = load_config(Path.cwd())
    level = config.level if args.level is None else args.level
    _refuse_plan_level(level)
    scope = args.scope or "manual-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    text = _read_input(args.file)
    ctx = Context()
    with ctx.vault.transaction(scope) as markers:
        masked, counts = mask_text(text, markers, level=level, config=to_detect_config(config))
    ctx.journal.append(
        JournalEntry(
            channel="manual",
            provider="unknown",
            account_type="unknown",
            level=level,
            markers_by_kind=counts,
            status="prepared",
            payload_sha256=_sha256(masked),
            coverage="full",
            scope=scope,
            versions={"boxed": __version__},
        )
    )
    sys.stdout.write(masked)
    print(f"scope: {scope}", file=sys.stderr)
    return EXIT_OK


def cmd_restore(args: argparse.Namespace) -> int:
    ctx = Context()
    if args.scope not in ctx.vault.scopes():
        raise UserError(UNKNOWN_SCOPE)
    text = _read_input(args.file)
    result = restore(text, ctx.vault.load_map(args.scope), dictionary_kinds(load_config(Path.cwd())))
    ctx.journal.append(
        JournalEntry(
            channel="manual",
            provider="unknown",
            account_type="unknown",
            level=-1,
            markers_by_kind={},
            status="received",
            payload_sha256=_sha256(text),
            coverage="full",
            scope=args.scope,
            versions={"boxed": __version__},
            note=f"restored={result.restored} unknown={len(result.unknown)} suspicious={len(result.suspicious)}",
        )
    )
    anomalies = result.unknown + result.suspicious
    if anomalies:
        print("not restored, check by hand: " + ", ".join(anomalies), file=sys.stderr)
        if not args.force:
            return EXIT_ANOMALY
    sys.stdout.write(result.text)
    return EXIT_OK


def _shown(text: str, stream) -> str:
    """The text as a terminal may be given it: control characters other than the line feed and the tab as \\xNN, because the
    answer comes from the network and ESC, CR, BEL and the C1 characters move the cursor, retitle the window or write to the
    clipboard (OSC 52). Into a pipe or a file the text goes exactly as it is."""
    if not stream.isatty():
        return text
    return "".join(f"\\x{ord(c):02x}" if unicodedata.category(c) == "Cc" and c not in "\n\t" else c for c in text)


def _send(provider, model: str, prompt: str, key: str):
    """channels.call, after one line on stderr when the request goes to a relay and not to the provider's own address. It is
    said here, where the request is made: a policy block or a refused argument sends nothing, so says nothing."""
    from urllib.parse import urlsplit

    from .channels import PROVIDERS, call

    if provider.base_url != PROVIDERS[provider.name].base_url:
        where = f"{urlsplit(provider.base_url).netloc} (BOXED_{provider.name.upper()}_BASE_URL)"
        print(f"boxed: sending through the relay at {where}", file=sys.stderr)
    return call(provider, model, prompt, key)


def cmd_ask(args: argparse.Namespace) -> int:
    """Mask a prompt, send it through the person's API key and print the restored answer. Nothing but the answer reaches
    stdout; the key is never printed, and an error says only what channels.py lets through."""
    from .channels import ChannelError, PolicyBlocked, api_key, ask

    key = api_key(args.provider)
    if key is None:
        print(f"boxed: no API key for {args.provider}: run boxed key set {args.provider}", file=sys.stderr)
        return EXIT_ERROR
    config = load_config(Path.cwd())
    scope = args.scope or "ask-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    text = _read_input(args.file)
    ctx = Context()
    try:
        result = ask(
            text, provider=args.provider, model=args.model, key=key, scope=scope, vault=ctx.vault, journal=ctx.journal,
            config=config, account=args.account, level=args.level, categories=args.category or (), transport=_send,
        )
    except PolicyBlocked as blocked:
        print(f"boxed: {blocked}", file=sys.stderr)
        for reason in blocked.decision.reasons:
            print(f"reason: {reason}", file=sys.stderr)
        for warning in blocked.decision.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        return EXIT_POLICY
    except ChannelError as e:
        print(f"boxed: {e}", file=sys.stderr)
        return EXIT_FAIL
    print(f"scope: {scope}", file=sys.stderr)
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not result.complete:
        print("warning: the answer was cut off: the provider stopped it before the end", file=sys.stderr)
    anomalies = result.unknown + result.suspicious
    if anomalies:  # the text stays as it is: a placeholder that was not restored shows no original, and the answer was paid for
        print(_shown("not restored, check by hand: " + ", ".join(anomalies), sys.stderr), file=sys.stderr)
    sys.stdout.write(_shown(result.text, sys.stdout))
    return EXIT_ANOMALY if anomalies else EXIT_OK


def _read_key(provider: str) -> str:
    """The key from a hidden prompt on a terminal, else the first line of stdin (a pipe or a file). It is never echoed, and a
    byte that is not text reads as a character the key check refuses, so no error quotes a piece of it."""
    if sys.stdin.isatty():
        return getpass.getpass(f"API key for {provider} (input hidden): ")
    stream = getattr(sys.stdin, "buffer", None)
    return stream.readline(4096).decode("utf-8", "replace") if stream else sys.stdin.readline(4096)


def cmd_key(args: argparse.Namespace) -> int:
    from .channels import PROVIDERS, delete_api_key, key_source, set_api_key

    if args.action == "status":
        source = key_source(args.provider)
        print(f"set ({source})" if source else "not set")
        return EXIT_OK
    if args.action == "set":
        set_api_key(args.provider, _read_key(args.provider))
        print(f"key for {args.provider} stored in the keychain")
        return EXIT_OK
    stored = key_source(args.provider) == "keychain"
    delete_api_key(args.provider)
    print(f"key for {args.provider} removed from the keychain" if stored else f"no key for {args.provider} in the keychain")
    if key_source(args.provider) == "environment":  # the person's own variable: named, never read out, never touched
        print(f"note: {PROVIDERS[args.provider].env_key} is still set in the environment")
    return EXIT_OK


def _checks_damaged(error: Exception) -> int:
    """The CheckError's own fixed text: "damaged", or "need to be confirmed again" for a missing or wrong signature."""
    print(
        f"boxed: error: {error}, so every account counts as personal-training until you run boxed check reset "
        "(it moves the file aside; nothing is deleted)",
        file=sys.stderr,
    )
    return EXIT_ERROR


def _check_list(home: Path) -> int:
    from .checks import NOTE, SETTINGS, CheckError, account_kind, due, load_checks
    from .dashboard import CHECKS_FAIL_SAFE

    try:
        checks = load_checks(home)
    except CheckError as e:
        return _checks_damaged(e)
    overdue = {(c.provider, c.account) for c in due(checks, datetime.now(UTC).date())}
    if not checks:
        print("no checks recorded yet: boxed check set --provider P --account A --training on|off|unknown --memory on|off|unknown")
    for c in checks:
        late = (c.provider, c.account) in overdue
        print(
            f"{c.provider}  {c.account}  training {c.training}  memory {c.memory}  checked {c.checked_at} ({c.source})"
            f"  recipient {account_kind(c)}" + ("  due" if late else "")
        )
        if late and SETTINGS[c.provider]:
            print(f"  check again: {SETTINGS[c.provider]}")
    print(f"\n{NOTE}\n{CHECKS_FAIL_SAFE}")
    return EXIT_DUE if overdue else EXIT_OK


def _check_set(home: Path, args: argparse.Namespace) -> int:
    from .checks import ACCOUNT_RE, Check, CheckError, save_check

    if not ACCOUNT_RE.fullmatch(args.account):
        raise UserError("--account takes a short name: letters, digits and . _ @ + - (at most 64, starting with a letter or digit)")
    check = Check(args.provider, args.account, args.training, args.memory, "asked", datetime.now(UTC).date().isoformat())
    try:
        save_check(home, check)
    except CheckError as e:
        return _checks_damaged(e)
    print(f"saved: {check.provider} {check.account} training {check.training} memory {check.memory}")
    return EXIT_OK


def _check_remove(home: Path, args: argparse.Namespace) -> int:
    from .checks import FILE_NAME, VERSION, CheckError, _load, _write  # _write: the one safe way checks.json is written; _load: the lock is held

    path = home / FILE_NAME
    with file_lock(path):  # the browser's host may save a check at the same moment
        try:
            saved = _load(home)
        except CheckError as e:
            return _checks_damaged(e)
        kept = [c for c in saved if (c.provider, c.account) != (args.provider, args.account)]
        if len(kept) == len(saved):
            print(f"boxed: no check for {args.provider} {args.account}", file=sys.stderr)
            return EXIT_FAIL
        _write(path, json.dumps({"version": VERSION, "checks": [asdict(c) for c in kept]}, indent=2) + "\n")
    print(f"removed: {args.provider} {args.account}")
    return EXIT_OK


def _check_reset(home: Path) -> int:
    from .checks import FILE_NAME, CheckError, _load

    path = home / FILE_NAME
    if not os.path.lexists(path):
        print("no checks.json: nothing to reset")
        return EXIT_OK
    aside = path.with_name(f"{FILE_NAME}.damaged-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
    with file_lock(path):
        try:
            _load(home)
        except CheckError:
            pass
        else:
            raise UserError("checks.json is readable: nothing to reset (boxed check remove deletes one check)")
        if os.path.lexists(aside):
            raise UserError("a checks.json moved aside in this second exists already: wait a second and run boxed check reset again")
        os.rename(path, aside)  # a file, a folder or a link: whatever stands there is kept, under its new name
    print(f"damaged checks.json moved to {aside}\nrecord the settings again with boxed check set")
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    home = boxed_home()
    if args.action == "list":
        return _check_list(home)
    if args.action == "set":
        return _check_set(home, args)
    if args.action == "remove":
        return _check_remove(home, args)
    return _check_reset(home)


def cmd_policy(args: argparse.Namespace) -> int:
    from .policy import Policy, Recipient, categories_for, decide

    config = load_config(Path.cwd())
    parts = args.recipient.split(":")
    if len(parts) != 3:
        raise UserError("--recipient takes provider:kind:jurisdiction, for example openai:personal-private:US")
    found = detect(_read_input(args.file), level=max(KINDS_BY_LEVEL), config=to_detect_config(config))
    categories = categories_for({d.kind for d in found}, dictionary_kinds(config)) | set(args.category or ())
    decision = decide(categories, Recipient(*parts), Policy.from_config(config.policy))
    level = f" (level {decision.min_level} or higher)" if decision.verdict == "masked" else ""
    print(f"verdict: {decision.verdict}{level}")
    print("categories: " + (", ".join(sorted(categories)) or "none found"))
    for reason in decision.reasons:
        print(f"reason: {reason}")
    for warning in decision.warnings:
        print(f"warning: {warning}")
    return EXIT_POLICY if decision.verdict in ("deny", "local-only") else EXIT_OK


def _json_safe(markers: MarkerMap) -> MarkerMap:
    """The same placeholders with JSON-escaped originals, for restoring inside a JSON plan."""
    items = [[m, kind, json.dumps(original, ensure_ascii=False)[1:-1]] for m, kind, original in markers.items()]
    return MarkerMap.from_json(json.dumps({"version": 1, "items": items}))


def _is_chart(head: bytes) -> bool:
    """Do the first bytes of a file belong to a chart spec that plan run wrote: an object that starts with its kind and the x axis?"""
    return head.startswith((b'{"kind": "bar", "x": ', b'{"kind": "line", "x": ', b'{"kind": "pie", "x": '))


def cmd_plan(args: argparse.Namespace) -> int:
    from .opplan import guess_decimal, infer_schema, normalize_rows, parse_plan, plan_columns, plan_prompt, run_plan

    config = load_config(Path.cwd())
    result_file = Target(args.out, kind="result table", replace=args.replace) if args.action == "run" and args.out else None
    chart_file = Target(args.chart, kind="chart file", own=_is_chart, replace=args.replace) if args.action == "run" and args.chart else None
    header, rows, delimiter = _read_table(args.table)
    decimal = guess_decimal(rows) if args.decimal == "auto" else args.decimal  # a table over the cell limit is refused here
    if args.action == "prompt":
        rows = normalize_rows(rows, decimal)  # the model is told the type of every column
    ctx = Context()
    if args.action == "prompt":
        scope = args.scope or "plan-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        detect_config, counts, names = to_detect_config(config), Counter(), []
        with ctx.vault.transaction(scope) as markers:  # the task and the column names go out masked too
            task, found = mask_text(args.task, markers, level=config.level, config=detect_config)
            counts.update(found)
            for name in header:
                masked, found = mask_text(name, markers, level=config.level, config=detect_config)
                names.append(masked)
                counts.update(found)
        prompt = plan_prompt(task, infer_schema(names, rows), header_confirmed=args.header_ok)
        _journal_plan(ctx, scope, "prepared", dict(counts), prompt, "level 4: task and schema only")
        sys.stdout.write(prompt + "\n")
        print(f"scope: {scope}; decimal: {decimal}", file=sys.stderr)
        return EXIT_OK
    if args.scope not in ctx.vault.scopes():
        raise UserError(UNKNOWN_SCOPE)
    text = _read_input(args.plan)
    restored = restore(text, _json_safe(ctx.vault.load_map(args.scope)), dictionary_kinds(config))
    anomalies = restored.unknown + restored.suspicious
    if anomalies:
        print("plan not run, check these placeholders: " + ", ".join(anomalies), file=sys.stderr)
        return EXIT_ANOMALY
    rows = normalize_rows(rows, decimal, columns=plan_columns(restored.text, header))  # only the columns the plan reads
    result = run_plan(parse_plan(restored.text, infer_schema(header, rows)), header, rows)
    out = io.StringIO()
    writer = csv.writer(out, delimiter=delimiter, lineterminator="\n")
    writer.writerow(result.header)
    writer.writerows(result.rows)
    _journal_plan(ctx, args.scope, "received", {}, text, f"level 4 plan run, {len(result.rows)} rows")  # before any data goes out
    if result.chart and chart_file:
        chart_file.write(json.dumps(result.chart, ensure_ascii=False).encode("utf-8"))
    if result_file:
        result_file.write(out.getvalue().encode("utf-8"))
    else:
        sys.stdout.write(out.getvalue())
    return EXIT_OK


def _journal_plan(ctx: "Context", scope: str, status: str, counts: dict[str, int], payload: str, coverage: str) -> None:
    ctx.journal.append(
        JournalEntry(
            channel="manual",
            provider="unknown",
            account_type="unknown",
            level=4,
            markers_by_kind=counts,
            status=status,
            payload_sha256=_sha256(payload),
            coverage=coverage,
            scope=scope,
            versions={"boxed": __version__},
        )
    )


def cmd_mask_file(args: argparse.Namespace) -> int:
    from .formats import mask_file

    config = load_config(Path.cwd())
    level = config.level if args.level is None else args.level
    _refuse_plan_level(level)
    scope = args.scope or "file-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    src, dest = Path(args.src), Path(args.dest)
    if dest.exists() and os.path.samefile(src, dest):  # also a link to it, or another spelling on a file system that ignores case
        raise UserError("the output would replace the source file")
    target = Target(args.dest, kind="masked file", replace=args.replace)  # before anything is created
    ctx = Context()
    with target.stage() as part:  # the map is saved only when the clean copy was written; the copy lands after the map and the journal
        with ctx.vault.transaction(scope) as markers:
            report = mask_file(src, part, markers, level=level, config=to_detect_config(config), delimiter=DELIMITERS.get(args.delimiter))
        _journal_file(ctx, scope, "prepared", level, report, part.read_bytes())  # the hash of the copy made here
        target.publish(part)
    _print_report(report, report.output)
    print(f"scope: {scope}", file=sys.stderr)
    return EXIT_OK


def cmd_restore_file(args: argparse.Namespace) -> int:
    from .formats import restore_file

    config = load_config(Path.cwd())
    ctx = Context()
    if args.scope not in ctx.vault.scopes():
        raise UserError(UNKNOWN_SCOPE)
    src, dest = Path(args.src), Path(args.dest)
    if dest.exists() and os.path.samefile(src, dest):
        raise UserError("the output is the input file: choose another output name")
    target = Target(args.dest, kind="restored file", replace=args.replace)
    with target.stage() as part:  # nothing reaches dest unless the restore is exact or forced
        report, anomalies = restore_file(
            src, part, ctx.vault.load_map(args.scope), kinds=dictionary_kinds(config), delimiter=DELIMITERS.get(args.delimiter)
        )
        if anomalies:
            print("not restored, check by hand: " + ", ".join(anomalies), file=sys.stderr)
            if not args.force:
                return EXIT_ANOMALY
        _journal_file(ctx, args.scope, "received", -1, report, part.read_bytes())  # before the originals land
        target.publish(part)
    _print_report(report, dest.name)
    return EXIT_OK


def _check_rows(home: Path, today) -> list[dict] | None:
    """The saved checks as the dashboard shows them: the fields of a check, its settings page and whether it is due. None
    when the file cannot be read, which is not the same as "none recorded"."""
    from .checks import SETTINGS, CheckError, due, load_checks

    try:
        saved = load_checks(home)
    except CheckError:
        return None
    overdue = {(c.provider, c.account) for c in due(saved, today)}
    return [asdict(c) | {"due": (c.provider, c.account) in overdue, "settings_url": SETTINGS[c.provider]} for c in saved]


def cmd_dashboard(args: argparse.Namespace) -> int:
    from .dashboard import is_report, journal_rows, period_bounds, render_html, summarize, to_csv
    from .observe import observed_journal
    from .policy import Policy

    if not (args.html or args.csv):
        raise UserError("give --html FILE, --csv FILE or both")
    if args.html and args.csv and Path(args.html).expanduser().resolve() == Path(args.csv).expanduser().resolve():
        raise UserError("--html and --csv name the same file")  # also when one of them is a link to the other
    html_out = Target(args.html, kind="report", own=is_report, reports=True) if args.html else None
    csv_out = Target(args.csv, kind="report", own=is_report, reports=True) if args.csv else None  # both are checked before either is written
    today = datetime.now(UTC).date()
    if args.period:
        if args.since or args.until:
            raise UserError("--period names the days itself: use it or --since and --until, not both")
        since, until = period_bounds(args.period, today)
    else:
        since, until = args.since, args.until
    ctx = Context()
    records, damaged = ctx.journal.read()
    if damaged:  # the page says so itself, a csv cannot
        print(f"{damaged} damaged line{'s' if damaged > 1 else ''} skipped, run boxed journal verify", file=sys.stderr)
    if html_out is not None:
        observed = observed_journal(ctx.home, ctx.keys)  # the browser's log: a chain of its own, never mixed into the journal
        seen, seen_damaged = observed.read()
        page = render_html(
            summarize(records, since, until), ctx.journal.verify(), damaged,
            rows=journal_rows(records, since, until),
            observed=seen, observed_verify=observed.verify(), observed_damaged=seen_damaged,
            checks=_check_rows(ctx.home, today),
            policy=Policy.from_config(load_config(Path.cwd()).policy),
        )
        html_out.write(page.encode("utf-8"))
        print(f"dashboard: {args.html}")
    if csv_out is not None:  # a byte order mark first so Excel reads UTF-8; the rows keep the CRLF the csv module wrote
        csv_out.write(b"\xef\xbb\xbf" + to_csv(records, since, until).encode("utf-8"))
        print(f"csv: {args.csv}")
    return EXIT_OK


def _is_export(head: bytes) -> bool:
    """Do the first bytes of a file belong to a journal export that boxed wrote: an object that starts with the format's name?"""
    from .dashboard import EXPORT_FORMAT

    return head.startswith(b"{") and f'"format": "{EXPORT_FORMAT}"'.encode() in head


def cmd_journal(args: argparse.Namespace) -> int:
    from .dashboard import export_for_security, verify_export

    if args.action == "check-export":  # the security team's side: no key store, only the file
        if not args.file:
            raise UserError("check-export needs the export file")
        report = verify_export(json.loads(Path(args.file).read_text(encoding="utf-8")))
        print(f"{'ok' if report.ok else 'BROKEN'}: {report.count} records verified; {report.reason}")
        return EXIT_OK if report.ok else EXIT_FAIL
    ctx = Context()
    if args.action == "key":
        print(ctx.journal.public_key_hex())
        return EXIT_OK
    if args.action == "export":
        if not args.out:
            raise UserError("export needs --out FILE")
        out = Target(args.out, kind="journal export", own=_is_export, replace=args.replace)
        export = export_for_security(ctx.journal, args.since, args.until)
        out.write((json.dumps(export, ensure_ascii=False, indent=1) + "\n").encode("utf-8"))
        print(f"{len(export['entries'])} records exported to {args.out}; device key {export['public_key']}")
        return EXIT_OK
    if args.action == "verify":
        report = ctx.journal.verify()
        print(f"{'ok' if report.ok else 'BROKEN'}: {report.count} records verified; {report.reason}")
        return EXIT_OK if report.ok else EXIT_FAIL
    records, damaged = ctx.journal.read()
    for rec in records[-args.last :]:
        print(json.dumps(rec, ensure_ascii=False))
    if damaged:
        print(f"{damaged} damaged line{'s' if damaged > 1 else ''} skipped, run boxed journal verify", file=sys.stderr)
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    import secrets
    from collections import Counter

    from .audit import report
    from .audit.paths import mount_table, show_path
    from .audit.sources import claude_settings_files, iter_claude_code, iter_claude_settings, iter_codex
    from .keys import KEYCHAIN_MISSING, KeychainTimeout

    html_out = Target(args.html, kind="audit report", own=report.is_audit_report, reports=True) if args.html else None  # before the scan
    stats: Counter = Counter()
    projects: set[str] = set()  # every folder a transcript names, read before --since leaves anything out
    mounts = mount_table()  # read once; None: no folder is known to be on a local disk, and audit reads none
    claude_dir = Path(args.claude_dir).expanduser()
    codex_dir = Path(args.codex_dir).expanduser()
    # a missing folder is skipped without a word by the readers; one that is there and cannot be listed is counted as not checked
    items = [iter_claude_code(claude_dir, stats, projects, mounts), iter_codex(codex_dir, stats, projects, mounts)]
    since = args.since
    try:
        key = default_keystore().get_or_create("audit-mac-key", 32)
    except (AssertionError, KeychainTimeout):
        raise
    except Exception as e:  # one random key for the whole run: the transcripts and the settings files share it
        key = secrets.token_bytes(32)
        damaged = isinstance(e, ValueError) and str(e) != KEYCHAIN_MISSING  # a stored key that is no key of 32 bytes
        why = "the audit key in the keychain cannot be used" if damaged else "no keychain"
        print(f"boxed: {why}: prefixes are random for this run", file=sys.stderr)
    summary = report.run_audit((i for source in items for i in source), level=args.level, since=since, stats=stats, key=key)
    # the settings of Claude Code: the user's next to the transcripts (~/.claude), and those of every project the transcripts named
    user_dir = claude_dir.parent if claude_dir.name == "projects" else None
    settings = iter_claude_settings(claude_settings_files(user_dir, summary.projects | projects, stats, mounts), stats, mounts)
    summary = report.run_audit(settings, level=args.level, stats=stats, key=key, summary=summary)
    if html_out is not None:
        html_out.write(report.render_html(summary).encode("utf-8"))
    sys.stdout.write(report.render_terminal(summary))
    if args.html:
        print(f"report: {show_path(str(args.html))}")
    return EXIT_ANOMALY if summary.incomplete else EXIT_OK  # something was there and not checked: the report is incomplete


def cmd_workspace(args: argparse.Namespace) -> int:
    from .workspace import NOT_MARKER_PROBLEMS, create_workspace, drop_workspace, list_workspaces, project_folder, sync_back

    if args.action != "list" and not args.target:  # "" would be the current folder
        raise UserError(NEEDS_TARGET[args.action])
    if args.dry_run and args.action != "sync":  # create and drop have no dry run: refused before anything is made or deleted
        raise UserError("--dry-run works with sync only")
    if args.action == "create":  # the folder and the level are settled before the data folder, the vault or a key is touched
        original = project_folder(Path(args.target).expanduser())
        config = load_config(original)
        level = config.level if args.level is None else args.level
        _refuse_plan_level(level)
    ctx = Context()
    if args.action == "create":
        report = create_workspace(original, level=level, config=config, vault=ctx.vault, journal=ctx.journal, home=ctx.home)
        ws = report.workspace
        print(f"workspace {ws.id} created: {report.copied} files masked, {len(report.skipped)} skipped, level {level}")
        print(f"mirror: {ws.mirror}")
        for rel, reason in report.skipped:
            print(f"  skipped {rel} ({reason})")
        return EXIT_OK
    if args.action == "sync":
        r = sync_back(args.target, vault=ctx.vault, journal=ctx.journal, home=ctx.home, force=args.force, delete=args.delete, dry_run=args.dry_run, only=set(args.only) if args.only else None, diff=args.diff)
        prefix = "would " if args.dry_run else ""
        for label, paths in (("write", r.written), ("create", r.created), ("delete", r.deleted)):
            for rel in paths:
                print(f"{prefix}{label} {rel}")
        for rel in r.conflicts:
            print(f"conflict {rel}: the original changed since the mirror was made", file=sys.stderr)
        for rel, res in r.refused:
            markers = res.unknown or any(s not in NOT_MARKER_PROBLEMS for s in res.suspicious)
            hint = " (use --force after checking)" if markers else ""
            print(f"refused {rel}: {', '.join(res.unknown + res.suspicious)}{hint}", file=sys.stderr)
        for rel, why in r.failed:
            print(f"failed {rel}: {why}", file=sys.stderr)
        for rel in r.unreadable:
            print(f"unreadable {rel}: boxed cannot look into this folder of the mirror, so nothing in it was synced", file=sys.stderr)
        for rel in r.unmatched:
            print(f"not in the mirror: {rel}", file=sys.stderr)
        for rel in r.missing:
            print(f"kept {rel}: deleted in the mirror, add --delete to delete the original", file=sys.stderr)
        for text in r.diffs.values():
            sys.stdout.write(text)
        return EXIT_ANOMALY if (r.conflicts or r.refused or r.unmatched or r.failed or r.unreadable) else EXIT_OK
    if args.action == "list":
        for ws in list_workspaces(ctx.home):
            print(f"{ws.id}  level {ws.level}  {ws.created_at}  {ws.original} -> {ws.mirror}")
        return EXIT_OK
    drop_workspace(args.target, vault=ctx.vault, home=ctx.home)
    print(f"workspace {args.target} dropped")
    return EXIT_OK


def _log_hook_error(home: Path, event: str, error: Exception) -> None:
    """One line in hook-errors.log: the time, the event and the class of the error, never its message, which may quote a path, a
    setting or a value the hook was given (as native_host._log_failure does). The log is opened as the journal is: for appending,
    without following a link and without waiting on a pipe, mode 600 from the first byte, and written only if it is a plain file
    with no other name. A link, a hard link (a second
    name of another file would be that file), a pipe, a folder or a file that cannot be written gets nothing, and the hook goes on
    as it would have: a log that fails must neither write somewhere else nor change what the hook answers."""
    line = f"{datetime.now(UTC).isoformat()} {event}: {type(error).__name__}: {HOOK_LOG_NOTE}\n"
    try:
        fd = open_nofollow(home / "hook-errors.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    except OSError:
        return
    try:
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            make_private(fd)  # a log an older version left readable
            os.write(fd, line.encode("utf-8", "replace"))  # a name with a byte that is not UTF-8 must not stop the log
    except OSError:
        pass
    finally:
        os.close(fd)


def _hook_input() -> object:
    """The JSON the hook was given, or None for input that cannot be read: not UTF-8, not JSON."""
    try:
        return json.loads(_read_input("-"))
    except (OSError, ValueError, RecursionError):
        return None


def cmd_hook(args: argparse.Namespace) -> int:
    """Claude Code hook entry point. Inside a mirror any failure blocks (exit 2, one fixed line); outside one the hook never blocks
    and says nothing. A hook that cannot tell where it is counts as inside: a failure there must not let a call through. That
    includes a data folder it cannot open, which is what a hook meets under `boxed run`."""
    from .hooks import HOOK_FAILED, HOOKS, find_marker, inside_workspaces

    home, in_mirror = None, True
    try:
        payload = _hook_input()
        cwd = payload.get("cwd") if isinstance(payload, dict) else None
        cwd = (Path(cwd) if isinstance(cwd, str) and cwd else Path.cwd()).resolve()
        home = boxed_home_path()  # only looked at first, so a data folder that cannot be made still says where the mirrors are
        in_mirror = find_marker(cwd) is not None or inside_workspaces(cwd, home)
        home = boxed_home()
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")  # only its class goes to hook-errors.log
        result = HOOKS[args.event](payload, home)
    except Exception as e:
        if home is not None:
            _log_hook_error(home, args.event, e)
        if not in_mirror:
            return EXIT_OK
        print(HOOK_FAILED, file=sys.stderr)
        return EXIT_ERROR
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.exit_code


def cmd_mcp(args: argparse.Namespace) -> int:
    from .hooks import find_workspace
    from .mcp_server import ServerContext, build_server
    from .workspace import load_workspace_config

    home = boxed_home_path()  # only looked at: a refusal must leave the data folder as it is
    ws = find_workspace(Path.cwd(), home)
    config = load_workspace_config(ws.id, home) if ws else load_config(Path.cwd())
    if ws:
        config.level = ws.level
    _refuse_plan_level(config.level)  # the server masks at this level and journals it
    ctx = Context()
    scope = ws.scope if ws else "mcp-" + datetime.now(UTC).strftime("%Y%m%d")
    build_server(ServerContext(ctx.home, config, ctx.vault, ctx.journal, scope)).run("stdio")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from .serve import main as serve_main

    return serve_main()


def cmd_install(args: argparse.Namespace) -> int:
    from .install import extension_dir, install_claude, install_codex, install_native_host, refuse_native_host_here, remove_native_host

    if args.remove and args.target != "native-host":
        raise UserError("--remove works with native-host only")
    if args.target in ("claude", "codex"):
        refuse_on_windows(f"install {args.target}")  # the plugin commands and the Codex config are made for macOS for now
    if args.target == "native-host":
        refuse_native_host_here()  # before the hint about --extension-id: no id helps on Linux
        if args.remove:
            removed = remove_native_host(dry_run=args.dry_run)
            for path in removed:
                print(("would remove: " if args.dry_run else "removed: ") + str(path))
            if not removed:
                print("the native host is not installed")
            return EXIT_OK
        if not args.extension_id:
            print(f"extension folder to load unpacked: {extension_dir()}", file=sys.stderr)  # where boxed is installed, said apart from the error
            raise UserError("native-host needs --extension-id: load the extension folder above unpacked in the browser, then copy its id")
        for path in install_native_host(args.extension_id, dry_run=args.dry_run):
            print(("would write: " if args.dry_run else "wrote: ") + str(path))
        print(f"extension folder to load unpacked: {extension_dir()}")
        return EXIT_OK
    if args.target == "claude":
        from .install import marketplace_dir

        for command in install_claude(marketplace_dir(), dry_run=args.dry_run):
            print(("would run: " if args.dry_run else "ran: ") + command)
        return EXIT_OK
    config = Path("~/.codex/config.toml").expanduser()
    verb = "would add" if args.dry_run else "added"
    print(f"{verb} boxed MCP server to {config}" if install_codex(config, dry_run=args.dry_run) else f"boxed is already in {config}")
    return EXIT_OK


def cmd_native_host(args: argparse.Namespace) -> int:
    from .native_host import main as serve_browser

    return serve_browser()


def cmd_run(args: argparse.Namespace) -> int:
    from .run import run_agent

    extra, keep = list(args.args), list(args.keep_env or [])
    while extra and (extra[0] == "--keep-env" or extra[0].startswith("--keep-env=")):  # also after the agent's name, before --
        if extra[0] == "--keep-env":
            if len(extra) < 2:
                raise UserError("--keep-env needs the name of a variable")
            keep.append(extra[1])
            extra = extra[2:]
        else:
            keep.append(extra[0].partition("=")[2])
            extra = extra[1:]
    extra = extra[1:] if extra[:1] == ["--"] else extra
    if args.agent == "codex":
        print("boxed: Codex runs with its own sandbox off; the macOS sandbox from boxed is the outer guard", file=sys.stderr)
    return run_agent(args.agent, extra, cwd=Path.cwd(), home=boxed_home(), keep_env=keep)


ARGUMENT_ERROR = re.compile(r"argument (?P<name>.+?): (?P<reason>.*)", re.S)
REQUIRED = "the following arguments are required: "
UNRECOGNIZED = "unrecognized arguments: boxed COMMAND --help lists the known ones"


def _action_name(action: argparse.Action) -> str | None:
    """The name argparse gives an argument in its errors."""
    if action.option_strings:
        return "/".join(action.option_strings)
    if action.metavar not in (None, argparse.SUPPRESS):
        return action.metavar if isinstance(action.metavar, str) else None
    if action.dest not in (None, argparse.SUPPRESS):
        return action.dest
    return None


def _why(action: argparse.Action, reason: str) -> str:
    """A fixed reason for what argparse said of a known argument. Its own words quote the value."""
    if reason == DATE_FORMAT:  # the words of _day_argument
        return reason
    if "invalid choice" in reason and action.choices is not None:
        return "not one of " + ", ".join(str(choice) for choice in action.choices)
    if "invalid int value" in reason:
        return "not a whole number"
    if reason.startswith("expected one argument"):
        return "needs a value"
    if reason.startswith("expected"):
        return "has the wrong number of values"
    if reason.startswith("ignored explicit argument"):
        return "takes no value"
    if reason.startswith("not allowed with argument"):
        return "cannot go with another argument that was given"
    return "not accepted"


def _argument_error(parser: argparse.ArgumentParser, message: str) -> str:
    """argparse's error in fixed words: the name of a known argument of this parser and a fixed reason, never what was typed."""
    actions = {name: action for action in parser._actions if (name := _action_name(action))}
    if found := ARGUMENT_ERROR.fullmatch(message):
        action = actions.get(found.group("name"))
        if action is None:
            return f"an argument is not accepted: {parser.prog} --help lists the known ones"
        return f"argument {found.group('name')}: {_why(action, found.group('reason'))}"
    if message.startswith("unrecognized arguments"):
        return UNRECOGNIZED
    if message.startswith(REQUIRED):
        names = message.removeprefix(REQUIRED).split(", ")
        if all(name in actions for name in names):
            return REQUIRED + ", ".join(names)
        return REQUIRED.removesuffix(": ") + f": {parser.prog} --help lists them"
    if message.startswith("ambiguous option"):
        return "a shortened option fits more than one: write it in full"
    return f"the arguments cannot be read: {parser.prog} --help lists them"


class _Parser(argparse.ArgumentParser):
    """argparse, whose own errors quote the value of a wrong argument and an unknown argument as typed: here they name a known
    argument and a fixed reason. The parsers of the commands are of this class too (add_subparsers takes the class of its parent)."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {_argument_error(self, message)}\n")


def build_parser() -> argparse.ArgumentParser:
    from .channels import PROVIDERS
    from .checks import SETTINGS, STATES
    from .dashboard import PERIOD_DAYS
    from .policy import RECIPIENT_KINDS

    parser = _Parser(prog="boxed", description="Mask secrets and personal data before they reach AI models.")
    parser.add_argument("--version", action="version", version=f"boxed {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("mask", help="mask a file or stdin, print the masked text")
    p.add_argument("--level", type=int, choices=range(5))
    p.add_argument("--scope")
    p.add_argument("file", nargs="?", default="-")
    p.set_defaults(func=cmd_mask)

    p = sub.add_parser("restore", help="put the originals back into a model answer")
    p.add_argument("--scope", required=True)
    p.add_argument("--force", action="store_true", help="print the text even if some markers look wrong")
    p.add_argument("file", nargs="?", default="-")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("ask", help="send a masked prompt through your API key and print the restored answer")
    p.add_argument("--provider", required=True, choices=list(PROVIDERS))
    p.add_argument("--model", required=True)
    p.add_argument("--account", choices=[kind for kind in RECIPIENT_KINDS if kind != "local"], help="the kind of account the key belongs to")
    p.add_argument("--scope")
    p.add_argument("--level", type=int, choices=range(5))
    p.add_argument("--category", action="append", choices=NAMED_CATEGORIES, help="the text holds this kind of data (repeatable)")
    p.add_argument("file", nargs="?", default="-")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("key", help="store, remove or check the API key of a provider (kept in the OS keychain)")
    p.add_argument("action", choices=["set", "remove", "status"])
    p.add_argument("provider", choices=list(PROVIDERS))
    p.set_defaults(func=cmd_key)

    p = sub.add_parser("check", help="what you know about training on chats, per account: list, set, remove, reset")
    check_sub = p.add_subparsers(dest="action", required=True)
    pc = check_sub.add_parser("list", help="show the checks; exit code 5 when one is due")
    pc.set_defaults(func=cmd_check)
    pc = check_sub.add_parser("set", help="write down what the data controls of an account say")
    pc.add_argument("--provider", required=True, choices=list(SETTINGS))
    pc.add_argument("--account", required=True)
    pc.add_argument("--training", required=True, choices=STATES, help="is training on your chats on, off or unknown")
    pc.add_argument("--memory", required=True, choices=STATES, help="is the chat's memory on, off or unknown")
    pc.set_defaults(func=cmd_check)
    pc = check_sub.add_parser("remove", help="delete the check of one account")
    pc.add_argument("--provider", required=True, choices=list(SETTINGS))
    pc.add_argument("--account", required=True)
    pc.set_defaults(func=cmd_check)
    pc = check_sub.add_parser("reset", help="move a damaged checks.json aside (it is kept, not deleted)")
    pc.set_defaults(func=cmd_check)

    p = sub.add_parser("journal", help="verify, show or export the signed journal; print the device key")
    p.add_argument("action", choices=["verify", "show", "export", "key", "check-export"])
    p.add_argument("file", nargs="?", help="check-export: the export file to check")
    p.add_argument("--last", type=int, default=20)
    p.add_argument("--out", help="export: where to write the export")
    p.add_argument("--since", type=_day_argument, help="export: first day, YYYY-MM-DD (UTC)")
    p.add_argument("--until", type=_day_argument, help="export: last day, YYYY-MM-DD (UTC)")
    p.add_argument("--replace", action="store_true", help="export: replace a file that is not an earlier export")
    p.set_defaults(func=cmd_journal)

    p = sub.add_parser("mask-file", help="write a masked clean copy of a CSV, XLSX, DOCX or PDF (PDF to .txt)")
    p.add_argument("--level", type=int, choices=range(0, 5))
    p.add_argument("--scope")
    p.add_argument("--replace", action="store_true", help="replace a file that is already there")
    p.add_argument("--delimiter", choices=list(DELIMITERS), help="the delimiter of a CSV file, when boxed cannot tell it for sure")
    p.add_argument("src")
    p.add_argument("dest")
    p.set_defaults(func=cmd_mask_file)

    p = sub.add_parser("restore-file", help="put the originals back into a masked file a model returned")
    p.add_argument("--scope", required=True)
    p.add_argument("--force", action="store_true", help="write the file even with unknown or suspicious markers")
    p.add_argument("--replace", action="store_true", help="replace a file that is already there")
    p.add_argument("--delimiter", choices=list(DELIMITERS), help="the delimiter of a CSV file, when boxed cannot tell it for sure")
    p.add_argument("src")
    p.add_argument("dest")
    p.set_defaults(func=cmd_restore_file)

    p = sub.add_parser("dashboard", help="write a self-contained HTML overview of the journal, and a CSV of its records")
    p.add_argument("--html", help="the overview page")
    p.add_argument("--csv", help="the records of the period, for a spreadsheet")
    p.add_argument("--period", choices=list(PERIOD_DAYS), help="the last day, 7 days or 30 days up to today (UTC)")
    p.add_argument("--since", type=_day_argument, help="first day, YYYY-MM-DD (UTC)")
    p.add_argument("--until", type=_day_argument, help="last day, YYYY-MM-DD (UTC)")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("audit", help="count secrets and personal data in the local session records and settings files of Claude Code and Codex")
    p.add_argument("--since", type=_day_argument, help="YYYY-MM-DD")
    p.add_argument("--claude-dir", default="~/.claude/projects")
    p.add_argument("--codex-dir", default="~/.codex/sessions")
    p.add_argument("--html", help="also write a self-contained HTML report here")
    p.add_argument("--level", type=int, choices=range(5), default=2)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("workspace", help="masked project mirror for AI agents: create, sync back, list, drop")
    p.add_argument("action", choices=["create", "sync", "list", "drop"])
    p.add_argument("target", nargs="?", help="project path for create, workspace id for sync and drop")
    p.add_argument("--level", type=int, choices=range(5))
    p.add_argument("--force", action="store_true", help="sync files even with unknown or suspicious markers; with --only, just those files")
    p.add_argument("--only", action="append", metavar="PATH", help="sync only this mirror path (repeatable)")
    p.add_argument("--diff", action="store_true", help="print a unified diff of every change sync makes or would make")
    p.add_argument("--delete", action="store_true", help="delete originals of files deleted in the mirror")
    p.add_argument("--dry-run", action="store_true", help="sync only: print what would change, change nothing")
    p.set_defaults(func=cmd_workspace)

    p = sub.add_parser("policy", help="check what the company policy allows for a text and a recipient")
    p.add_argument("action", choices=["check"])
    p.add_argument("--recipient", required=True, help="provider:kind:jurisdiction, for example openai:personal-private:US")
    p.add_argument("--category", action="append", choices=NAMED_CATEGORIES, help="the text holds this kind of data (repeatable)")
    p.add_argument("file", nargs="?", default="-")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("plan", help="level 4: send only the task and the table schema, run the returned plan locally")
    plan_sub = p.add_subparsers(dest="action", required=True)
    pp = plan_sub.add_parser("prompt", help="print the prompt: masked task, column names and types, made-up rows")
    pp.add_argument("--task", required=True)
    pp.add_argument("--scope")
    pp.add_argument("--decimal", choices=["auto", ".", ","], default="auto")
    pp.add_argument("--header-ok", action="store_true", help="the first row is a header even though it looks like data")
    pp.add_argument("table")
    pp.set_defaults(func=cmd_plan)
    pr = plan_sub.add_parser("run", help="run the model's plan locally on the real table")
    pr.add_argument("--scope", required=True)
    pr.add_argument("--decimal", choices=["auto", ".", ","], default="auto")
    pr.add_argument("--out", help="write the result table here instead of stdout")
    pr.add_argument("--replace", action="store_true", help="replace a --out file that is already there, or a --chart file that is not a chart")
    pr.add_argument("--chart", help="write the chart spec (JSON) here")
    pr.add_argument("plan")
    pr.add_argument("table")
    pr.set_defaults(func=cmd_plan)

    p = sub.add_parser("hook", help="Claude Code hook entry point, reads the hook JSON from stdin")
    p.add_argument("event", choices=["pre-tool-use", "user-prompt-submit", "session-start", "skills-check"])
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("mcp", help="run the stdio MCP server with masked read and search")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("serve", help="run the core for the desktop program: framed JSON on stdin and stdout, until stdin closes")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("install", help="add boxed to Claude Code (plugin), Codex (MCP server) or the browser (native host)")
    p.add_argument("target", choices=["claude", "codex", "native-host"])
    p.add_argument("--extension-id", help="native-host: the id Chrome or Edge shows for the unpacked extension")
    p.add_argument("--remove", action="store_true", help="native-host: take the registration and its files away")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("native-host", help="the browser starts this: serve the side panel on stdin and stdout")
    p.set_defaults(func=cmd_native_host)

    p = sub.add_parser("run", help="start Claude Code or Codex in the current workspace under the macOS sandbox")
    p.add_argument(
        "--keep-env", action="append", metavar="NAME",
        help="pass this variable to the agent although it looks like a credential (repeatable); credentials are kept out by default",
    )
    p.add_argument("agent", choices=["claude", "codex"])
    p.add_argument("args", nargs=argparse.REMAINDER, help="arguments for the agent, after --")
    p.set_defaults(func=cmd_run)

    from .skills.command import register

    register(sub)
    return parser


TOML_AT = re.compile(r"\(at (line \d+, column \d+|end of document)\)\Z")  # the place tomllib names; its words may quote a key


def _error_text(error: Exception) -> str:
    """What the last line says of an error: the message of a UserError (fixed words, tests/test_error_texts.py); for the vault and
    the journal their own fixed words; the place a TOML or JSON parser names; the system's words for the number of a file error,
    without the path; else the class of the error and fixed words. Python and the libraries quote what they were given (int() its
    text, a codec the byte, tomllib a key), and so may an error that boxed raises without UserError: none of those texts is shown."""
    import tomllib

    from .journal import NOT_PLAIN, JournalError
    from .locks import NOT_PLAIN as LOCK_NOT_PLAIN
    from .vault import VaultError

    if isinstance(error, VaultError):  # its message names the scope
        return VAULT_UNREADABLE
    if isinstance(error, JournalError):
        return NOT_PLAIN
    if isinstance(error, UserError):  # ChannelError too: the provider's name and words of a fixed list (channels._fail)
        return str(error)
    if isinstance(error, tomllib.TOMLDecodeError):
        at = TOML_AT.search(str(error))
        return "not valid TOML" + (f" (at {at.group(1)})" if at else "")
    if isinstance(error, json.JSONDecodeError):
        return f"not valid JSON (at line {error.lineno}, column {error.colno})"
    if isinstance(error, ImportError) and error.name:  # an extra that is not installed: the name of a module, no value
        return f"no module named {error.name}: install the extra that brings it (see install.md)"
    if isinstance(error, OSError):  # the system's words for its number; boxed's own fixed words (a link, a folder, not a plain file)
        words = error.strerror if error.strerror in (LOCK_NOT_PLAIN, *OWN_OS_WORDS) else None
        if words is None and isinstance(error.errno, int):
            words = os.strerror(error.errno)
        if words:
            return words[:1].lower() + words[1:]
    return f"{type(error).__name__}: {UNEXPECTED}"


def main(argv: list[str] | None = None) -> int:
    utf8_console()
    args = build_parser().parse_args(argv)
    try:
        if args.command in NEEDS_MACOS_OR_HOOKS:
            refuse_on_windows(args.command)  # before the data folder or a key is touched
        return args.func(args)
    except LockTimeout:  # a lock that another process holds for LOCK_TIMEOUT seconds; the words are fixed, they name no file
        print(LOCK_BUSY, file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:  # fail closed: nothing reaches stdout on any error
        print(f"boxed: error: {_error_text(e)}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
