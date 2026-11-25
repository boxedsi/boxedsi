# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow [Semantic Versioning](https://semver.org/). While the version is 0.x, anything can change between releases.

## 0.1.0 - unreleased

First public version. Alpha: no external security audit. See [SECURITY.md](SECURITY.md). Details of each part are in [docs/guide/](docs/guide/README.md).

### Fixed

- Commands that read or create a key stop after 30 seconds with a fixed message when the system keychain does not answer, including a locked macOS keychain without a desktop session.

### Added

- `boxed mask` and `boxed restore`: local masking of secrets and personal data with typed placeholders such as `[EMAIL_1]`, levels 0-3, scopes; restore never guesses.
- Optional local name models for people and companies: Russian (`ner-ru`) and multilingual (`ner-en`).
- Encrypted vault for the placeholder maps (key in the OS keychain) and a signed, hash-chained journal of kinds, counts and hashes (`boxed journal`).
- `boxed audit`: finds potential secrets and personal data in saved Claude Code and Codex session records and in Claude Code settings files, by kind, tool, role and project, with keyed hashes instead of values. Transcripts and settings are read only as plain files on a confirmed local disk; an unreadable mount table, an unknown file system or a closed folder shows under not checked.
- `boxed dashboard`: HTML and CSV reports of the journal.
- Masked workspace for Claude Code and Codex (`boxed workspace create|sync|drop`) with guard hooks.
- `boxed run`: the agent in a masked workspace under the macOS sandbox, with credential-like variables kept out of its environment.
- Claude Code plugin (skill, MCP server, session-start hook) and Codex MCP server, with `read_masked` and `search_masked` (`boxed install claude|codex`, `boxed mcp`).
- `boxed ask` and `boxed key`: a masked prompt through your own key to OpenAI, Anthropic, DeepSeek or OpenRouter, answer restored locally.
- Company policy (`boxed policy check`, `[boxed.policy]` in `boxed.toml`) with an EEA and training warning.
- `boxed skills scan|list|quarantine|restore`: static, offline check of the skills, plugins, MCP servers, hooks and settings of six agents, with an optional `--ai` second look. Agent configs (settings, MCP, hooks, Codex config, `.claude.json`, plugin manifests, in any letter case) never leave with `--ai` and are redacted in every report; the journal marks coverage `partial` when a check is incomplete; rules version 11.
- `boxed check`: your notes on whether each chat account trains on your data.
- Error output in fixed words that never quote a value, a key, a path or a scope.
- Python is pinned to 3.13.
- Windows 11 support for the core commands, the browser extension host and keys in Credential Manager.
- User guide, security documents, decision records and a detection benchmark (`bench/`).

### Experimental

These parts work but are less tested and may change or break:

- Browser side panel for Chrome and Edge: mask, insert and restore on five AI chats, observation mode, training checks.
- Desktop app (Tauri): mask and restore in a window, unsigned, macOS on Apple silicon only.
- Files and tables: `boxed mask-file` and `boxed restore-file` for CSV (`--delimiter` to name the separator), XLSX and DOCX; a PDF's text layer is masked into a `.txt` file, and that text file is restored (images and scanned pages are not covered); level 4 table plans (`boxed plan prompt|run`).

### Known limitations

- Detectors are rules: they miss unusual formats; names need a name model. Masking does not stop inference from context.
- `boxed audit` sees only the transcripts still on disk.
- Windows: `boxed run`, `workspace`, hooks, `mcp` and `install claude|codex` are refused. CI runs the whole test suite on Windows: about 100 tests of `serve` and `skills` do not pass yet, so the Windows job, core tests included, does not fail the run until they are fixed. `boxed skills` runs in CI on Windows but has not been tried on a Windows desktop.
- Linux: no sandbox for `boxed run` and no browser host (`install native-host` refuses). The test suite passes in a container; not tried on a desktop. Without a Secret Service keyring, `audit` (with a temporary key), a scan of a folder, `skills list`, `policy check` and `journal check-export` run; a scan of what is installed shows its findings but cannot save them; masking, restoring and the journal stop.
- The macOS sandbox leaves gaps listed in the threat model (clipboard, IDE and tmux sockets, `~/Library/Caches`). The MCP tools do not work inside `boxed run` yet.
