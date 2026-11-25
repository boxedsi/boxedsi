# Troubleshooting

Exit codes, the error texts you will meet, and what to do about each. The commands themselves are in [cli.md](cli.md).

## How an error looks

- Errors go to stderr. Stdout carries only the result, so a failed command in a pipe passes on nothing.
- A command that cannot do its work prints `boxed: error: <text>` and exits with code 2. A few messages, such as those of `boxed ask`, start with `boxed:` only, and some come with another exit code (the table below). The text is fixed. It never quotes your text, a value, a key, a path or a scope name, and never repeats what a provider replied. Of an error that comes from Python or a library, boxed shows only the system's words for a file error (`no such file or directory`), the line and column of a TOML or JSON error, or the name of a missing module; anything else shows the class of the error and fixed words.
- A mistake on the command line shows the usage lines of the command and `boxed <command>: error: ...`, with exit code 2. It names the argument and a fixed reason (`argument --level: not a whole number`, `argument --provider: not one of openai, anthropic, deepseek, openrouter`, `unrecognized arguments: boxed COMMAND --help lists the known ones`), never the value you typed.
- On Windows, `workspace`, hooks, `mcp`, `run` and `install claude|codex` stop with "not supported on Windows yet". `BOXED_HOME` must sit inside your user profile there, and the keychain (Credential Manager) works only in your own desktop session, not over SSH.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done |
| 1 | The work ran and failed: a call to the provider failed (also the AI check of `skills scan --ai`), there is no check to remove, a journal or an export does not verify, a `skills scan` of installed items found nothing wrong but its check could not be saved |
| 2 | Error: a wrong input, a wrong setting or the environment. Nothing was done |
| 3 | Done, and something needs a look: placeholders that were not restored, files that `workspace sync` did not write, a plan with unknown placeholders, an extension that `skills scan` found `dangerous` or `suspicious`, or something it could not check in full or could not read, an `audit` that could not check everything it found |
| 4 | The policy says the text must not go to that recipient |
| 5 | A training check is due |

By command:

| Command | Codes |
|---|---|
| `mask`, `mask-file`, `dashboard`, `install` | 0, or 2 on any error |
| `audit` | 0; 3 when something it found was not checked (the report lists it under "not checked" and says `nothing found in what was read` when it found nothing); 2 on any error |
| `restore`, `restore-file` | 0; 3 when the text holds unknown or damaged placeholders and `--force` is missing (nothing is printed or written); 2 |
| `ask` | 0 answer printed (also a cut-off answer, with a warning); 1 the call failed; 2 error, for example no key; 3 the answer holds placeholders that were not restored (it is printed anyway); 4 the policy blocks |
| `key` | 0, or 2 |
| `check list` | 0; 5 when a check is due; 2 when `checks.json` is damaged |
| `check set`, `check reset` | 0, or 2 |
| `check remove` | 0; 1 when the account has no check; 2 |
| `journal verify`, `journal check-export` | 0 ok; 1 BROKEN; 2 the file is missing, not JSON, or not given |
| `journal show`, `key`, `export` | 0, or 2 |
| `policy check` | 0 for `allow` and `masked`; 4 for `deny` and `local-only`; 2 |
| `plan prompt` | 0, or 2 |
| `plan run` | 0; 3 when the plan holds unknown placeholders (the plan is not run); 2 |
| `workspace create`, `list`, `drop` | 0, or 2 |
| `workspace sync` | 0; 3 when there is a conflict, a refused file, a failed file, an unreadable mirror folder or an unknown `--only` path; 2 |
| `skills scan` | 0 every item is `ok`, nothing was left unchecked and the check was saved; 3 something is `dangerous` or `suspicious`, or was not checked in full or could not be read (a `could not read` line with any reason but `link to a missing target`; the report is printed in full, also when the check could not be saved); 1 `--ai` was asked and the AI check failed (the report of the rules is printed too), or every item is `ok` but the check could not be saved; 2 error |
| `skills list` | 0, or 2 |
| `skills quarantine`, `skills restore` | 0 done, or done though a step failed after it had changed the item (the quarantine is kept and a line says so); 2 a refusal, and nothing was changed |
| `hook` | 0 allow; 2 block. Inside a masked workspace a failure of the hook blocks too. `hook skills-check` only informs: it exits 0, and a failure outside a masked workspace is a line in `hook-errors.log` |
| `mcp` | 0 when the server ends; 2 on a setting that stops it |
| `run` | The exit code of the agent; 2 when boxed cannot start it |

## Messages and what to do

### Start and environment

| Message | What it means and what to do |
|---|---|
| `unknown BOXED_KEYSTORE: it takes keyring or insecure-file` | `BOXED_KEYSTORE` holds something other than `keyring` or `insecure-file`. Unset it or fix it |
| `the system keychain cannot be used, and boxed keeps its keys there: on linux, run a secret service such as gnome keyring or kwallet in your session` | The machine has no keychain service, or it is locked: usual on a Linux server or in a container. Run a Secret Service (GNOME Keyring, KWallet) in your session. `audit`, a scan of a folder, `skills list`, `policy check` and `journal check-export` work without one; a scan of what is installed is not saved. For a throwaway test only, set `BOXED_KEYSTORE=insecure-file`; never use that for real data |
| `the system keychain did not answer: it may be locked or have no desktop session; unlock it, or use the insecure-file keystore only in a throwaway home with made-up data` | Boxed stops waiting after 30 seconds, including when reading or creating a key. Unlock the keychain or sign in to a desktop session; a locked macOS keychain may not answer over SSH. For a throwaway home with made-up data only, set `BOXED_KEYSTORE=insecure-file`; never use that for real data. `audit` stops too, rather than treating a timeout as a damaged key |
| `the folder for the keychain lock in the temporary folder is not a private folder of this user: remove it, or make the home folder writable` | The home folder is missing or read-only, so boxed takes the lock of a new key in `boxed-<user number>` in the temporary folder (`/tmp` or `$TMPDIR`), and that name is a link, belongs to another user, or is open to others. Remove it if it is yours, or make `~/.boxed` possible |
| `boxed install native-host works on macos and windows only` | On Linux the browsers read their native hosts from other folders, which boxed does not write yet. The side panel does not work on Linux |
| `No module named 'natasha'`, `No module named 'gliner'` | `boxed.toml` asks for a name model whose extra is not installed. Install the extra `ner-ru` or `ner-en`, or remove `ner` |
| `this file type needs the formats extra: reinstall boxed with it, as docs/guide/install.md shows` | `mask-file` and `restore-file` need the extra `formats` for XLSX, DOCX and PDF. Install boxed again with it, with the command in [install.md](install.md) |
| `the journal file is not a regular file` | `journal.jsonl` in the boxed home is a link, a folder or a pipe. Move it away; boxed starts a new journal |
| `a marker map of the vault cannot be decrypted: wrong key or tampered data` | The vault key in the keychain is not the key that locked that scope, or `vault.db` changed. The map of that scope cannot be read. Restore the keychain entry (`vault-key`, service `boxed.si`) from a backup if you have one |
| `unknown scope: boxed journal show lists the scopes in use (the scope field)` | The vault has no scope of that name: a typo, another `BOXED_HOME`, or a deleted `vault.db`. List the names in the `scope` field of `boxed journal show` |

### boxed.toml

The message starts with `boxed.toml:` or with the section, `[boxed.policy]`, and never with the path, a value or a key you wrote. The full list is in [configuration.md](configuration.md#errors-in-the-file) and, for the policy, in [policy.md](policy.md). The common ones:

| Message | What to do |
|---|---|
| `[boxed] has a key boxed does not know; the known ones are level, internal_domains, dictionary, allow, protected_paths, mcp_roots, ner, policy` | Remove the key or fix the spelling. The message does not say which key it refuses. The keys are in [configuration.md](configuration.md) |
| `[boxed].level must be int` (also `list`, `dict`) | Fix the type of the value: `level = 2`, not `"2"` |
| `[boxed].level must be 0-4` | Use 0 to 4 |
| `[boxed].ner takes ru, en` | Use `"ru"` or `"en"` |
| `[boxed.dictionary] a term cannot use a built-in kind name (EMAIL, DATE, NUMBER and the like)` | Give the term another kind, for example `CLIENT`. The built-in names are the kinds of the placeholders in [concepts.md](concepts.md#what-each-placeholder-stands-for), and `PASSPORT`, `SSN`, `VAT_ID` and `CRYPTO_ADDR` are among them. If an older `boxed.toml` used one of these for your own terms, rename the kind in that file (`"Acme Corp" = "PASSPORT"` becomes `"Acme Corp" = "CLIENT"`); the message does not say which kind it refuses |
| `[boxed.dictionary] a kind has letters, digits and _ only, and starts with a letter` | Fix the kind, for example `CLIENT_NAME`, not `CLIENT NAME` |
| `[boxed].internal_domains must be a list of strings` (also `allow`, `protected_paths`, `mcp_roots`, `ner`) | An item of the list is not a string. Put every item in quotes: `"corp.example.com"` |
| `[boxed.dictionary] every kind must be a string, such as CLIENT` | A kind in the dictionary is not a string. Write `"Acme Corp" = "CLIENT"`, not `"Acme Corp" = 5` |
| `not valid TOML (at line 1, column 5)` | The file is not valid TOML. The message names the line and the column, not what stands there: the words of the TOML parser can quote a key, such as a client's name |
| `[boxed.policy.rules] finance:corporate: allow is looser than masked:3, a policy can only be tightened` | A policy rule is looser than its profile. Use a stricter rule, or a looser profile |

### Masking and restoring

| Message | What it means and what to do |
|---|---|
| `no such file or directory` | A file you named is not there. Check the name and the folder you run from. The message names no path: a path can be private |
| `<ErrorClass>: an unexpected error; its message is not shown, it may quote a path or a value` | Something failed that boxed has no words of its own for. The message of such an error is never printed: it can hold a path or a piece of your data. Note the class and the command, and report it (see `SECURITY.md` if it looks like a leak) |
| `the input is not UTF-8` | boxed reads UTF-8 only. Convert the file, for example `iconv -f cp1252 -t utf-8 in.txt > out.txt` |
| `level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3` | Level 4 is for tables. Lower `--level` or `level` in `boxed.toml`, or use `boxed plan` |
| `not restored, check by hand: [EMAIL_9], [EMAIL 1]` (exit code 3) | The answer holds placeholders the scope does not know (`[EMAIL_9]`), or damaged ones (`[EMAIL 1]`). Read the answer, ask the AI again, or add `--force` to print it anyway |

### Writing files

For `mask-file`, `restore-file`, `dashboard`, `audit`, `journal export` and `plan run`.

| Message | What to do |
|---|---|
| `the output file exists already: name another file, delete it first, or add --replace to replace it` | Choose another name, delete the file, or add `--replace` |
| `the output file exists and boxed did not write it: name another file, or delete it first` | boxed replaces only a file it wrote itself (a report, an export, a chart). Choose another name |
| `the output is not written in the boxed home, where the journal, the vault and the keys are` | Write the file outside `~/.boxed`. Reports may go below `~/.boxed/reports/` |
| `the output path is a link: name the file itself` | boxed never writes through a link. Name the real file |
| `the folder of the output file does not exist` | Make the folder first. Reports create their folder; other files do not |
| `the output path is not a plain file` | The name belongs to a folder or another special file |
| `the delimiter of this csv file cannot be told for sure: name it (boxed mask-file --delimiter comma, semicolon, tab or pipe)` | The header and the rows of the CSV fit more than one delimiter, or none. Name it: `boxed mask-file --delimiter semicolon in.csv out.csv` (`restore-file` takes the same option) |
| `the output would replace the source file`, `the output is the input file: choose another output name` | The output and the input are the same file. Choose another output name |
| `unsupported file type; supported: .csv, .docx, .pdf, .xlsx` | `mask-file` takes these four. A text file needs `boxed mask` |
| `a pdf is masked to a .txt file` | Name the output `something.txt`. A PDF becomes a text file of its text layer |
| `a pdf is restored from the .txt made from it` | Restore the `.txt`, not the PDF |
| `cannot process this xlsx file` | The file is damaged, not a real file of that type, or not readable. The text never says why, so that it cannot quote the file |
| `--html and --csv name the same file` | Give two files |
| `give --html FILE, --csv FILE or both` | `boxed dashboard` writes nothing without one of them |
| `--period names the days itself: use it or --since and --until, not both` | Use one way to set the period |
| `argument --since: a date is written YYYY-MM-DD, for example 2026-12-31` (exit code 2, also for `--until`) | `audit`, `dashboard` and `journal export` take a real day as `YYYY-MM-DD` |
| `export needs --out FILE`, `check-export needs the export file` | Name the file |

### boxed ask and API keys

| Message | What to do |
|---|---|
| `no API key for openai: run boxed key set openai` | Store a key, or set `OPENAI_API_KEY` (the variable of the provider). See [configuration.md](configuration.md) |
| `the API key must be printable ASCII without spaces` | The key has a space, a line break or a character outside ASCII. Paste it again without extras |
| `openai: cannot store the key in the keychain`, `openai: cannot remove the key from the keychain` | The OS keychain refused. Unlock it, or use the provider's environment variable |
| `openai: HTTP 401 (invalid_api_key)` | The provider did not accept the key. The word in brackets is from a fixed list; the provider's own message is never shown |
| `openai: HTTP 429 (rate_limit_exceeded)`, `HTTP 503 (overloaded_error)` | Limit or outage at the provider. Wait and retry |
| `openai: network error`, `openai: timed out` | No connection, a wrong relay address, or no answer within 120 seconds |
| `openai: the provider reported an error (...)`, `the model refused to answer`, `the answer was filtered` | The provider answered, but not with an answer. Change the prompt or the model |
| `openai: malformed answer` | The reply was not in the shape boxed expects. Check the relay, if you use one |
| `warning: the answer was cut off: the provider stopped it before the end` | The answer is printed with a warning. Ask for a shorter one |
| `BOXED_OPENAI_BASE_URL must be an https address (or http on this computer) without a login, query or fragment` | Fix the address. See [configuration.md](configuration.md). The message never shows the address |
| `bad model name` | The model name has a space or another character a model name does not hold |
| `argument --provider: not one of openai, anthropic, deepseek, openrouter` | Use a listed provider |
| `blocked by policy: deny` (exit code 4) | The policy stops this text for this recipient. Read the `reason:` lines. See [policy.md](policy.md) |

### Policy

| Message | What to do |
|---|---|
| `--recipient takes provider:kind:jurisdiction, for example openai:personal-private:US` | Give three parts, separated by colons |
| `unknown recipient kind, expected one of personal-training, personal-private, corporate, api-zero-retention, local` | Use one of the five kinds |
| `the policy asks for level 4, which sends the task and the table schema only: use boxed plan` | A rule needs `masked:4`. Use `boxed plan`, or relax the rule |

### Journal, checks and the dashboard

| Message | What to do |
|---|---|
| `BROKEN: 4 records verified; record 5: hash does not match content` | Record 5 was changed. Treat the journal as altered from that record on. Compare it with an export |
| `BROKEN: 4 records verified; record 6: chain break` | A record before record 6 is missing, added or moved |
| `BROKEN: 0 records verified; record 1: bad signature` | The records were not signed with this device's key. The keychain entry `device-signing-key` was replaced or lost. Old exports still verify with the old public key |
| `BROKEN: 47 records verified; line 48 is not a journal record (1 damaged); the 47 whole records verify` | A line is damaged, often by a crash during a write. The whole records still verify. `journal show` and the dashboard skip the line and tell you |
| `BROKEN: 0 records verified; not a boxed journal export` | The file given to `check-export` is not an export of boxed |
| `checks.json is damaged, so every account counts as personal-training until you run boxed check reset (it moves the file aside; nothing is deleted)` | Run `boxed check reset`, then record the settings again with `boxed check set` |
| `training checks need to be confirmed again, so every account counts as personal-training until you run boxed check reset (...)` | The file was edited, written by another computer, or written by an older boxed version. Run `boxed check reset` and record again |
| `checks.json is readable: nothing to reset (boxed check remove deletes one check)` | `reset` is for a damaged file. To delete one check, use `boxed check remove` |
| `no check for gemini nobody` (exit code 1) | `check remove` found no check for that provider and account |
| `--account takes a short name: letters, digits and . _ @ + - (at most 64, starting with a letter or digit)` | Use a short account name; a text with a space is refused |

### Workspaces, agents and hooks

| Message | What to do |
|---|---|
| `workspace e8da0889 created: 0 files masked, 0 skipped, level 2` | A mirror with no files: the folder holds no text file that boxed copies. It leaves out files in folders named `.git`, `node_modules`, `.venv` and `__pycache__`, and (in a git project) files that `.gitignore` excludes. If that is not what you wanted, drop it with `boxed workspace drop e8da0889` |
| `the project folder does not exist`, `the project path is not a folder` | `workspace create` needs a folder that exists. Check the path. Nothing was written |
| `create needs the project folder`, `sync needs the workspace id (boxed workspace list shows them)` | The command has no argument, or an empty one: `boxed workspace create <folder>`, `boxed workspace sync <id>` |
| `skipped notes.txt (name-taken)` | The mirror already holds a file under that name, for example `a.txt` and `A.txt` of a project on a case-sensitive volume while the mirror lies on a volume that reads the two names as one. The first file is in the mirror. Rename one of them in the project and create the mirror again |
| `unknown workspace: boxed workspace list shows them` | Run `boxed workspace list` for the ids |
| `conflict app.py: the original changed since the mirror was made` (exit code 3) | The file changed in the project after the mirror was made, and boxed never overwrites a changed original. Compare the project file with the file in the mirror (`boxed workspace list` shows its path), merge by hand, or drop the mirror and create a new one |
| `refused config.txt: [EMAIL_9] (use --force after checking)` (exit code 3) | The file holds a placeholder the workspace does not know or that looks damaged. Read the file. If it is right, run `boxed workspace sync <id> --only config.txt --force` |
| `not in the mirror: nothing.txt` | A path given to `--only` is not in the mirror. Check the spelling |
| `kept notes.txt: deleted in the mirror, add --delete to delete the original` | The agent deleted the file in the mirror. The original stays unless you add `--delete` |
| `failed app.py: Permission denied` (exit code 3) | The file system refused the change to `app.py` in your project (a read-only file or folder), or boxed cannot read the file in the mirror. That file is untouched and the others were synced. Change the rights and run `sync` again. A dry run says the same |
| `unreadable src: boxed cannot look into this folder of the mirror, so nothing in it was synced` (exit code 3) | A folder of the mirror has no rights for you, for example after a `chmod` by the agent. Fix the rights and run `sync` again. The originals of the files in it are not deleted |
| `the mirror folder of the workspace is missing; nothing was synced` | The mirror was deleted or moved. Put it back, or run `boxed workspace drop <id>` |
| `the mirror folder of the workspace is not the folder boxed made, or boxed cannot read it ...` | The mirror was replaced by a link or by an empty folder, its `.boxed-workspace` is gone or names another workspace, or its rights stop boxed. `sync` stops so that `--delete` cannot take every file for deleted. Put the folder back. If only `.boxed-workspace` is gone, write `{"id": "e8da0889"}` into it |
| `run this inside a boxed workspace (boxed workspace create <project>)` | `boxed run` works from inside the mirror folder |
| `claude not found on PATH`, `codex not found on PATH` | The agent is not installed, or not on the `PATH` of this shell |
| `no such file or directory` from `boxed install claude` | The `claude` command is missing. Install Claude Code first |
| `boxed: the hook failed and blocked this step; details are in the boxed hook error log` | A hook could not run. Read the last line of `hook-errors.log` in the boxed home. Inside a masked workspace the step is blocked (exit code 2). Outside one, the same text appears but the step goes through (exit code 0) |
| `boxed: prompt blocked, it contains EMAIL 2. Mask it first, ...` | The prompt held data the workspace level covers. Mask the text with `boxed mask --scope <scope>` and paste the result |
| `boxed: Bash blocked: it points outside the masked workspace. Work only with files inside this folder.` | The hook stopped a tool call aimed outside the mirror. Work with the files inside it |
| `boxed: Bash blocked: boxed commands do not run inside the masked workspace. Run them in your own terminal.` | Run the `boxed` command in your own terminal, not through the agent |

### Agent extensions: `boxed skills`

The commands are in [skills.md](skills.md). Arguments and reports:

| Message | What to do |
|---|---|
| `--ai needs --provider and --model` | Name both: `boxed skills scan --ai --provider openai --model gpt-5` |
| `--provider, --model and --account go with --ai: add --ai` | The three options mean something only with `--ai` |
| `the target is empty: name a folder, a file, a .zip or an https git address, or leave it out to check what is installed` | The target argument is an empty string. Name a target, or leave it out |
| `--html and --json name the same file: give each its own` | Give two files |
| `the output file exists and boxed did not write it: name another file, delete it first, or add --replace to replace it` | boxed replaces only a skills report it wrote itself. Choose another name, or add `--replace` |
| `the output is not written in the boxed home, where the journal, the vault and the keys are` | Write the report outside `~/.boxed` |
| `the output path is a link: name the file itself`, `the folder of the output file does not exist`, `the output path is not a plain file` | The same rules as for the other files boxed writes (see "Writing files") |
| `record.json is damaged: move it aside and run boxed skills scan again (the quarantine folder keeps its files)` | `skills/record.json` in the boxed home is not what boxed wrote: edited, cut off, a link, or readable by others. Move it aside and scan again. The earlier verdicts are gone, and `boxed skills list` no longer shows what was in quarantine: put that back by hand from `skills/quarantine/<id>/`, which boxed leaves alone |
| `boxed: warning: the check was not saved, so the next session will not know about it: run boxed skills scan again` (stderr; exit code 1, or 3 when something is `dangerous` or `suspicious`) | The report printed before it is whole and right. boxed could not write `skills/record.json` in the boxed home: a full disk, no rights on the `skills` folder, or a record that cannot be read back. Fix the cause and run `boxed skills scan` again. Until then the warning at the start of a session compares with the older check, or says that nothing has been checked |
| `boxed: warning: the check was not saved: the journal could not take it (no keychain, or the journal cannot be written), so the record was left as it was: run boxed skills scan again` (stderr; exit code 1, or 3 when something is `dangerous` or `suspicious`) | The report printed before it is whole and right. The signed journal did not take the entry of the check, so boxed did not touch `skills/record.json` either: a check the journal does not back would quiet the next session. Usual causes: no keychain (a Linux server or container), or `journal.jsonl` in the boxed home cannot be written. Fix the cause and run `boxed skills scan` again. Until then the warning at the start of a session compares with the older check |

The target of `scan`:

| Message | What to do |
|---|---|
| `the target is not a folder, a file, a .zip or an https git address: check the spelling or give owner/repo` | No such path on this computer, and the text is not an address |
| `only https git addresses are fetched: give an https address or clone it yourself and scan the folder` | An ssh (`git@host:...`), `http` or `file` address. Clone it yourself and scan the folder |
| `the address must be a plain https address: no login, query or fragment` | Cut the login, the `?...` or the `#...` from the address |
| `the address could not be fetched: check it, and that git is installed and the repository is public` | A wrong address, a private repository, no network, or a clone that took over 120 seconds. Clone it yourself and scan the folder |
| `git is not installed: install it, or download the repository and scan the folder` | boxed runs the `git` program for an address |
| `that path is not in the repository: check the address` | The folder after `owner/repo/` or `/tree/<ref>/` is not in the clone, or a link stands on the way |
| `the archive has a path that leaves its folder: it is not unpacked`, `the archive uses the same name twice: it is not unpacked` | The zip is built to write outside its folder or to confuse the check. Treat it as hostile and do not unpack it |
| `the archive holds too many files to check here: ...`, `the archive unpacks to too much data to check here: ...` | Over 10,000 files or 256 MiB. Unpack it yourself and scan the folder |
| `the archive cannot be unpacked here: scan the folder after unpacking it yourself` | Unpack it by hand |
| `boxed: no folder of that name here, taking https://github.com/owner/repo` (stderr, no error) | `owner/repo` is no folder on this computer, so boxed took it as a GitHub address |
| `boxed: 2 links in the archive were not unpacked, and will be reported` (stderr, no error; one link reads `boxed: 1 link in the archive was not unpacked, and will be reported`) | The zip held links. boxed makes none, but it judges each one as it judges a link in a folder: a link that stays inside its item is no finding, one that leads out of it is a `link-outside` finding (`critical` when it points at keys, credentials, the settings of an agent, your home folder or the root, `high` otherwise), and the exit code is then 3 |

Quarantine and restore. A refusal changes nothing:

| Message | What to do |
|---|---|
| `no installed item matches: run boxed skills list to see the ids` | Use an id or a name from `list` |
| `several items match: give the full id that boxed skills list shows` | Give the full id |
| `this item is already in quarantine: run boxed skills list to see its quarantine id`, `this item is already switched off: nothing to do` | Nothing to do, or restore it first |
| `this comes from a plugin: quarantine the plugin that declares it`, `this hook is declared in a skill, agent or command file: quarantine that file instead` | Quarantine the plugin or the file that holds the hook or MCP server |
| `this item cannot be taken out of use automatically: edit its config file by hand` | boxed has no safe way for this kind of item. Edit its config file |
| `the config file changed since it was read: run boxed skills list, then the command again`, `the item is no longer where it was found: run boxed skills list, then the command again` | Something changed the file or the folder between the two steps. Run `list` and try again |
| `the config file of this item does not parse: fix it by hand, then run the command again` | The config file is not valid JSON or TOML, or has a key twice. boxed edits only what it can read back. The id of the item says which agent and scope the file belongs to |
| `the config file of this item cannot be edited safely here: take the entry out by hand` | The entry sits in a shape boxed cannot cut out without risk. Edit it by hand |
| `the config file of this item is a link: edit the file it points to by hand`, `the config file of this item is not a plain file: edit it by hand` | boxed never writes through a link |
| `the config file of this item has another name on disk (a hard link): edit it by hand` | The config file has a second name. A replacement would leave the other name with the old content and part the two for good, so boxed does not touch it, at quarantine and at restore. Edit the file by hand |
| `claude is not on PATH: put it on PATH, or run claude mcp remove and claude mcp add-json by hand` | A Claude Code MCP server of `~/.claude.json` is taken out with `claude mcp remove`, so the `claude` command must be there to quarantine it. A restore does not need it: boxed writes the entry back into `~/.claude.json` itself |
| `claude mcp remove failed: run it by hand to see why; nothing was changed by boxed` | The `claude` command failed and the server is still in place. boxed does not show its output, which can hold the entry. When the server is gone after such a failure, the line about a kept quarantine (below) is printed instead |
| `the item is on another volume than the boxed folder: move it aside by hand` | A move never copies, so a skill on another disk is not quarantined |
| `nothing in quarantine matches: run boxed skills list to see the quarantine ids`, `several quarantined items match: run boxed skills list and give one quarantine id` | Use a quarantine id from `list` |
| `the original place is taken again: move what is there aside, then run boxed skills restore again` | Something stands where the item was. boxed does not overwrite it |
| `the config file changed too much since the quarantine: the saved entry stays in the quarantine folder; put it back by hand` | `entry.json` in `skills/quarantine/<id>/` holds the entry. This also happens for a hook whose place is gone: it goes back only into the group it was cut from, one of the same event with the same matcher |
| `the quarantine folder of this item is missing or damaged: look into the quarantine folder of boxed`, `a folder of boxed is not a plain private folder: move it aside` | Look at `skills/quarantine/<id>/` in the boxed home; a link or a file where a folder belongs is refused |
| `the record of boxed could not be saved, so the quarantine was undone: nothing was changed; once the disk has room, run the command again` | The item was already out of use, but `skills/record.json` could not be written (a full disk, say), and without it `list` and `restore` would not know the quarantine. boxed put the item back as a restore does. Make room on the disk and run the same command again |

Lines that are no refusal. They go to stdout and the exit code is 0:

| Message | What to do |
|---|---|
| `the step reported a failure or was stopped, but the item is no longer as it was: it is kept in quarantine, see boxed skills list` (after the two lines with the quarantine id) | A step failed, timed out or was stopped with Ctrl-C after it had changed the item (after Ctrl-C the line is printed and the command then stops), for example `claude mcp remove` removed the server and then failed. boxed keeps the saved copy and records the quarantine, so nothing is lost. `boxed skills list` shows it, and `boxed skills restore <id>` puts the item back |
| `the record of boxed could not be saved and the quarantine could not be undone: keep its quarantine id; boxed skills list shows it as not in the record` (after the two lines with the quarantine id) | The record could not be written and putting the item back failed too (a full disk, say), so the item stays out of use with its saved copy in `skills/quarantine/<id>/`. `boxed skills list` finds it by that folder and marks it `not in the record`; `boxed skills restore <id>` finds it by its `entry.json` and puts it back |
| `the settings of this project still switch it on here: run the same command again to switch it off in this project too` (after the two lines with the quarantine id) | The plugin is off in your own settings, but the settings of the current project switch it on again, and those win. Run the same command once more: the second quarantine writes `false` into the project's `.claude/settings.local.json`. Restore each by its own id |
| `restored claude:mcp:user:files: written back into .claude.json`, `restored claude:mcp:user:files: already back in .claude.json` | boxed put a Claude Code MCP server back at its key in `~/.claude.json` itself, without `claude`. `already back` means the same entry was in place already (put back by hand, or by an earlier restore that was not recorded); the quarantine is closed all the same |

The AI look (`--ai`). Lines that start with `ai:` go to stderr:

| Message | What to do |
|---|---|
| `no API key for openai: run boxed key set openai` | Store the key, as for `boxed ask`. Not asked when nothing is to be sent |
| `ai: sending 2 files (about 900 tokens) in 1 request to openai, model gpt-5; secrets and personal data are masked first` | Not an error: what goes out and where |
| `ai: skipped 1 file: too big to send (over 100 KiB)`, `ai: skipped 1 file: not text`, `ai: skipped 1 file: could not be read` | These files stay with the verdict of the rules |
| `ai: blocked by policy: deny` with `ai: reason: ...` lines (exit code 1) | Your policy does not allow this recipient. The report of the rules stands. See [policy.md](policy.md) |
| `ai: openai: HTTP 401 (invalid_api_key)` and `ai: the remaining files were not sent` (exit code 1) | A channel error, with the same texts as in "boxed ask and API keys" |
| `ai: ignored 1 answer part that did not follow the format`, `ai: ignored 2 findings whose quote is not in the file` | Nothing was taken from that part of the answer. Not a failure |
| `ai: the answer could not be checked against the masked values: it was ignored` (exit code 1) | boxed could not read back the map of the hidden values, so it cannot be sure that the answer holds none of them, and it takes nothing from it. The report of the rules stands. Scan again; if it keeps happening, see `cannot decrypt scope` in "Start and environment" |
| `ai: nothing to send: every file with findings is already checked, or cannot be sent` | Every answer is in the record, or no file can be sent |
| `ai: the model added 2 findings`, `ai: the model added no findings` | The result of the look |

### Browser panel

The panel shows a fixed sentence and never the program's own error.

| The panel says | What to do |
|---|---|
| `The boxed.si program is not registered with this browser. Run: boxed install native-host --extension-id <id>` | Run the command with the id shown on the extensions page |
| `The boxed.si program does not trust this extension yet. Run: boxed install native-host --extension-id <id>` | The id is a different one from the extension that is loaded. Run the command with the id on the extensions page |
| `The boxed.si program cannot start. Check keychain access and boxed.toml.` | The program could not open the vault or read `boxed.toml` in the boxed home. Run `boxed mask` in a terminal with the same home to see the error |
| `The boxed.si program failed. Nothing was prepared.` | An internal failure. The last line of `host-errors.log` names the error class |
| `The boxed.si program did not answer in 2 minutes, so it was stopped. Try again, or split the text into smaller parts.` | Split a very long text. Loading the name models can take a while on the first click |
| `No placeholders are saved under this scope. Use the scope shown after masking.` | Restore needs the scope that masked the text |
| `The saved training checks cannot be read, so every provider counts as training on your chats. ...` | Run `boxed check reset` in a terminal (it keeps the damaged file), then record your settings again |

## Symptoms without a message

- The text came out unchanged. Run `boxed mask --level 3 --scope probe file` to see what the rules find at all. Then check: names and companies need a name model or a dictionary; boxed replaces only internal hosts; a phone number needs `+` or the form `8 (495) 123-45-67`; boxed leaves a value in `allow` alone. See [concepts.md](concepts.md).
- boxed replaced something it should not have. Add its exact text to `allow` in `boxed.toml`.
- `boxed mask` seems stuck. Without a file it reads standard input. Press Ctrl-D to end the input, or give a file.
- The same person gets different placeholders in two prompts. You masked the prompts in different scopes. Use one `--scope` for related texts.
- The result differs on two computers. Each has its own boxed home and its own keys, and maybe another `boxed.toml`. Placeholders and scopes are per home.
- boxed seems to ignore `boxed.toml`. It uses the first one found from the current folder upward, and ignores keys outside `[boxed]`. The browser panel uses only the file in the boxed home.
- Every item shows `[new]` in `boxed skills scan`. There is no record of the last check: this is the first scan, or `skills/record.json` was moved aside, or the last scan could not be saved (it printed the warning about it). A scan of a folder or an address saves no record, so it never ends the marks.
- The warning at the start of a Claude Code session never appears. It runs at the start of a session and after `/clear`, not when you resume one. It needs the plugin (`boxed install claude`) and `boxed` on the `PATH` or in `~/.local/bin`. It says nothing when nothing is new and nothing dangerous is installed, and under `boxed run`. What a quarantine switched off (with what a quarantined plugin declares) is in neither line, and neither are the guard hooks that boxed itself writes into a masked copy. Otherwise a masked workspace is looked at like any project, and what the copy holds is new until a scan has been run from its folder. A failure leaves a line in `hook-errors.log`.
- The warning names a plugin or a server that you switched off. Only a quarantine takes an item out of both lines. One that you switched off by hand is left out of the dangerous line only, and stays in the new or changed line while it is new or changed since the last check: run `boxed skills scan` to end that, or quarantine it.
- An extension you trust shows as `suspicious` or `dangerous`. The rules judge patterns, and an honest tool can look like an attack, for example an installer that pipes a download into a shell. Read the evidence and the line it names. boxed has no list of exceptions: a verdict follows from the files.

## Logs boxed writes

| File in the boxed home | Holds |
|---|---|
| `hook-errors.log` | One line per hook failure: the time, the hook and the error class. The error's message is not kept, since it can name a path or quote a value |
| `host-errors.log` | One line per failure of the browser program: the time and the error class, never a message. At most 64 KiB |

There is no other log, and no debug mode that records your text.

## Report a problem without sending data

Send enough to find the problem, and nothing that came from your work.

Send:

- the output of `boxed --version`, and your operating system;
- the command, with file names changed to neutral ones, and its exit code;
- the error line from stderr, after you have read it for names of files or folders;
- the output of `boxed journal verify`;
- the last line of `host-errors.log`, for a problem with the browser panel.

Reproduce it on made-up text where you can, in a throwaway home: the block in [Try it without touching your own data](install.md#try-it-without-touching-your-own-data). A new `BOXED_HOME` by itself still reads your real agent folders, so that block sets a new `HOME` too.

Do not send `vault.db`, `insecure-keys/`, a masked workspace, your API keys or `checks.json`. Do not send a `boxed.toml` whose dictionary holds client names; replace the terms first. Read a dashboard, an audit report or a journal export before you send it: they hold no values, but they name scopes, folders and hashes.
