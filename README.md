# esopen

**See which apps are reading your private files.**

esopen watches every file your Mac opens, live, and flags apps that go after things they shouldn't: your messages and email, saved passwords, crypto wallets, SSH keys, and the files that make programs start at login.

![esopen: live file activity, flagged rows, and the Insights summary](docs/demo.gif)

<sub>The demo uses fake data with made-up apps. Try it yourself with `python3 esopen.py --demo`.</sub>

## Install

Paste this into Claude Code, Codex, Cursor, ChatGPT or any AI assistant:

```
Install and start esopen on my Mac by following https://raw.githubusercontent.com/sincethestudy/esopen/main/AGENT_INSTALL.md
```

The agent does the setup. You type your Mac password and turn on one switch in System Settings (Full Disk Access). It needs macOS 13 or newer.

## How it works

1. **Watches.** esopen uses Apple's Endpoint Security (the same system that security software is built on) to see every file any app opens. That's often thousands per second.
2. **Checks.** Each one is compared against your private places: Messages and Mail, browser passwords and cookies, crypto wallets, SSH and API keys, Photos, the keychain and startup files. Apple's own processes, and apps opening their own data (like Chrome opening Chrome's cookies), are ignored.
3. **Flags.** Whatever is left is tagged in the live list the moment it happens. The Insights tab then sums it up per app: what it opened, who made it, and where it runs from.

## What you'll see

**Live** shows every file open as it happens.

- Flagged rows get a red or orange tag, like **Passwords**, **Wallet**, **Keys** or **Startup file**. Click **Flagged only** to see just those.
- Click any row for the details and a plain-English reason it was flagged.
- Search (`-word` excludes, `proc:"Name"` and `path:~/Documents` target a field), use **Hide Apple** to cut system noise, press `Space` to pause, and **Export** to CSV.

**Insights** is a summary of everything since esopen started.

- One card per suspicious app: what it opened, who signed it ("Made by Acme Labs, Inc." or "Not signed by any developer"), and whether it runs from an odd place like a hidden folder or Downloads.
- Ranked High, Medium or Low. High means an app that isn't Apple's touched your messages, mail, passwords, wallets or privacy settings, or set itself up to start at login.
- **Your private places** shows which apps got into each one.

## Reading the results

- macOS also reports attempts it blocked. A flag means an app *tried* to open the file, not necessarily that it succeeded.
- Leave it running while you use your Mac normally. Some apps only act every few minutes or hours.
- File activity can't show screen recording, keystroke monitoring or network traffic. Review those in System Settings → Privacy & Security.
- If an app worries you, remove it from Full Disk Access, uninstall it, and check `~/Library/LaunchAgents` for anything it left behind.

## Privacy and safety

- **Nothing leaves your Mac.** The viewer is only served on `127.0.0.1`, and it rejects requests that come from other websites.
- **Nothing is saved to disk.** Events stay in memory (the browser keeps the latest 50,000) and are gone when you stop esopen.
- **It only watches.** It runs `eslogger` as root because macOS requires that, but it never blocks or changes anything.
- **It's one readable file** using only Python's standard library. Read it before you run it.

## Options

```
python3 esopen.py [--demo] [--port PORT] [--no-open]
```

| Option | What it does |
|---|---|
| `--demo` | Fake data, no password needed |
| `--port PORT` | Port for the local page (default 4747; uses the next free one if it's taken) |
| `--no-open` | Don't open the browser automatically |

## Troubleshooting

| Message | Fix |
|---|---|
| "macOS blocked it: *App* needs Full Disk Access" | Turn on Full Disk Access for that app (esopen opens the setting for you), quit and reopen it, then run esopen again. |
| "needs macOS 13 (Ventura) or newer" | `eslogger` only exists on macOS 13+. |
| "too many Endpoint Security clients" | Another `eslogger` or esopen is already running. Stop it first. |
| A **Dropped** counter appears | Events arrived faster than macOS could deliver them. A few is normal. |

## Uninstall

Stop it with `Ctrl+C`, then run `rm -rf ~/.esopen`. Optionally turn off your terminal's Full Disk Access.

## Under the hood

macOS 13 added `/usr/bin/eslogger`, a command-line client for Apple's Endpoint Security framework. esopen runs `eslogger open`, which prints one JSON record per `ES_EVENT_TYPE_NOTIFY_OPEN` event, and keeps a few fields from each. It checks each event against the rules above, then streams batches to the page four times a second. Apple notes that `eslogger`'s output isn't a stable API, so a future macOS update could change it.

## License

[MIT](LICENSE)
