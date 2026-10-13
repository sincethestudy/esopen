# Installing esopen: instructions for AI agents

You're helping a user install and start **esopen**, a free, open-source tool that shows every file their Mac opens, live, in their browser. It also flags apps that touch private data like messages, mail, browser passwords and SSH keys. It's a single Python file: https://github.com/sincethestudy/esopen

Follow the steps in order and keep the user informed in plain language. Two steps need the user's own hands: **typing their Mac password** and **turning on Full Disk Access**. Never ask for, type or store their password, never run `sudo` yourself, and never change privacy settings yourself. Open the right place and let the user click.

---

## If you can't run commands on the user's Mac

If you're a chat assistant without a terminal tool, walk the user through it:

1. Check they're on macOS 13 (Ventura) or newer: Apple menu → About This Mac.
2. Have them open System Settings → Privacy & Security → Full Disk Access, turn on the terminal app they use (Terminal, iTerm, Ghostty…), then quit and reopen that app.
3. Have them paste this into that terminal, and type their Mac password when asked (nothing shows while typing):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/sincethestudy/esopen/main/run.sh | bash
   ```
4. The viewer opens in their browser. Explain it using **Explaining the results** below.

---

## If you can run commands

### 1. Check the Mac

```bash
sw_vers -productVersion                                       # needs 13 or higher
test -x /usr/bin/eslogger && echo "eslogger ok"
python3 -c 'import sys; print("python ok" if sys.version_info >= (3, 9) else "python too old")'
```

If `python3` is missing, run `xcode-select --install`. Tell the user to click **Install** in the window that appears, wait for it to finish, then continue.

### 2. Download esopen

```bash
mkdir -p ~/.esopen
curl -fsSL https://raw.githubusercontent.com/sincethestudy/esopen/main/esopen.py -o ~/.esopen/esopen.py
python3 ~/.esopen/esopen.py --version
```

### 3. Pick the terminal app that will run it

esopen needs administrator rights, so it has to run in a terminal window the user can type their password into, not in your own command runner. Ask which terminal app they use (Terminal, iTerm, Ghostty, Warp…). If they don't know, use Terminal.

### 4. Turn on Full Disk Access for that app

macOS only lets Endpoint Security run from an app that has Full Disk Access. Open the setting for them:

```bash
open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles"
```

Tell them to turn on their terminal app (click **+** to add it if it isn't listed), then **quit and reopen** that app. Wait until they confirm.

### 5. Start esopen in their terminal

Create a small launcher:

```bash
cat > ~/.esopen/start.command <<'EOF'
#!/bin/zsh
exec python3 ~/.esopen/esopen.py
EOF
chmod +x ~/.esopen/start.command
```

Then open it in their terminal app:

| App | Command |
|---|---|
| Terminal | `open -a Terminal ~/.esopen/start.command` |
| iTerm | `open -a iTerm ~/.esopen/start.command` |
| Ghostty | `open -na Ghostty --args -e /bin/zsh ~/.esopen/start.command` |
| Anything else | Ask them to paste `python3 ~/.esopen/esopen.py` into it |

Tell the user to **type their Mac password in that window** (nothing shows while typing) and press Return. The viewer then opens in their browser by itself.

### 6. Check that it's working

```bash
for p in $(seq 4747 4766); do
  s=$(curl -s -m 2 "http://127.0.0.1:$p/events" | head -c 600)
  [ -n "$s" ] && { echo "port $p: $s"; break; }
done
```

- `"state": "live"`: it's working. Tell them it's at `http://127.0.0.1:<port>`.
- `"state": "error"` mentioning **Full Disk Access**: the app named in the message doesn't have it yet. Repeat step 4 for that app, have them quit and reopen it, then repeat step 5.
- `"state": "connecting"`: wait a few seconds and check again.
- Nothing on any port: the password step probably hasn't finished. Ask what the terminal window shows.

---

## Explaining the results

- **Live tab**: every file open as it happens. Opens of private data by apps that aren't Apple's get a red or orange tag (Passwords, Wallet, Keys, Startup file…). **Flagged only** shows just those, and clicking a row explains why it was flagged.
- **Insights tab**: one card per suspicious app, saying what it opened, who made it and where it runs from, ranked High, Medium and Low. Below that, a grid shows which apps got into each private place.

You can read the findings yourself and explain them:

```bash
curl -s http://127.0.0.1:<port>/insights
```

Each item in `findings` has `sev`, `kind`, `name`, `exe`, `signer` (who signed the app), `count` and `examples` (file paths). Start with high and medium findings. Say which app it is and who made it, what it touched, and what the user can do. For example: remove the app from Full Disk Access, uninstall it, or check `~/Library/LaunchAgents` for leftovers. Mention that macOS also reports attempts it blocked, so a finding means the app *tried* to open the file, not necessarily that it succeeded. Recommend leaving esopen running for a while, since some apps only act every few minutes or hours.

---

## Stopping and uninstalling

- **Stop:** press `Ctrl+C` in the terminal window running esopen.
- **Run it again later:** `python3 ~/.esopen/esopen.py`
- **Uninstall:** stop it, then `rm -rf ~/.esopen`. Optionally turn off the terminal app's Full Disk Access.

## Ground rules

- Everything stays on the user's Mac. esopen only serves on `127.0.0.1` and saves nothing to disk.
- Never ask for, type or store the user's password, and don't run `sudo` yourself.
- Don't change System Settings yourself. Open the page and let the user click.
- If something fails, show the user the exact message from the esopen window.
