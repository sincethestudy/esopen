#!/usr/bin/env python3
"""esopen - watch every file your Mac opens, live, and see which apps touch your private data.

    python3 esopen.py           # asks for your password, then opens the viewer in your browser
    python3 esopen.py --demo    # fake data, no password needed

Needs macOS 13 or newer (it uses Apple's built-in /usr/bin/eslogger). The terminal app you run it
from needs Full Disk Access: System Settings > Privacy & Security > Full Disk Access.
Single file, standard library only, works with the Python 3.9 that ships with Apple's developer tools.
"""

import argparse
import atexit
import json
import math
import os
import pwd
import queue
import random
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "0.2.0"

BATCH_INTERVAL = 0.25  # seconds between pushes to the browser
MAX_PER_BATCH = 8000   # beyond this, excess events are dropped (and counted)
ESLOGGER = "/usr/bin/eslogger"
FDA_SETTINGS = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles"


# ---------------------------------------------------------------- insights

SEV_RANK = {"high": 0, "medium": 1, "low": 2}

# Sensitive places: key, label, phrase used in finding titles, severity when a non-Apple app touches
# data that isn't its own, and the path pattern (non-capturing groups only, so m.lastgroup is the key).
PLACES = [
    ("messages", "Messages, Mail, Contacts & Notes", "Messages, Mail, Contacts or Notes data", "high",
     r"/Library/(?:Messages|Mail|Calendars|Application Support/AddressBook)/|/Group Containers/group\.com\.apple\.notes/"),
    ("tcc", "Privacy permissions database", "privacy permissions database", "high", r"/com\.apple\.TCC/TCC\.db"),
    ("browser", "Browser passwords, cookies & history", "browser passwords, cookies or history", "high",
     r"/(?:Login Data|Login Data For Account|Cookies|History|Web Data|key4\.db|logins\.json|cookies\.sqlite|places\.sqlite)"
     r"(?:-journal|-wal)?$|/Library/Safari/|/Library/Cookies/"),
    ("wallets", "Crypto wallets", "crypto wallet data", "high",
     r"/Local Extension Settings/(?:nkbihfbeogaeaoehlefnkodbefgpgknn|hnfanknocfeofbddgcijnmhnfnkdnaad|bfnaelmomeimhlpmgjnjophhpkkoljpa"
     r"|acmacodkjbdgmoleebolmdjonilkdbch|egjidjbpglichdcondbcbdnbeeppgdph)/"
     r"|/Application Support/(?:Exodus|atomic|Ledger Live|Bitcoin/wallets|Guarda|Coinomi)/|/\.electrum/"),
    ("secrets", "SSH keys & developer secrets", "SSH keys or developer secrets", "medium",
     r"/\.(?:ssh|aws|gnupg|kube|docker)/|/\.config/(?:gh|gcloud)/|/\.(?:netrc|git-credentials|npmrc|pypirc)$|/\.env(?:\.[\w-]+)?$"),
    ("photos", "Photos library", "Photos library", "medium", r"\.photoslibrary/"),
    ("keychain", "Keychain files", "keychain files", "low", r"/Keychains/"),
    ("documents", "Desktop, Documents & Downloads", "Desktop, Documents or Downloads", "low",
     r"^/Users/[^/]+/(?:Desktop|Documents|Downloads)/"),
    ("icloud", "iCloud Drive", "iCloud Drive", "low", r"/Library/Mobile Documents/"),
]
ANY_PLACE = re.compile("|".join("(?P<%s>%s)" % (p[0], p[4]) for p in PLACES))
PLACE_SEV = {p[0]: p[3] for p in PLACES}
ESCALATE = {"low": "medium", "medium": "high"}  # for unsigned programs running from odd places
PLACE_SHORT = {p[0]: p[2] for p in PLACES}

# What exactly a sensitive path is, in words: (pattern, short tag for the live list, phrase for sentences, rank).
# Lower rank = more alarming; Insights leads with the lowest-ranked thing an app touched.
LABELS = [(re.compile(rx), tag, phrase, rank) for rank, (rx, tag, phrase) in enumerate([
    (r"/Library/Messages/", "iMessages", "iMessages"),
    (r"/Library/Mail/", "Email", "email"),
    (r"/(?:Login Data|Login Data For Account|logins\.json|key4\.db)(?:-journal|-wal)?$", "Passwords", "saved browser passwords"),
    (r"/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/", "Wallet", "MetaMask wallet"),
    (r"/Application Support/Exodus/", "Wallet", "Exodus wallet"),
    (r"/Local Extension Settings/|/Application Support/(?:Exodus|atomic|Ledger Live|Bitcoin|Guarda|Coinomi)/|/\.electrum/",
     "Wallet", "crypto wallet"),
    (r"/\.ssh/", "SSH key", "SSH keys"),
    (r"/\.aws/", "AWS keys", "AWS keys"),
    (r"/\.config/gh/", "GitHub login", "GitHub login"),
    (r"/\.env(?:\.[\w-]+)?$", "API keys", "API keys in .env files"),
    (r"/\.(?:npmrc|pypirc|netrc|git-credentials)$|/\.(?:gnupg|kube|docker)/|/\.config/gcloud/", "Dev secrets", "developer credentials"),
    (r"/Application Support/AddressBook/", "Contacts", "contacts"),
    (r"group\.com\.apple\.notes", "Notes", "notes"),
    (r"/Library/Calendars/", "Calendar", "calendar"),
    (r"/(?:Cookies|cookies\.sqlite)(?:-journal|-wal)?$|/Library/Cookies/", "Cookies", "browser cookies"),
    (r"/(?:History|places\.sqlite|Web Data)(?:-journal|-wal)?$|/Library/Safari/", "History", "browsing history"),
    (r"\.photoslibrary/", "Photos", "photo library"),
    (r"/com\.apple\.TCC/", "Privacy DB", "privacy settings"),
    (r"/Library/(?:LaunchAgents|LaunchDaemons|StartupItems)/", "Login item", "login items"),
    (r"/\.(?:zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|profile)$", "Shell startup", "shell startup file"),
    (r"/Keychains/", "Keychain", "keychain"),
    (r"/Library/Mobile Documents/", "iCloud", "iCloud Drive files"),
    (r"^/Users/[^/]+/(?:Desktop|Documents|Downloads)/", "Documents", "documents"),
])]


def describe(path):
    """(short tag, phrase, rank) for a sensitive path, or None."""
    for rx, tag, phrase, rank in LABELS:
        if rx.search(path):
            return tag, phrase, rank
    return None


def every_seconds(times):
    """If a file is opened on a steady rhythm, return the interval in seconds.

    Needs 3+ opens; with only 3, the two gaps must be nearly identical."""
    if len(times) < 3:
        return None
    gaps = sorted(b - a for a, b in zip(times, times[1:]))
    mid = gaps[len(gaps) // 2]
    slack = 1.15 if len(times) == 3 else 1.5
    if mid >= 3000 and gaps[-1] <= mid * slack and gaps[0] >= mid / slack:
        return mid / 1000
    return None


PERSIST = re.compile(r"/Library/(?:LaunchAgents|LaunchDaemons|StartupItems)/|^/Users/[^/]+/\.(?:zshrc|zprofile|zshenv|zlogin|"
                     r"bashrc|bash_profile|profile)$|^(?:/private)?/etc/(?:hosts|sudoers|paths|zshrc|profile)|/usr/lib/cron/tabs/")
LIB_AREA = re.compile(r"^/Users/[^/]+/Library/(Application Support|Containers|Group Containers|Caches|Preferences|HTTPStorages|WebKit)/([^/]+)")
SHARED_AREA = re.compile(r"^(?:\.GlobalPreferences|ByHost|com\.apple\.|group\.com\.apple\.|io\.sentry|SentryCrash|CrashReporter|.*\.savedState$)", re.I)
STD_LOCATION = re.compile(r"^(?:/System/|/usr/|/bin/|/sbin/|/Applications/|/Library/|/opt/homebrew/|/private/var/db/|/nix/|/Users/[^/]+/Applications/)")
APP_SUPPORT = re.compile(r"^/Users/[^/]+/Library/Application Support/")
TEMPISH = re.compile(r"^(?:/private)?/(?:tmp|var/folders)/|^/Users/[^/]+/(?:Downloads|Desktop)/|^/Users/Shared/")
HIDDEN_DIR = re.compile(r"/\.[^/.][^/]*/")
DEV_TOOL_DIRS = re.compile(r"/\.(?:cargo|rustup|nvm|bun|deno|local|pyenv|rbenv|volta|asdf|sdkman|vscode|cursor|npm|yarn|pnpm)/")
GENERIC_WORDS = {"contents", "macos", "applications", "frameworks", "framework", "helper", "helpers", "library", "versions",
                 "current", "plugin", "plugins", "renderer", "support", "application", "resources", "users", "private",
                 "folders", "local", "homebrew", "cellar", "sharedsupport", "loginitems", "xpcservices", "desktop",
                 "documents", "downloads", "caches", "containers", "group", "service", "agent"}


def signer_name(exe):
    """Who signed this program, in words (e.g. 'Meta Platforms, Inc. (V9WTTPBFK9)')."""
    try:
        out = subprocess.run(["/usr/bin/codesign", "-dvv", exe], capture_output=True, text=True, timeout=3).stderr
    except Exception:
        return None
    m = re.search(r"^Authority=(?:Developer ID Application|Apple Development|Apple Distribution|Mac Developer): (.+)$", out, re.M)
    if m:
        return m.group(1)
    if "Authority=Software Signing" in out:
        return "Apple"
    if "Signature=adhoc" in out:
        return "No developer (ad-hoc signature)"
    if "not signed" in out:
        return "Not signed"
    return None


class Insights:
    """Rolls every event into security-relevant summaries. Covers the whole run, not just the UI's buffer."""

    def __init__(self, home):
        self.home = home
        self.generic = GENERIC_WORDS | {os.path.basename(home).lower()}
        self.lock = threading.Lock()
        self.signers = {}
        self._clear()

    def _clear(self):
        self.started = time.time()
        self.events = 0
        self.flagged = 0
        self.exes = {}   # exe path -> identity info
        self.hits = {}   # (kind, key, exe) -> counts and example paths
        self.places = {p[0]: {"total": 0, "apple": 0, "apps": {}} for p in PLACES}

    def reset(self):
        with self.lock:
            self._clear()

    def _exe(self, e):
        exe = e["exe"]
        info = self.exes.get(exe)
        if info is None:
            base = exe.rsplit("/", 1)[-1] or "?"
            words = re.split(r"[/ .()_\-]+", (exe + " " + (e.get("sid") or "")).lower())
            toks = {w for w in words if len(w) >= 4 and w not in self.generic}
            if e.get("team"):
                toks.add(e["team"].lower())
            signed = bool(e.get("team"))
            loc = None
            if not (e["plat"] or "code_sign_clone" in exe or STD_LOCATION.match(exe) or (signed and APP_SUPPORT.match(exe))):
                if signed or DEV_TOOL_DIRS.search(exe):
                    loc = "low"
                elif TEMPISH.match(exe):
                    loc = "high"
                else:
                    loc = "medium"
            info = self.exes[exe] = {"name": base, "base": base.lower(), "toks": toks, "team": e.get("team"),
                                     "plat": e["plat"], "signed": signed, "loc": loc}
        return info

    @staticmethod
    def _owns(info, s):
        s = s.lower()
        return any(t in s for t in info["toks"]) or ("/" + info["base"] + "/") in s

    def _hit(self, kind, key, e, sev):
        k = (kind, key, e["exe"])
        h = self.hits.get(k)
        if h is None:
            h = self.hits[k] = {"sev": sev, "count": 0, "writes": 0, "first": e["ts"], "last": 0, "examples": [],
                                "labels": {}, "times": {}}
        h["count"] += 1
        h["last"] = e["ts"]
        if e["ff"] & 2:
            h["writes"] += 1
        path = e["path"]
        if len(h["examples"]) < 3 and path not in h["examples"]:
            h["examples"].append(path)
        if kind != "location":
            d = describe(path)
            if d:
                lab = h["labels"].setdefault(d[1], [d[2], 0, path])
                lab[1] += 1
            times = h["times"].get(path)
            if times is None and len(h["times"]) < 50:
                times = h["times"][path] = []
            if times is not None:
                times.append(e["ts"])
                del times[:-6]

    def add(self, e):
        """Update the summaries, and tag the event (e["tag"], e["sev"]) so the live list can highlight it."""
        path = e["path"]
        tag = sev = None
        with self.lock:
            self.events += 1
            info = self._exe(e)
            if info["loc"]:
                self._hit("location", "", e, info["loc"])
            m = ANY_PLACE.search(path)
            if m:
                key = tag = m.lastgroup
                place = self.places[key]
                place["total"] += 1
                if e["plat"]:
                    place["apple"] += 1
                else:
                    rel = path[len(self.home):] if path.startswith(self.home + "/") else path
                    a = place["apps"].get(e["exe"])
                    if a is None:
                        a = place["apps"][e["exe"]] = {"count": 0, "writes": 0, "other": 0}
                    a["count"] += 1
                    if e["ff"] & 2:
                        a["writes"] += 1
                    if not self._owns(info, rel):
                        a["other"] += 1
                        sev = PLACE_SEV[key]
                        if info["loc"] in ("high", "medium"):
                            sev = ESCALATE.get(sev, sev)
                        self._hit("place", key, e, sev)
                        if sev == "low" and key in ("documents", "icloud"):
                            sev = None  # counted in Insights, but too common to flag in the live list
            elif not e["plat"]:
                m2 = LIB_AREA.match(path)
                if m2 and not SHARED_AREA.match(m2.group(2)) and not self._owns(info, m2.group(2)):
                    tag, sev = "crossapp", "medium"
                    self._hit("crossapp", m2.group(1) + "/" + m2.group(2), e, sev)
            if e["ff"] & 2 and PERSIST.search(path):
                tag, sev = "persist", "medium" if e["plat"] else "high"
                self._hit("persist", "", e, sev)
            if sev in ("high", "medium"):
                self.flagged += 1
        if tag:
            e["tag"] = tag
            d = describe(path)
            if d:
                e["what"], e["phrase"] = d[0], d[1]
        if sev:
            e["sev"] = sev

    def snapshot(self):
        with self.lock:
            unknown = [exe for (_, _, exe) in self.hits if exe not in self.signers]
        for exe in unknown[:8]:  # codesign is slow-ish; fill in a few per request, outside the lock
            self.signers[exe] = signer_name(exe)
        with self.lock:
            findings = []
            for (kind, key, exe), h in self.hits.items():
                info = self.exes[exe]
                rhythms = [every_seconds(t) for t in h["times"].values()]
                rhythms = [r for r in rhythms if r]
                findings.append({
                    "kind": kind, "key": key, "sev": h["sev"], "name": info["name"], "exe": exe, "team": info["team"],
                    "signed": info["signed"], "signer": self.signers.get(exe), "count": h["count"], "writes": h["writes"],
                    "first": h["first"], "last": h["last"], "examples": list(h["examples"]),
                    "what": PLACE_SHORT.get(key, key), "every": min(rhythms) if rhythms else None,
                    # [phrase, rank, count, example path], most alarming first
                    "labels": sorted(([p, r, c, ex] for p, (r, c, ex) in h["labels"].items()), key=lambda x: x[1]),
                })
            places = []
            for key, label, _, sev, _ in PLACES:
                p = self.places[key]
                apps = sorted(({"name": self.exes[x]["name"], "count": a["count"], "writes": a["writes"], "own": not a["other"]}
                               for x, a in p["apps"].items()), key=lambda a: -a["count"])[:8]
                places.append({"key": key, "label": label, "sev": sev, "total": p["total"], "apple": p["apple"], "apps": apps})
            out = {"since": self.started * 1000, "events": self.events, "flagged": self.flagged,
                   "programs": len(self.exes), "findings": findings, "places": places}
        findings.sort(key=lambda f: (SEV_RANK[f["sev"]], -f["count"]))
        return out


# ---------------------------------------------------------------- hub

class Hub:
    """Collects events from the source thread and fans batches out to browser tabs."""

    def __init__(self, mode, home):
        self.mode = mode
        self.home = home
        self.insights = Insights(home)
        self.lock = threading.Lock()
        self.pending = []
        self.clients = set()
        self.total = 0
        self.es_dropped = 0  # gaps in Endpoint Security's seq_num
        self.ui_dropped = 0  # trimmed because a batch was too large
        self.status = {"state": "starting", "message": ""}

    def push(self, ev):
        self.insights.add(ev)  # first, so the event carries its tag to the browser
        with self.lock:
            self.pending.append(ev)
            self.total += 1

    def set_status(self, state, message=""):
        self.status = {"state": state, "message": message}
        self.broadcast(json.dumps(dict(type="status", **self.status)))

    def subscribe(self):
        q = queue.Queue(maxsize=40)
        with self.lock:
            self.clients.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.clients.discard(q)

    def broadcast(self, data):
        with self.lock:
            clients = list(self.clients)
        for q in clients:
            try:
                q.put_nowait(data)
            except queue.Full:
                pass  # a stalled tab; it picks up again with the next batch

    def run_batcher(self):
        while True:
            time.sleep(BATCH_INTERVAL)
            with self.lock:
                batch, self.pending = self.pending, []
            if len(batch) > MAX_PER_BATCH:
                self.ui_dropped += len(batch) - MAX_PER_BATCH
                batch = batch[-MAX_PER_BATCH:]
            self.broadcast(json.dumps({
                "type": "batch", "events": batch, "total": self.total, "flagged": self.insights.flagged,
                "esDropped": self.es_dropped, "uiDropped": self.ui_dropped,
            }, separators=(",", ":")))


# ---------------------------------------------------------------- eslogger

_TS = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?")
_ts_cache = {}
_users = {}


def epoch_ms(s):
    m = _TS.match(s or "")
    if not m:
        return time.time() * 1000
    base, frac = m.groups()
    sec = _ts_cache.get(base)
    if sec is None:
        sec = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        if len(_ts_cache) > 4096:
            _ts_cache.clear()
        _ts_cache[base] = sec
    return sec * 1000 + (int(frac[:3].ljust(3, "0")) if frac else 0)


def username(uid):
    if uid not in _users:
        try:
            _users[uid] = pwd.getpwuid(uid).pw_name
        except (KeyError, TypeError):
            _users[uid] = str(uid)
    return _users[uid]


def slim(msg):
    """Reduce eslogger's es_message_t JSON to the fields the UI shows."""
    proc = msg.get("process") or {}
    token = proc.get("audit_token") or {}
    op = (msg.get("event") or {}).get("open") or {}
    uid = token.get("euid")
    return {
        "ts": epoch_ms(msg.get("time")),
        "pid": token.get("pid"),
        "ppid": proc.get("ppid"),
        "uid": uid,
        "user": username(uid),
        "exe": (proc.get("executable") or {}).get("path") or "",
        "sid": proc.get("signing_id"),
        "team": proc.get("team_id"),
        "plat": bool(proc.get("is_platform_binary")),
        "path": (op.get("file") or {}).get("path") or "",
        "ff": op.get("fflag") or 0,
    }


def run_eslogger(hub, app_name):
    if os.geteuid() != 0:
        hub.set_status("error", "Watching file activity needs administrator rights. Run `python3 esopen.py` again "
                                "and enter your password, or add --demo to try it with fake data.")
        return
    try:
        proc = subprocess.Popen([ESLOGGER, "open"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1 << 16)
    except OSError as e:
        hub.set_status("error", "Couldn't start %s: %s" % (ESLOGGER, e))
        return
    atexit.register(proc.terminate)

    stderr_lines = []
    err_reader = threading.Thread(
        target=lambda: stderr_lines.extend(l.decode("utf-8", "replace").strip() for l in proc.stderr), daemon=True)
    err_reader.start()

    hub.set_status("connecting", "Starting eslogger...")
    last_seq = None
    first = True
    for line in proc.stdout:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        seq = msg.get("seq_num")
        if isinstance(seq, int):
            if last_seq is not None and seq > last_seq + 1:
                hub.es_dropped += seq - last_seq - 1
            last_seq = seq
        hub.push(slim(msg))
        if first:
            first = False
            hub.set_status("live")

    code = proc.wait()
    err_reader.join(timeout=1)
    detail = " ".join(stderr_lines)[-600:]
    who = app_name or "the terminal app you ran this from"
    if "NOT_PERMITTED" in detail:
        message = ("macOS blocked it: %s needs Full Disk Access. I've opened that setting for you. Turn on %s, "
                   "quit and reopen it, then run `python3 esopen.py` again." % (who, who))
        run_as_user(["/usr/bin/open", FDA_SETTINGS])
    elif "NOT_PRIVILEGED" in detail:
        message = "eslogger needs administrator rights. Run `python3 esopen.py` again and enter your password."
    elif "TOO_MANY_CLIENTS" in detail:
        message = "macOS has too many Endpoint Security clients running. Close another eslogger or esopen and retry."
    else:
        message = "eslogger stopped (code %s). %s" % (code, detail)
    print("\n  ! " + message + "\n", file=sys.stderr, flush=True)
    hub.set_status("error", message)


# ---------------------------------------------------------------- demo data

def run_demo(hub):
    hub.set_status("demo")
    rnd = random.Random()
    H = hub.home
    me = int(os.environ.get("SUDO_UID", os.getuid()))

    def hexs(n):
        return "".join(rnd.choice("0123456789abcdef") for _ in range(n))

    pick = lambda *xs: (lambda: rnd.choice(xs))
    vocab = {
        "n": lambda: str(rnd.randint(1, 40)),
        "hex": lambda: hexs(16),
        "hex2": lambda: hexs(2),
        "doc": pick("Q3 Plan.pages", "invoice-0423.pdf", "notes.md", "Budget 2026.xlsx",
                    "Screenshot 2026-10-12 at 10.41.22.png", "resume.docx", "roadmap.key"),
        "dl": pick("archive.zip", "installer.dmg", "IMG_2041.jpg", "export.csv", "paper.pdf"),
        "plist": pick("com.apple.finder.plist", "com.apple.dock.plist", ".GlobalPreferences.plist",
                      "com.google.Chrome.plist", "com.apple.Safari.plist", "com.apple.Terminal.plist"),
        "chrome": pick("History", "Cookies", "Preferences", "Login Data", "Web Data", "Favicons",
                       "Network/TransportSecurity", "Local Storage/leveldb/000123.log", "Sessions/Tabs_13371337"),
        "ldb": pick("000231.ldb", "LOG", "MANIFEST-000001", "CURRENT", "000232.log"),
        "proj": pick("robot-app", "website", "firmware"),
        "src": pick("src/main.ts", "src/App.tsx", "src/lib/motor.ts", "package.json", "tsconfig.json",
                    "README.md", "src/components/Header.tsx", "vite.config.ts"),
        "git": pick("HEAD", "index", "config", "refs/heads/main", "packed-refs", "FETCH_HEAD"),
        "app": pick("Safari.app", "Slack.app", "Spotify.app", "Notes.app", "Xcode.app"),
        "zf": pick("compinit", "promptinit", "_git", "_brew", "vcs_info"),
        "nm": pick("react", "react-dom", "typescript", "vite", "esbuild", "@babel/core", "lodash", "zod"),
        "dylib": pick("libSystem.B.dylib", "libobjc.A.dylib", "libc++.1.dylib", "libz.1.dylib"),
    }

    def fill(tpl):
        return re.sub(r"\{(\w+)\}", lambda m: vocab[m.group(1)](), tpl)

    def prof(exe, sid, team, plat, uid, weight, write_p, paths, ppid=1, ephemeral=False):
        return dict(exe=exe, sid=sid, team=team, plat=plat, uid=uid, weight=weight, w=write_p,
                    paths=paths, ppid=ppid, ephemeral=ephemeral, pid=rnd.randint(300, 60000))

    chrome_pid = rnd.randint(400, 9000)
    profiles = [
        prof("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/"
             "Versions/A/Support/mds_stores", "com.apple.mds_stores", None, True, 0, 16, 0.2,
             ["/System/Volumes/Data/.Spotlight-V100/Store-V2/5B8D2F4A-91C3-4E67-A0D2-7C1E9F3B6A58/live.{n}.indexPostings",
              "/System/Volumes/Data/.Spotlight-V100/Store-V2/5B8D2F4A-91C3-4E67-A0D2-7C1E9F3B6A58/journalAttr.{n}",
              H + "/Documents/{doc}", H + "/Downloads/{dl}"]),
        prof("/usr/sbin/cfprefsd", "com.apple.cfprefsd.xpc.daemon", None, True, me, 9, 0.15,
             [H + "/Library/Preferences/{plist}", "/Library/Preferences/{plist}"]),
        prof("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/"
             "130.0.6723.70/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
             "com.google.Chrome.helper", "EQHXZ8M8AV", False, me, 13, 0.3,
             [H + "/Library/Caches/Google/Chrome/Default/Cache/Cache_Data/{hex}_0",
              H + "/Library/Application Support/Google/Chrome/Default/{chrome}"], ppid=chrome_pid),
        prof("/Applications/Slack.app/Contents/MacOS/Slack", "com.tinyspeck.slackmacgap", "BQR82RBBHL", False, me, 5, 0.3,
             [H + "/Library/Application Support/Slack/IndexedDB/https_app.slack.com_0.indexeddb.leveldb/{ldb}",
              H + "/Library/Application Support/Slack/Cache/Cache_Data/{hex}_0", H + "/Library/Keychains/login.keychain-db"]),
        prof("/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/"
             "Code Helper (Plugin)", "com.microsoft.VSCode.helper.plugin", "UBF8T346G9", False, me, 7, 0.05,
             [H + "/code/{proj}/{src}"]),
        prof("/usr/bin/git", "com.apple.git", None, True, me, 2, 0.1,
             [H + "/code/{proj}/.git/{git}", H + "/code/{proj}/.git/objects/{hex2}/{hex}", H + "/code/{proj}/{src}"],
             ephemeral=True),
        prof("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "com.apple.finder", None, True, me, 3, 0.03,
             [H + "/Desktop/{doc}", H + "/Downloads/{dl}", "/Applications/{app}/Contents/Info.plist"]),
        prof("/usr/libexec/trustd", "com.apple.trustd", None, True, 0, 3, 0.05,
             ["/private/var/protected/trustd/private/TrustStore.sqlite3",
              "/System/Library/Security/Certificates.bundle/Contents/Resources/certsTable.data",
              "/Library/Keychains/crls/valid.sqlite3"]),
        prof("/bin/zsh", "com.apple.zsh", None, True, me, 2, 0.0,
             [H + "/.zshrc", H + "/.zsh_history", "/etc/zshenv", "/usr/share/zsh/5.9/functions/{zf}"], ephemeral=True),
        prof("/opt/homebrew/Cellar/node/22.9.0/bin/node", None, None, False, me, 5, 0.08,
             [H + "/code/{proj}/node_modules/{nm}/package.json", H + "/code/{proj}/node_modules/{nm}/index.js",
              H + "/code/{proj}/{src}"], ephemeral=True),
        prof("/Applications/Spotify.app/Contents/MacOS/Spotify", "com.spotify.client", "2FNC3A47ZF", False, me, 3, 0.45,
             [H + "/Library/Caches/com.spotify.client/Data/{hex2}/{hex}.file"]),
        prof("/usr/libexec/logd", "com.apple.logd", None, True, 0, 4, 0.9,
             ["/private/var/db/diagnostics/Persist/0000000000000{hex2}.tracev3", "/private/var/db/uuidtext/{hex2}/{hex}"]),
        prof("/System/Library/PrivateFrameworks/CloudDocsDaemon.framework/Versions/A/Support/bird", "com.apple.bird",
             None, True, me, 2, 0.3,
             [H + "/Library/Application Support/CloudDocs/session/db/client.db",
              H + "/Library/Mobile Documents/com~apple~CloudDocs/{doc}"]),
        prof("/usr/libexec/xpcproxy", "com.apple.xpc.proxy", None, True, 0, 3, 0.0,
             ["/usr/lib/{dylib}", "/System/Library/dyld/dyld_shared_cache_arm64e"], ephemeral=True),
        prof("/System/Applications/Messages.app/Contents/MacOS/Messages", "com.apple.MobileSMS", None, True, me, 1, 0.3,
             [H + "/Library/Messages/chat.db", H + "/Library/Messages/chat.db-wal"]),
    ]
    bursty = [p for p in profiles if p["exe"].endswith(("/git", "/node", "mds_stores", "Helper"))]

    # Made-up bad actors (all names fictional) so the Insights tab has something to show in demo mode.
    # The star: a normal-looking, signed notes app that quietly checks your iMessages, email and contacts on a timer.
    notes, notes_pid, notes_every = "/Applications/Acme Notes.app/Contents/MacOS/Acme Notes", rnd.randint(2000, 9000), 15.0
    notes_paths = [H + "/Library/Application Support/com.apple.TCC/TCC.db", H + "/Library/Messages/chat.db",
                   H + "/Library/Mail/V10/MailData/Envelope Index", H + "/Library/Application Support/AddressBook/AddressBook-v22.abcddb"]

    def notes_tick(at):
        for i, path in enumerate(notes_paths):
            hub.push({"ts": at * 1000 + i * 3, "pid": notes_pid, "ppid": 1, "uid": me, "user": username(me), "exe": notes,
                      "sid": "com.acme.notes", "team": "A1C2M3E4N5", "plat": False, "path": path, "ff": 0x1})

    syncd, dl_node = "/Users/Shared/.sync/syncd", H + "/Downloads/setup-tools/bin/node"
    profiles += [
        # An info-stealer hiding in a shared folder: browser logins, wallets, SSH/cloud keys, then a login item.
        prof(syncd, "syncd-55554944", None, False, me, 1, 0.0,
             [H + "/Library/Application Support/Google/Chrome/Default/Login Data",
              H + "/Library/Application Support/Google/Chrome/Default/Cookies",
              H + "/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
              H + "/Library/Application Support/Exodus/exodus.wallet/seed.seco",
              H + "/.ssh/id_ed25519", H + "/.aws/credentials", H + "/Library/LaunchAgents/com.sync.agent.plist"]),
        # A script running out of Downloads, hunting for API keys in your projects.
        prof(dl_node, None, None, False, me, 1, 0.0,
             [H + "/code/{proj}/.env", H + "/code/{proj}/.env.local", H + "/.npmrc", H + "/.config/gh/hosts.yml"]),
    ]
    hub.insights.signers.update({notes: "Acme Labs, Inc. (A1C2M3E4N5)", syncd: "Not signed", dl_node: "Not signed"})
    weights = [p["weight"] for p in profiles]

    # Pretend Acme Notes has been doing this for the last few minutes, on the same rhythm it keeps going at.
    next_notes = time.time() + 19
    for k in range(12, 0, -1):
        notes_tick(next_notes - k * notes_every)

    burst, burst_until, acc, tick = None, 0.0, 0.0, 0.05
    while True:
        now = time.time()
        if now >= next_notes:
            notes_tick(next_notes)
            next_notes += notes_every
        if burst and now > burst_until:
            burst = None
        if not burst and rnd.random() < 0.012:
            burst, burst_until = rnd.choice(bursty), now + rnd.uniform(0.8, 3.0)
            if burst["ephemeral"]:
                burst["pid"] = rnd.randint(20000, 90000)
        rate = 140 * (1 + 0.35 * math.sin(now / 3.0) + rnd.uniform(-0.2, 0.2)) + (900 if burst else 0)
        acc += rate * tick
        n, acc = int(acc), acc - int(acc)
        for _ in range(n):
            p = burst if burst and rnd.random() < 0.85 else rnd.choices(profiles, weights)[0]
            path = fill(rnd.choice(p["paths"]))
            ff = 0x1
            if "/LaunchAgents/" in path:
                ff = 0x2 | 0x200 | 0x400
            elif rnd.random() < p["w"]:
                ff = rnd.choice([0x2 | 0x200, 0x3, 0x2 | 0x200 | 0x400, 0x2 | 0x8 | 0x200])
            if rnd.random() < 0.1:
                ff |= 0x4
            hub.push({"ts": time.time() * 1000, "pid": p["pid"], "ppid": p["ppid"], "uid": p["uid"],
                      "user": username(p["uid"]), "exe": p["exe"], "sid": p["sid"], "team": p["team"],
                      "plat": p["plat"], "path": path, "ff": ff})
        time.sleep(tick)


# ---------------------------------------------------------------- http

def make_handler(hub, port):
    allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def allowed(self):
            # This stream is fed by root; refuse foreign Host headers so a web page can't DNS-rebind into it.
            if self.headers.get("Host") in allowed_hosts:
                return True
            self.send_error(403)
            return False

        def do_GET(self):
            if not self.allowed():
                return
            path = self.path.split("?")[0]
            if path == "/":
                self.send_body(PAGE.encode(), "text/html; charset=utf-8")
            elif path == "/events":
                self.stream()
            elif path == "/insights":
                self.send_body(json.dumps(hub.insights.snapshot()).encode(), "application/json")
            else:
                self.send_error(404)

        def do_POST(self):
            if not self.allowed():
                return
            if self.path == "/insights/reset":
                hub.insights.reset()
                self.send_body(b"{}", "application/json")
            else:
                self.send_error(404)

        def send_body(self, body, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            q = hub.subscribe()
            try:
                self.send_event(json.dumps(dict(type="hello", mode=hub.mode, home=hub.home, version=__version__, **hub.status)))
                while True:
                    try:
                        data = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                        continue
                    self.send_event(data)
            except OSError:
                pass  # tab closed
            finally:
                hub.unsubscribe(q)

        def send_event(self, data):
            self.wfile.write(b"data: " + data.encode() + b"\n\n")
            self.wfile.flush()

    return Handler


# ---------------------------------------------------------------- startup

def user_home():
    user = os.environ.get("SUDO_USER")
    if user:
        try:
            return pwd.getpwnam(user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def run_as_user(cmd):
    """Run a GUI command (like `open`) as the logged-in user rather than root."""
    user, uid = os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID")
    if os.geteuid() == 0 and user and uid:
        cmd = ["/bin/launchctl", "asuser", uid, "/usr/bin/sudo", "-u", user] + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def launching_app():
    """Name of the app this was started from (Terminal, iTerm, Ghostty...), which is what needs Full Disk Access.

    Walks up to the outermost app, since editors like Cursor run their terminals inside nested helper apps."""
    pid, found = os.getppid(), None
    for _ in range(20):
        try:
            out = subprocess.run(["/bin/ps", "-o", "ppid=,comm=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        except OSError:
            break
        if not out:
            break
        ppid, comm = out.split(None, 1)
        m = re.match(r"(.*?)\.app/", comm)
        if m:
            found = os.path.basename(m.group(1))
        pid = int(ppid)
        if pid <= 1:
            break
    return found


def main():
    ap = argparse.ArgumentParser(description="See every file your Mac opens, live, in your browser.")
    ap.add_argument("--demo", action="store_true", help="show fake events (no password needed)")
    ap.add_argument("--port", type=int, default=4747, help="port for the local web page (default 4747)")
    ap.add_argument("--no-open", action="store_true", help="don't open the browser automatically")
    ap.add_argument("--version", action="version", version="esopen " + __version__)
    args = ap.parse_args()

    if sys.platform != "darwin":
        sys.exit("esopen only runs on macOS.")
    if not args.demo and not os.path.exists(ESLOGGER):
        sys.exit("esopen needs macOS 13 (Ventura) or newer: %s is missing. Try --demo to see the UI." % ESLOGGER)
    if not args.demo and os.geteuid() != 0:
        print("\n  esopen needs administrator rights to watch file activity. Enter your Mac password if asked.\n", flush=True)
        os.execv("/usr/bin/sudo", ["/usr/bin/sudo", sys.executable, os.path.abspath(__file__)] + sys.argv[1:])

    hub = Hub("demo" if args.demo else "live", user_home())
    server = None
    for port in range(args.port, args.port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(hub, port))
            break
        except OSError:
            continue
    if server is None:
        sys.exit("Ports %d-%d are all busy. Try --port with another number." % (args.port, args.port + 19))
    url = "http://127.0.0.1:%d" % port

    threading.Thread(target=hub.run_batcher, daemon=True).start()
    if args.demo:
        threading.Thread(target=run_demo, args=(hub,), daemon=True).start()
    else:
        threading.Thread(target=run_eslogger, args=(hub, launching_app()), daemon=True).start()

    print("  esopen %s%s" % (__version__, " (demo data)" if args.demo else ""))
    print("  Viewer: %s" % url)
    print("  Press Ctrl+C to stop.\n", flush=True)
    if not args.no_open:
        run_as_user(["/usr/bin/open", url])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.", flush=True)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>esopen · File Opens</title>
<style>
:root{
  --line:#eef0f3; --line2:#e4e7ec; --text:#0f172a; --muted:#64748b; --faint:#94a3b8;
  --accent:#2563eb; --accent-soft:#eef3ff; --green:#16a34a; --amber:#d97706; --red:#dc2626;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Inter","Helvetica Neue",sans-serif;
  --row:32px;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{height:100%;margin:0;background:#fff;color:var(--text);font:13px/1.4 var(--sans);-webkit-font-smoothing:antialiased}
body{display:flex;flex-direction:column;overflow:hidden}
button{font:inherit;color:inherit}

/* header */
header{display:flex;align-items:center;gap:14px;padding:14px 20px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;white-space:nowrap}
.brand b{font-size:15px;font-weight:650;letter-spacing:-.015em}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);position:relative;flex:none;transition:background .3s}
.dot::after{content:"";position:absolute;inset:-5px;border-radius:50%;border:2px solid currentColor;opacity:0}
.dot.live{background:var(--green);color:var(--green)}
.dot.demo{background:var(--accent);color:var(--accent)}
.dot.live::after,.dot.demo::after{animation:ping 1.8s cubic-bezier(0,0,.2,1) infinite}
.dot.paused{background:var(--amber)}
.dot.err{background:var(--red)}
@keyframes ping{0%{transform:scale(.5);opacity:.55}100%{transform:scale(1.5);opacity:0}}
.state{font-size:12px;color:var(--muted);font-weight:500;padding:3px 8px;border-radius:999px;background:#f4f6f8}
.tabs{display:flex;background:#f3f5f8;border-radius:10px;padding:3px;gap:2px}
.tab{border:0;background:none;height:28px;padding:0 13px;border-radius:8px;font-size:12.5px;font-weight:550;color:var(--muted);
  cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:background .15s,color .15s,box-shadow .15s}
.tab:hover{color:var(--text)}
.tab.on{background:#fff;color:var(--text);box-shadow:0 1px 2px rgba(15,23,42,.08),0 0 0 1px rgba(15,23,42,.04)}
.tbadge{min-width:17px;height:17px;padding:0 5px;border-radius:999px;background:var(--red);color:#fff;font-size:10.5px;font-weight:700;
  display:inline-grid;place-items:center}
.tbadge.med{background:var(--amber)}
.search{flex:1;min-width:200px;max-width:440px;position:relative;display:block}
.search input{width:100%;height:34px;border:1px solid var(--line2);border-radius:10px;padding:0 34px 0 34px;font:13px var(--sans);
  color:var(--text);background:#fff;outline:none;transition:border-color .15s,box-shadow .15s}
.search input::placeholder{color:#a3adbb}
.search input:focus{border-color:#bfcffd;box-shadow:0 0 0 4px rgba(37,99,235,.08)}
.search svg{position:absolute;left:11px;top:10px;color:var(--faint);pointer-events:none}
.search kbd{position:absolute;right:9px;top:8px;font:11px var(--mono);color:var(--faint);border:1px solid var(--line2);
  border-radius:5px;padding:0 5px;line-height:16px;background:#fafbfc}
.search input:focus + kbd{opacity:0}
.chips{display:flex;gap:6px}
.chip,.btn{height:32px;padding:0 12px;border-radius:9px;border:1px solid var(--line2);background:#fff;color:#334155;
  font-size:12.5px;font-weight:500;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap;
  transition:background .15s,border-color .15s,color .15s,box-shadow .15s}
.chip:hover,.btn:hover{border-color:#cfd5de;background:#fafbfc}
.chip.on{background:var(--text);border-color:var(--text);color:#fff}
.chip.on:hover{background:#1e293b}
.btn.primary{background:var(--text);border-color:var(--text);color:#fff}
.btn.primary:hover{background:#1e293b}
.btn.resume{background:var(--amber);border-color:var(--amber);color:#fff}
.grow{flex:1}
body.ins .live-only{display:none!important}

/* banner */
.banner{display:none;padding:9px 20px;font-size:12.5px;border-bottom:1px solid var(--line)}
.banner.show{display:block}
.banner.info{background:#f5f8ff;color:#1e40af}
.banner.err{background:#fef4f4;color:#991b1b}
.banner.muted{background:#f8fafc;color:var(--muted)}
.banner code{font:12px var(--mono);background:rgba(255,255,255,.8);border:1px solid rgba(0,0,0,.07);padding:1px 6px;border-radius:5px}

/* stats */
.stats{display:flex;align-items:center;padding:14px 20px;border-bottom:1px solid var(--line);gap:0}
.stat{padding-right:26px;margin-right:26px;border-right:1px solid var(--line);min-width:96px}
.stat .k{font-size:10.5px;color:var(--faint);font-weight:600;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap}
.stat .v{font-size:24px;font-weight:650;letter-spacing:-.025em;font-variant-numeric:tabular-nums;margin-top:1px}
.stat .v.accent{color:var(--accent)}
.stat.warn .v{color:var(--amber)}
.sparkwrap{flex:1;min-width:180px;position:relative}
.legend{display:flex;gap:12px;justify-content:flex-end;font-size:11px;color:var(--faint);margin-bottom:2px}
.legend i{display:inline-block;width:8px;height:3px;border-radius:2px;margin-right:5px;vertical-align:middle}
.l-all{background:#cbd5e1}.l-match{background:var(--accent)}
#spark{width:100%;height:46px;display:block}

/* table */
main{flex:1;display:grid;grid-template-columns:minmax(0,1fr) 330px;min-height:0;position:relative;overflow:hidden}
.table{display:flex;flex-direction:column;min-width:0;min-height:0;position:relative;border-right:1px solid var(--line)}
.thead,.row{display:grid;grid-template-columns:96px 250px 46px minmax(0,1fr);align-items:center;column-gap:14px;padding:0 20px}
.thead{height:34px;flex:none;font-size:10.5px;font-weight:600;color:var(--faint);text-transform:uppercase;letter-spacing:.07em;
  border-bottom:1px solid var(--line);background:#fff}
.list{flex:1;overflow-y:auto;overflow-x:hidden;position:relative;overflow-anchor:none}
#spacer{width:1px}
.rows{position:absolute;top:0;left:0;right:0}
.row{position:absolute;top:0;left:0;right:0;height:var(--row);cursor:pointer;border-bottom:1px solid #f5f6f8;
  contain:layout style paint;background:#fff}
.rows.anim .row{transition:transform .22s cubic-bezier(.2,.8,.2,1)}
.row:hover{background:#f8fafc}
.row.sel{background:var(--accent-soft)}
.row.fresh{animation:fresh .9s ease-out}
@keyframes fresh{from{background:#f0f5ff}to{background:#fff}}
.c-time{font:12px var(--mono);color:#475569;white-space:nowrap}
.c-time .ms{color:#b6bfcc}
.c-proc{display:flex;align-items:center;gap:9px;min-width:0}
.av{width:20px;height:20px;border-radius:6px;display:grid;place-items:center;font-size:10.5px;font-weight:700;flex:none}
.pn{font-weight:550;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pid{font:11px var(--mono);color:var(--faint);flex:none}
.badge{display:inline-block;font:600 10.5px var(--mono);padding:2px 0;width:28px;text-align:center;border-radius:5px;letter-spacing:.02em}
.badge.r{background:#f1f5f9;color:#64748b}
.badge.w,.badge.rw{background:#fff3e0;color:#c2410c}
.badge.n{background:#f8fafc;color:#cbd5e1}
.c-path{display:flex;min-width:0;font:12.5px var(--mono);white-space:nowrap}
.c-path .dir{color:#9aa5b5;overflow:hidden;text-overflow:ellipsis;flex:0 1 auto;min-width:0}
.c-path .file{color:var(--text);flex:0 0 auto;max-width:75%;overflow:hidden;text-overflow:ellipsis}
.empty{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;color:var(--faint);font-size:13px}
.ring{width:28px;height:28px;border-radius:50%;border:2px solid #e5e9f0;border-top-color:var(--accent);animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.newpill{position:absolute;top:44px;left:50%;transform:translate(-50%,-8px);opacity:0;pointer-events:none;z-index:3;
  background:var(--text);color:#fff;border:0;border-radius:999px;padding:6px 14px;font-size:12px;font-weight:600;cursor:pointer;
  box-shadow:0 6px 20px rgba(15,23,42,.18);transition:opacity .2s,transform .2s}
.newpill.show{opacity:1;transform:translate(-50%,0);pointer-events:auto}

/* side panel */
aside{overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:14px;background:#fbfbfc}
.card{border:1px solid var(--line);border-radius:14px;background:#fff;padding:14px 14px 8px}
.card h3{margin:0 0 8px;font-size:12.5px;font-weight:650;display:flex;justify-content:space-between;align-items:baseline}
.card h3 span{color:var(--faint);font-weight:500;font-size:11.5px}
.top:empty::before{content:"Nothing yet";display:block;color:var(--faint);font-size:12px;padding:6px 0 10px}
.ti{display:grid;grid-template-columns:22px minmax(0,1fr) 22px;gap:10px;align-items:center;padding:6px 6px;margin:0 -6px;border-radius:9px;cursor:pointer;transition:background .15s}
.ti:hover{background:#f5f7fa}
.ti .av{width:22px;height:22px}
.tr{display:flex;justify-content:space-between;gap:10px;font-size:12.5px}
.tl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:550}
.ti.file .tl{font-family:var(--mono);font-size:12px}
.tc{color:var(--muted);font-variant-numeric:tabular-nums;flex:none}
.tsub{font:11px var(--mono);color:var(--faint);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.tb{height:4px;background:#f1f3f6;border-radius:4px;margin-top:5px;overflow:hidden}
.tb i{display:block;height:100%;width:0;border-radius:4px;transition:width .7s cubic-bezier(.2,.8,.2,1)}
.tx{opacity:0;border:0;background:none;color:var(--faint);cursor:pointer;width:22px;height:22px;border-radius:6px;display:grid;place-items:center;padding:0}
.ti:hover .tx{opacity:1}
.tx:hover{background:#e9edf2;color:var(--text)}
.hint{font-size:11.5px;color:var(--faint);line-height:1.6;padding:0 4px}
.hint code{font:11px var(--mono);background:#f1f3f6;padding:1px 5px;border-radius:4px;color:#475569}

/* drawer */
.drawer{position:absolute;top:0;right:0;bottom:0;width:400px;background:#fff;border-left:1px solid var(--line);
  box-shadow:-16px 0 40px rgba(15,23,42,.07);transform:translateX(105%);transition:transform .3s cubic-bezier(.2,.8,.2,1);
  overflow-y:auto;padding:20px 22px;z-index:5}
.drawer.open{transform:none}
.dh{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.dh .av{width:38px;height:38px;border-radius:11px;font-size:17px}
.dn{font-size:15px;font-weight:650;letter-spacing:-.01em;word-break:break-word}
.ds{font-size:12px;color:var(--muted);margin-top:1px}
.x{margin-left:auto;border:0;background:#f4f6f8;width:28px;height:28px;border-radius:8px;cursor:pointer;color:var(--muted);font-size:16px;flex:none}
.x:hover{background:#e9edf2;color:var(--text)}
.sec{margin-bottom:16px}
.lbl{font-size:10.5px;color:var(--faint);font-weight:600;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
.pathbox{font:12.5px/1.55 var(--mono);background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:10px 12px;word-break:break-all}
.pathbox .dir{color:#8b97a8}
.flags{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:6px}
.flag{font:600 11px var(--mono);padding:3px 7px;border-radius:6px;background:#f1f5f9;color:#475569}
.flag.hot{background:#fff3e0;color:#c2410c}
.mini{border:1px solid var(--line2);background:#fff;border-radius:7px;padding:4px 10px;font-size:12px;cursor:pointer;margin-top:8px}
.mini:hover{background:#f8fafc}
.kv{display:grid;grid-template-columns:110px 1fr;gap:9px 12px;margin:0 0 20px;font-size:12.5px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-all}
.mono{font-family:var(--mono);font-size:12px}
.faint{color:var(--faint)}
.actions{display:flex;flex-direction:column;gap:8px}
.actions .btn{justify-content:center;height:34px}

/* live-list flags */
.c-path .tag{flex:none;margin-left:auto;padding:1px 8px;border-radius:999px;font:600 10.5px var(--sans);background:#f1f5f9;color:#64748b}
.c-path .file + .tag{margin-left:auto}
.c-path .tag.high{background:#fee2e2;color:#b91c1c}
.c-path .tag.medium{background:#ffedd5;color:#c2410c}
.row.flag-high{box-shadow:inset 3px 0 0 var(--red)}
.row.flag-medium{box-shadow:inset 3px 0 0 var(--amber)}
.row.flag-high .pn{color:#b91c1c}
.stat.flagged-stat .v{color:var(--red)}
.flagchip i{width:7px;height:7px;border-radius:50%;background:var(--red);display:inline-block}
.chip.on.flagchip{background:var(--red);border-color:var(--red)}
.chip.on.flagchip i{background:#fff}
.flagbox{border-radius:12px;padding:12px 14px;margin-bottom:16px;font-size:12.5px;line-height:1.5}
.flagbox b{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px}
.flagbox.high{background:#fef2f2;color:#7f1d1d}
.flagbox.medium{background:#fff7ed;color:#7c2d12}
.flagbox.low{background:#f8fafc;color:#475569}

/* insights */
#insights{flex:1;overflow-y:auto;background:#fff}
body.ins .stats{display:none}
.ins-wrap{max-width:820px;margin:0 auto;padding:40px 24px 60px}
.ins-head{display:flex;align-items:flex-start;gap:16px;margin-bottom:22px}
.ins-title{display:flex;align-items:center;gap:12px;font-size:23px;font-weight:700;letter-spacing:-.025em}
.ins-title .vi{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;font-size:15px;flex:none}
.ins-title.bad .vi{background:#fee2e2;color:var(--red)}
.ins-title.warn .vi{background:#fff7ed;color:var(--amber)}
.ins-title.ok .vi{background:#ecfdf3;color:var(--green)}
.ins-sub{color:var(--muted);font-size:13px;margin:6px 0 0 42px}
.applist{border:1px solid var(--line);border-radius:14px;overflow:hidden}
.approw{padding:14px 18px;border-top:1px solid var(--line);cursor:pointer;transition:background .15s}
.approw:first-child{border-top:0}
.approw:hover,.approw.open{background:#fafbfc}
.ar-top{display:flex;align-items:flex-start;gap:12px;min-width:0}
.ar-top .av{width:34px;height:34px;border-radius:10px;font-size:14px;margin-top:1px}
.ar-text{flex:1;min-width:0}
.ar-head{font-size:16px;line-height:1.35;letter-spacing:-.01em;color:var(--text)}
.ar-head b{font-weight:700}
.ar-head em{font-style:normal;font-weight:700;color:#b91c1c}
.approw.medium .ar-head em{color:#b45309}
.ar-sub{font-size:13px;color:#334155;margin-top:4px}
.ar-who{font-size:12.5px;color:var(--muted);margin-top:3px;word-break:break-all}
.ar-who .bad{color:#b91c1c;font-weight:550}
.ar-chev{flex:none;color:var(--faint);transition:transform .2s;margin-top:5px}
.approw.open .ar-chev{transform:rotate(90deg)}
.ar-detail{margin:12px 0 2px 46px;font-size:13px;color:#334155;cursor:auto}
.ar-files{display:flex;flex-direction:column;gap:7px;margin-bottom:10px}
.ar-files div{display:flex;flex-direction:column;font:11.5px/1.5 var(--mono);color:#64748b;word-break:break-all}
.ar-files b{font:600 11.5px var(--sans);color:#475569}
.linkbtn{border:0;background:none;color:var(--accent);font-size:12.5px;font-weight:550;cursor:pointer;padding:0}
.ins-low{color:var(--muted);font-size:12.5px;margin-top:14px}
.ins-low:empty{display:none}
.ins-note{color:var(--faint);font-size:12px;margin-top:8px}

@media (max-width:1100px){main{grid-template-columns:1fr}aside{display:none}.stat.procs{display:none}}
@media (max-width:820px){.thead,.row{grid-template-columns:84px 170px 40px minmax(0,1fr)}.chips{display:none}}
</style>
</head>
<body>
<header>
  <div class="brand"><span class="dot" id="dot"></span><b>esopen</b><span class="state" id="stateLabel">Connecting…</span></div>
  <div class="tabs">
    <button class="tab on" data-tab="live">Live</button>
    <button class="tab" data-tab="insights">Insights <span class="tbadge" id="insBadge" hidden></span></button>
  </div>
  <label class="search live-only">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
    <input id="q" placeholder='Filter…  e.g. Slack  -mds  proc:"Code Helper"' spellcheck="false" autocomplete="off">
    <kbd>/</kbd>
  </label>
  <div class="chips live-only">
    <button class="chip flagchip" id="tFlag" title="Only show apps (not Apple's own) opening your private data"><i></i>Flagged only</button>
    <button class="chip" id="tApple" title="Hide Apple platform binaries (system daemons, Finder, Safari…)">Hide Apple</button>
    <button class="chip" id="tWrites" title="Only opens that ask for write access">Writes only</button>
  </div>
  <div class="grow"></div>
  <button class="btn live-only" id="pause" title="Pause / resume (Space)"></button>
  <button class="btn live-only" id="export" title="Download the events in the list as a CSV file">Export</button>
  <button class="btn live-only" id="clear" title="Clear the list">Clear</button>
</header>
<div class="banner" id="banner"></div>
<section class="stats">
  <div class="stat"><div class="k">Events / sec</div><div class="v" id="sRate">0</div></div>
  <div class="stat flagged-stat" title="Opens of private data by apps that aren't Apple's (medium or high)"><div class="k">Flagged</div><div class="v" id="sFlag">0</div></div>
  <div class="stat"><div class="k">Matching / sec</div><div class="v accent" id="sMatch">0</div></div>
  <div class="stat procs"><div class="k">Processes · 30s</div><div class="v" id="sProcs">0</div></div>
  <div class="stat"><div class="k">Total seen</div><div class="v" id="sTotal">0</div></div>
  <div class="stat warn" id="dropStat" hidden><div class="k">Dropped</div><div class="v" id="sDrop">0</div></div>
  <div class="sparkwrap">
    <div class="legend"><span><i class="l-all"></i>All</span><span><i class="l-match"></i>Matching</span><span id="peak">last 60s</span></div>
    <canvas id="spark"></canvas>
  </div>
</section>
<main id="liveView">
  <div class="table">
    <div class="thead"><div>Time</div><div>Process</div><div>Mode</div><div>File</div></div>
    <div class="list" id="list">
      <div id="spacer"></div>
      <div class="rows" id="rows"></div>
      <div class="empty" id="empty"><div class="ring" id="ring"></div><div id="emptyText">Waiting for events…</div></div>
    </div>
    <button class="newpill" id="newpill"></button>
  </div>
  <aside>
    <div class="card"><h3>Top processes <span>last 30s</span></h3><div class="top" id="topProcs"></div></div>
    <div class="card"><h3>Top files <span>last 30s</span></h3><div class="top" id="topFiles"></div></div>
    <div class="hint">Red and orange tags mark apps opening your private data. Click a row to see why. Click a process or file on the right to filter to it, or <b>⊘</b> to hide it.
      Prefix a term with <code>-</code> to exclude it. Press <code>Space</code> to pause, <code>/</code> to search.</div>
  </aside>
  <div class="drawer" id="drawer"></div>
</main>
<section id="insights" hidden>
  <div class="ins-wrap">
    <div class="ins-head">
      <div><div class="ins-title" id="insTitle">Collecting…</div><div class="ins-sub" id="insSub"></div></div>
      <div class="grow"></div>
      <button class="btn" id="insReset" title="Forget everything collected so far and start over">Start over</button>
    </div>
    <div id="insApps"></div>
    <div class="ins-low" id="insLow"></div>
    <div class="ins-note">Includes attempts macOS blocked. Can't see screen recording, keystrokes or network traffic.</div>
  </div>
</section>
<script>
(() => {
'use strict';
const ROW_H = 32, KEEP = 50000, WINDOW_MS = 30000, SPARK_N = 120, SPARK_MS = 500;
const $ = id => document.getElementById(id);
const list = $('list'), rowsEl = $('rows'), spacer = $('spacer'), emptyEl = $('empty');
const qInput = $('q'), drawer = $('drawer'), pill = $('newpill'), banner = $('banner'), pauseBtn = $('pause');

let all = [], view = [], seq = 0;
let home = '', status = { state: 'starting', message: '' }, connected = false;
let paused = false, pauseSeq = Infinity, pausedNew = 0;
let following = true, unseen = 0, selected = null, tab = 'live';
const buckets = new Map(), procSeen = new Map(), rowEls = new Map();

const prefs = { q: '', writes: false, hideApple: false, flagged: false };
try { Object.assign(prefs, JSON.parse(localStorage.getItem('esopen.prefs') || '{}')); } catch (_) {}
const savePrefs = () => { try { localStorage.setItem('esopen.prefs', JSON.stringify(prefs)); } catch (_) {} };

// ---------------------------------------------------------------- helpers
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const nf = new Intl.NumberFormat('en-US'), nfc = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const fmt = n => n >= 1e6 ? nfc.format(n) : nf.format(n);
const baseName = p => p.slice(p.lastIndexOf('/') + 1);
const tilde = p => (home && p.startsWith(home + '/')) ? '~' + p.slice(home.length) : p;
function splitPath(p) { const s = tilde(p || ''); const i = s.lastIndexOf('/'); return [s.slice(0, i + 1), s.slice(i + 1)]; }
const initial = n => ((n.match(/[A-Za-z0-9]/) || ['?'])[0]).toUpperCase();
const colors = new Map();
function color(name) {
  let c = colors.get(name);
  if (!c) {
    let h = 2166136261;
    for (let i = 0; i < name.length; i++) h = Math.imul(h ^ name.charCodeAt(i), 16777619);
    const hue = (h >>> 0) % 360;
    c = { bg: `hsl(${hue} 85% 95%)`, fg: `hsl(${hue} 50% 36%)`, bar: `hsl(${hue} 75% 62%)` };
    colors.set(name, c);
  }
  return c;
}
const avatar = (name, cls = 'av') => { const c = color(name); return `<span class="${cls}" style="background:${c.bg};color:${c.fg}">${esc(initial(name))}</span>`; };
const modeOf = ff => (ff & 1) && (ff & 2) ? ['RW', 'rw'] : (ff & 2) ? ['W', 'w'] : (ff & 1) ? ['R', 'r'] : ['–', 'n'];
const FLAGS = [[0x1, 'FREAD'], [0x2, 'FWRITE'], [0x4, 'O_NONBLOCK'], [0x8, 'O_APPEND'], [0x10, 'O_SHLOCK'], [0x20, 'O_EXLOCK'],
  [0x40, 'O_ASYNC'], [0x80, 'O_FSYNC'], [0x100, 'O_NOFOLLOW'], [0x200, 'O_CREAT'], [0x400, 'O_TRUNC'], [0x800, 'O_EXCL'],
  [0x8000, 'O_EVTONLY'], [0x20000, 'O_NOCTTY'], [0x100000, 'O_DIRECTORY'], [0x200000, 'O_SYMLINK'], [0x1000000, 'O_CLOEXEC']];
const HOT = new Set(['FWRITE', 'O_APPEND', 'O_CREAT', 'O_TRUNC']);
const TAG_LABEL = { messages: 'Messages', tcc: 'Privacy DB', browser: 'Passwords', wallets: 'Wallet', secrets: 'Keys', photos: 'Photos',
  keychain: 'Keychain', documents: 'Documents', icloud: 'iCloud', crossapp: "Other app's data", persist: 'Startup file' };
function clock(ts) {
  const d = new Date(ts), p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}<span class="ms">.${String(d.getMilliseconds()).padStart(3, '0')}</span>`;
}
function ago(ts) {
  const s = Math.max(0, (Date.now() - ts) / 1000);
  return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
}
function duration(ms) {
  const m = Math.floor(ms / 60000);
  return m < 1 ? 'under a minute' : m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`;
}

// ---------------------------------------------------------------- filtering
let tokens = [];
function compileQuery() {
  tokens = [];
  const re = /(-?)(?:(proc|path|pid):)?(?:"([^"]*)"?|(\S+))/g;
  let m;
  while ((m = re.exec(prefs.q))) {
    let val = (m[3] !== undefined ? m[3] : m[4]).trim().toLowerCase();
    if (home && val.startsWith('~')) val = home.toLowerCase() + val.slice(1);
    if (val) tokens.push({ neg: m[1] === '-', field: m[2] || '', val });
  }
}
function matches(e) {
  if (prefs.flagged && !(e.sev === 'high' || e.sev === 'medium')) return false;
  if (prefs.writes && !(e.ff & 2)) return false;
  if (prefs.hideApple && e.plat) return false;
  for (const t of tokens) {
    const hit = t.field === 'proc' ? e.lname.includes(t.val)
      : t.field === 'path' ? e.lpath.includes(t.val)
      : t.field === 'pid' ? String(e.pid) === t.val
      : e.lname.includes(t.val) || e.lpath.includes(t.val);
    if (hit === t.neg) return false;
  }
  return true;
}
function applyFilters() {
  prefs.q = qInput.value; savePrefs(); compileQuery();
  $('tWrites').classList.toggle('on', prefs.writes);
  $('tApple').classList.toggle('on', prefs.hideApple);
  $('tFlag').classList.toggle('on', prefs.flagged);
  rebuildView();
}
function addTerm(t) { qInput.value = (qInput.value.trim() + ' ' + t).trim(); applyFilters(); }
const quote = s => `"${s}"`;

// ---------------------------------------------------------------- data in
function ingest(events) {
  const now = Date.now(), b = Math.floor(now / SPARK_MS);
  let bucket = buckets.get(b);
  if (!bucket) buckets.set(b, bucket = [0, 0]);
  let added = 0;
  for (const e of events) {
    e.seq = ++seq; e.rx = now;
    e.name = baseName(e.exe || '') || '?';
    e.lname = e.name.toLowerCase(); e.lpath = (e.path || '').toLowerCase();
    all.push(e); procSeen.set(e.name, now); bucket[0]++;
    if (matches(e)) {
      bucket[1]++;
      if (paused) pausedNew++; else { view.push(e); added++; }
    }
  }
  if (all.length > KEEP * 1.2) trim();
  if (paused) updateState();
  if (!added || tab !== 'live') return;
  if (following) render(added <= 40 ? added : 0);
  else {
    spacer.style.height = view.length * ROW_H + 'px';
    list.scrollTop += added * ROW_H;   // keep what you're reading in place
    unseen += added; updatePill(); render();
  }
}
function trim() {
  const cut = all.length - KEEP, lastSeq = all[cut - 1].seq;
  all = all.slice(cut);
  let i = 0; while (i < view.length && view[i].seq <= lastSeq) i++;
  if (i) view = view.slice(i);
}
function rebuildView() {
  view = []; pausedNew = 0;
  for (const e of all) {
    if (!matches(e)) continue;
    if (e.seq <= pauseSeq) view.push(e); else pausedNew++;
  }
  for (const el of rowEls.values()) el.remove();
  rowEls.clear();
  list.scrollTop = 0; following = true; unseen = 0; updatePill();
  render(); computeTop(true); updateState();
}

// ---------------------------------------------------------------- virtual list
function makeRow(e, fresh) {
  const el = document.createElement('div');
  el.className = 'row' + (fresh ? ' fresh' : '') + (e.sev === 'high' || e.sev === 'medium' ? ' flag-' + e.sev : '');
  el._e = e;
  const [dir, file] = splitPath(e.path), [ml, mc] = modeOf(e.ff);
  el.innerHTML = `<div class="c-time">${clock(e.ts)}</div>`
    + `<div class="c-proc">${avatar(e.name)}<span class="pn">${esc(e.name)}</span><span class="pid">${e.pid == null ? '' : e.pid}</span></div>`
    + `<div><span class="badge ${mc}">${ml}</span></div>`
    + `<div class="c-path" title="${esc(e.path)}"><span class="dir">${esc(dir)}</span><span class="file">${esc(file)}</span>${e.sev ? `<span class="tag ${e.sev}">${esc(e.what || TAG_LABEL[e.tag] || e.tag)}</span>` : ''}</div>`;
  return el;
}
function render(slideBy = 0) {
  if (tab !== 'live') return;
  const n = view.length, now = Date.now();
  spacer.style.height = n * ROW_H + 'px';
  const top = list.scrollTop, h = list.clientHeight;
  const first = Math.max(0, Math.floor(top / ROW_H) - 4);
  const last = Math.min(n, Math.ceil((top + h) / ROW_H) + 4 + slideBy);
  rowsEl.classList.remove('anim');
  const keep = new Set(), placed = [];
  for (let i = first; i < last; i++) {
    const e = view[n - 1 - i];
    keep.add(e.seq);
    let el = rowEls.get(e.seq);
    if (!el) {
      el = makeRow(e, following && now - e.rx < 1200);
      rowEls.set(e.seq, el); rowsEl.appendChild(el);
      if (slideBy) el.style.transform = `translateY(${(i - slideBy) * ROW_H}px)`;  // start above, slide in
    }
    el.classList.toggle('sel', e === selected);
    placed.push(el, i * ROW_H);
  }
  for (const [k, el] of rowEls) if (!keep.has(k)) { el.remove(); rowEls.delete(k); }
  if (slideBy) { void rowsEl.offsetHeight; rowsEl.classList.add('anim'); }
  for (let j = 0; j < placed.length; j += 2) {
    const el = placed[j], y = placed[j + 1];
    if (el._y !== y) { el._y = y; el.style.transform = `translateY(${y}px)`; }
  }
  emptyEl.hidden = n > 0;
  if (!n) {
    const err = status.state === 'error';
    $('ring').style.display = all.length || err ? 'none' : '';
    $('emptyText').textContent = all.length ? (paused ? 'Paused' : 'No events match your filter')
      : err ? 'No events — see the message above' : 'Waiting for events…';
  }
}
list.addEventListener('scroll', () => {
  const f = list.scrollTop < ROW_H / 2;
  if (f && !following) { unseen = 0; updatePill(); }
  following = f;
  render();
}, { passive: true });
window.addEventListener('resize', () => render());
rowsEl.addEventListener('click', ev => { const r = ev.target.closest('.row'); if (r) openDrawer(r._e); });
function updatePill() {
  pill.classList.toggle('show', unseen > 0 && !following);
  if (unseen) pill.textContent = `↑  ${fmt(unseen)} new`;
}
pill.addEventListener('click', () => { list.scrollTop = 0; });

// ---------------------------------------------------------------- side panel
const EYE_OFF = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>';
function topItem(it) {
  const el = document.createElement('div');
  el.className = 'ti' + (it.kind === 'file' ? ' file' : '');
  el._key = it.key;
  const c = color(it.name);
  if (it.kind === 'proc') {
    el.innerHTML = `${avatar(it.name)}<div style="min-width:0"><div class="tr"><span class="tl">${esc(it.name)}</span><span class="tc"></span></div>`
      + `<div class="tb"><i style="background:${c.bar}"></i></div></div><button class="tx" title="Hide this process">${EYE_OFF}</button>`;
    el.title = `Show only ${it.name}`;
  } else {
    const [dir, file] = splitPath(it.key);
    el.innerHTML = `${avatar(it.name)}<div style="min-width:0"><div class="tr"><span class="tl">${esc(file || dir)}</span><span class="tc"></span></div>`
      + `<div class="tsub" title="${esc(it.key)}">&lrm;${esc(dir)}&lrm;</div><div class="tb"><i style="background:${c.bar}"></i></div></div>`
      + `<button class="tx" title="Hide this file">${EYE_OFF}</button>`;
    el.title = it.key;
  }
  return el;
}
function renderTop(box, items) {
  const max = items.length ? items[0].count : 1;
  const old = new Map([...box.children].map(el => [el._key, el]));
  items.forEach((it, idx) => {
    let el = old.get(it.key);
    if (el) old.delete(it.key); else el = topItem(it);
    el.querySelector('.tc').textContent = fmt(it.count);
    if (box.children[idx] !== el) box.insertBefore(el, box.children[idx] || null);
    const bar = el.querySelector('.tb i'), w = (it.count / max * 100).toFixed(1) + '%';
    requestAnimationFrame(() => { bar.style.width = w; });
  });
  for (const el of old.values()) el.remove();
}
function onTopClick(ev, kind) {
  const ti = ev.target.closest('.ti'); if (!ti) return;
  const neg = ev.target.closest('.tx') ? '-' : '';
  addTerm(neg + (kind === 'proc' ? 'proc:' + quote(ti._key) : 'path:' + quote(ti._key)));
}
$('topProcs').addEventListener('click', ev => onTopClick(ev, 'proc'));
$('topFiles').addEventListener('click', ev => onTopClick(ev, 'file'));
function computeTop(force) {
  const now = Date.now(), since = now - WINDOW_MS;
  let np = 0;
  for (const [k, t] of procSeen) { if (t < since) procSeen.delete(k); else np++; }
  tw.procs[1] = np;
  if ((paused && !force) || tab !== 'live') return;
  const pc = new Map(), fc = new Map();
  for (let i = view.length - 1, scanned = 0; i >= 0 && scanned < 40000; i--, scanned++) {
    const e = view[i];
    if (e.rx < since) break;
    const p = pc.get(e.name); if (p) p.count++; else pc.set(e.name, { count: 1 });
    const f = fc.get(e.path); if (f) f.count++; else fc.set(e.path, { count: 1, name: e.name });
  }
  const top = m => [...m.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);
  renderTop($('topProcs'), top(pc).map(([k, v]) => ({ key: k, name: k, count: v.count, kind: 'proc' })));
  renderTop($('topFiles'), top(fc).map(([k, v]) => ({ key: k, name: v.name, count: v.count, kind: 'file' })));
}

// ---------------------------------------------------------------- drawer
function openDrawer(e) {
  selected = e;
  const [dir, file] = splitPath(e.path);
  const d = new Date(e.ts);
  const flags = FLAGS.filter(([b]) => e.ff & b).map(([, n]) => `<span class="flag${HOT.has(n) ? ' hot' : ''}">${n}</span>`).join('') || '<span class="flag">none</span>';
  drawer.innerHTML = `
    <div class="dh">${avatar(e.name)}<div style="min-width:0"><div class="dn">${esc(e.name)}</div>
      <div class="ds">pid ${e.pid == null ? '?' : e.pid} · ${esc(e.user == null ? e.uid : e.user)}</div></div>
      <button class="x" data-act="close" title="Close (Esc)">×</button></div>
    ${e.sev ? flagBox(e) : ''}
    <div class="sec"><div class="lbl">File</div>
      <div class="pathbox"><span class="dir">${esc(dir)}</span><b>${esc(file)}</b></div>
      <button class="mini" data-act="copy">Copy full path</button></div>
    <div class="sec"><div class="lbl">Access requested</div><div class="flags">${flags}</div>
      <div class="mono faint">fflag 0x${(e.ff >>> 0).toString(16).padStart(8, '0')}</div></div>
    <dl class="kv">
      <dt>Time</dt><dd>${esc(d.toLocaleDateString())} ${clock(e.ts)}</dd>
      <dt>Executable</dt><dd class="mono">${esc(e.exe)}</dd>
      <dt>Signing ID</dt><dd class="mono">${esc(e.sid || '—')}</dd>
      <dt>Team ID</dt><dd class="mono">${esc(e.team || '—')}</dd>
      <dt>Apple binary</dt><dd>${e.plat ? 'Yes' : 'No'}</dd>
      <dt>Parent PID</dt><dd class="mono">${e.ppid == null ? '—' : e.ppid}</dd>
      <dt>User</dt><dd>${esc(e.user)} <span class="faint">(uid ${e.uid})</span></dd>
    </dl>
    <div class="actions">
      <button class="btn primary" data-act="only-proc">Show only ${esc(e.name)}</button>
      <button class="btn" data-act="hide-proc">Hide ${esc(e.name)}</button>
      <button class="btn" data-act="only-file">Show only this file</button>
    </div>`;
  drawer.classList.add('open');
  render();
}
function closeDrawer() { selected = null; drawer.classList.remove('open'); render(); }
drawer.addEventListener('click', ev => {
  const b = ev.target.closest('[data-act]'); if (!b || !selected) return;
  const e = selected, act = b.dataset.act;
  if (act === 'close') return closeDrawer();
  if (act === 'copy') {
    navigator.clipboard.writeText(e.path).then(() => { b.textContent = 'Copied ✓'; setTimeout(() => { b.textContent = 'Copy full path'; }, 1200); });
    return;
  }
  closeDrawer();
  if (act === 'only-proc') addTerm('proc:' + quote(e.name));
  if (act === 'hide-proc') addTerm('-proc:' + quote(e.name));
  if (act === 'only-file') addTerm('path:' + quote(e.path));
});

// ---------------------------------------------------------------- export
function exportCsv() {
  const rows = [['time', 'pid', 'process', 'executable', 'team_id', 'apple', 'user', 'mode', 'fflag', 'flag', 'path']];
  for (const e of view) rows.push([new Date(e.ts).toISOString(), e.pid, e.name, e.exe, e.team || '', e.plat ? 'yes' : 'no',
    e.user, modeOf(e.ff)[0], '0x' + (e.ff >>> 0).toString(16), e.sev ? e.sev + ':' + e.tag : '', e.path]);
  const cell = v => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const blob = new Blob([rows.map(r => r.map(cell).join(',')).join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `file-opens-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ---------------------------------------------------------------- insights
let ins = null;
const expanded = new Set();
const RANK = { high: 0, medium: 1, low: 2 };
const PLACE_WHAT = { messages: 'messages & mail', tcc: 'privacy settings', browser: 'browser passwords', wallets: 'crypto wallets',
  secrets: 'SSH & API keys', photos: 'photos', keychain: 'keychain', documents: 'documents', icloud: 'iCloud files' };
const WHY = {
  'place:messages': 'Reading these needs Full Disk Access. If you didn’t expect this app to touch your messages or mail, remove its Full Disk Access.',
  'place:tcc': 'Apps sometimes read this to check whether they have Full Disk Access. An app you don’t recognize doing it is worth a look.',
  'place:browser': 'Saved logins and cookies let someone sign in as you. Only your browser should normally open these.',
  'place:wallets': 'Crypto wallets are a top target for Mac malware. Only your wallet app and browser should open these.',
  'place:secrets': 'These files can unlock your servers, code and cloud accounts.',
  'place:photos': 'Only photo and backup apps should need your photo library.',
  'place:keychain': 'Apps often open the keychain file just to sign you in. Usually fine.',
  'place:documents': 'Normal for editors and tools you use on your own files.',
  'place:icloud': 'Normal for apps that open or sync your iCloud files.',
  'crossapp': 'Apps normally stay inside their own folders.',
  'location': 'Real apps usually live in /Applications. Programs running from hidden or temporary folders are a common malware trick.',
  'persist': 'Startup files make programs run automatically. Make sure you recognize this change.',
};
const listJoin = a => a.length < 2 ? (a[0] || '') : a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1];
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const areaName = key => key.split('/').pop();

function flagBox(e) {
  const what = e.tag === 'persist' ? `${e.name} changed a file that makes programs start automatically.`
    : e.tag === 'crossapp' ? `${e.name} opened another app's private data.`
    : `${e.name} isn't an Apple program, and it opened your ${e.phrase || PLACE_WHAT[e.tag] || 'private data'}.`;
  const why = WHY[e.tag === 'persist' || e.tag === 'crossapp' ? e.tag : 'place:' + e.tag] || '';
  return `<div class="flagbox ${e.sev}"><b>Why this is flagged</b>${esc(what)} ${esc(why)}</div>`;
}

// One entry per program, combining everything it was flagged for.
function groupApps(findings) {
  const by = new Map();
  for (const f of findings) {
    let g = by.get(f.exe);
    if (!g) by.set(f.exe, g = { exe: f.exe, name: f.name, signer: f.signer, team: f.team, signed: f.signed, sev: 'low',
      count: 0, last: 0, cross: [], loc: null, labels: new Map(), every: null });
    if (RANK[f.sev] < RANK[g.sev]) g.sev = f.sev;
    if (f.kind !== 'location') g.count += f.count;
    g.last = Math.max(g.last, f.last);
    if (f.kind === 'crossapp') g.cross.push(f);
    if (f.kind === 'location') g.loc = f;
    if (f.every && (!g.every || f.every < g.every)) g.every = f.every;
    for (const [phrase, rank, count, ex] of f.labels || []) {
      const x = g.labels.get(phrase);
      if (x) x.count += count; else g.labels.set(phrase, { phrase, rank, count, ex });
    }
  }
  const apps = [...by.values()];
  for (const g of apps) g.list = [...g.labels.values()].sort((a, b) => a.rank - b.rank);
  const worst = g => g.list.length ? g.list[0].rank : 99;
  return apps.sort((a, b) => RANK[a.sev] - RANK[b.sev] || worst(a) - worst(b) || b.count - a.count);
}
const STARTUP = new Set(['login items', 'shell startup file']);
const fmtEvery = s => s < 90 ? `${Math.round(s)} seconds` : s < 5400 ? `${Math.round(s / 60)} minutes` : `${Math.round(s / 3600)} hours`;
const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
// "Acme Notes is reading your iMessages": the single most alarming thing, in words.
function appHeadline(g) {
  const name = `<b>${esc(g.name)}</b>`, first = g.list.find(l => !STARTUP.has(l.phrase));
  if (first) return `${name} ${g.every ? 'is reading' : 'opened'} your <em>${esc(first.phrase)}</em>`;
  if (g.list.some(l => l.phrase === 'login items')) return `${name} <em>set itself up to start at login</em>`;
  if (g.list.length) return `${name} <em>edited your shell startup file</em>`;
  if (g.cross.length) return `${name} opened <em>other apps' private data</em>`;
  return `${name} runs from <em>an unusual folder</em>${g.signed ? '' : ' with no developer signature'}`;
}
// "Every 15 seconds · also your email, contacts and privacy settings"
function appSubline(g) {
  const things = g.list.filter(l => !STARTUP.has(l.phrase)).map(l => l.phrase), rest = things.slice(1), parts = [];
  if (g.every) parts.push(`every ${fmtEvery(g.every)}`);
  if (rest.length) parts.push('also your ' + listJoin(rest.length > 4 ? [...rest.slice(0, 3), `${rest.length - 3} more`] : rest));
  if (things.length && g.list.some(l => l.phrase === 'login items')) parts.push('set itself up to start at login');
  if (g.cross.length && g.list.length) parts.push(`read ${listJoin(g.cross.map(c => areaName(c.key)))}'s data`);
  return cap(parts.join(' · '));
}
function whoLine(g) {
  const signed = g.signer && !/^(No developer|Not signed)/.test(g.signer);
  const who = signed ? `Made by ${esc(g.signer.replace(/\s*\([A-Z0-9]{10}\)$/, ''))}`
    : g.team ? `Team ID ${esc(g.team)}` : '<span class="bad">Not signed by any developer</span>';
  const dir = tilde(g.exe.slice(0, g.exe.lastIndexOf('/') + 1));
  const where = g.loc ? ` · runs from <span class="${g.loc.sev === 'high' ? 'bad' : ''}">${esc(dir)}</span>` : '';
  return who + where;
}
function appRow(g) {
  const open = expanded.has(g.exe), sub = appSubline(g);
  let detail = '';
  if (open) {
    const files = [...g.list.map(l => [l.phrase, l.ex]), ...g.cross.map(c => [areaName(c.key) + ' data', c.examples[0]])];
    detail = `<div class="ar-detail">`
      + (files.length ? `<div class="ar-files">${files.map(([l, ex]) => `<div><b>${esc(cap(l))}</b><span>${esc(tilde(ex || ''))}</span></div>`).join('')}</div>` : '')
      + `<button class="linkbtn" data-show="${esc(g.name)}">Show in live view →</button></div>`;
  }
  return `<div class="approw ${g.sev}${open ? ' open' : ''}" data-exe="${esc(g.exe)}">
    <div class="ar-top">${avatar(g.name)}<div class="ar-text">
        <div class="ar-head">${appHeadline(g)}</div>
        ${sub ? `<div class="ar-sub">${esc(sub)}</div>` : ''}
        <div class="ar-who">${whoLine(g)}</div></div>
      <svg class="ar-chev" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg></div>
    ${detail}</div>`;
}
function renderInsights() {
  if (!ins) return;
  const apps = groupApps(ins.findings);
  const top = apps.filter(g => g.sev !== 'low'), low = apps.filter(g => g.sev === 'low');
  const t = $('insTitle'), watching = `Watching for ${duration(Date.now() - ins.since)}.`;
  if (top.some(g => g.sev === 'high')) {
    t.className = 'ins-title bad';
    t.innerHTML = `<span class="vi">!</span>${plural(top.length, 'app')} ${top.length === 1 ? 'is' : 'are'} touching your private data`;
  } else if (top.length) {
    t.className = 'ins-title warn';
    t.innerHTML = `<span class="vi">?</span>${plural(top.length, 'app')} worth a glance`;
  } else {
    t.className = 'ins-title ok';
    t.innerHTML = '<span class="vi">✓</span>Nothing worrying so far';
  }
  $('insSub').textContent = top.length ? `Click an app to see what it opened. ${watching}`
    : `${watching} Keep it running while you use your Mac. Some apps only act every few minutes.`;
  $('insApps').innerHTML = top.length ? `<div class="applist">${top.map(appRow).join('')}</div>` : '';
  $('insLow').textContent = low.length ? `Also seen, and normal-looking: ${listJoin(low.map(g => g.name))}.` : '';
}
async function loadInsights() {
  try { const r = await fetch('/insights'); ins = await r.json(); } catch (_) { return; }
  const apps = groupApps(ins.findings);
  const hi = apps.filter(g => g.sev === 'high').length, med = apps.filter(g => g.sev === 'medium').length;
  const badge = $('insBadge');
  badge.hidden = !(hi || med);
  badge.textContent = hi + med;
  badge.classList.toggle('med', !hi);
  if (tab === 'insights') renderInsights();
}
$('insApps').addEventListener('click', ev => {
  const b = ev.target.closest('[data-show]');
  if (b) { qInput.value = 'proc:' + quote(b.dataset.show); prefs.hideApple = false; prefs.flagged = false; setTab('live'); applyFilters(); return; }
  if (ev.target.closest('.ar-detail')) return;  // leave the details selectable
  const row = ev.target.closest('.approw');
  if (row) { const k = row.dataset.exe; expanded.has(k) ? expanded.delete(k) : expanded.add(k); renderInsights(); }
});
$('insReset').addEventListener('click', async () => {
  await fetch('/insights/reset', { method: 'POST' }).catch(() => {});
  loadInsights();
});
function setTab(t) {
  tab = t;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  document.body.classList.toggle('ins', t === 'insights');
  $('liveView').hidden = t !== 'live';
  $('insights').hidden = t !== 'insights';
  if (t === 'insights') { if (selected) closeDrawer(); loadInsights(); }
  else { for (const el of rowEls.values()) el.remove(); rowEls.clear(); render(); computeTop(true); }
}
document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));

// ---------------------------------------------------------------- header, state
const PAUSE_ICON = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="4" width="5" height="16" rx="1.5"/><rect x="14" y="4" width="5" height="16" rx="1.5"/></svg>';
const PLAY_ICON = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M7 4.5v15a1 1 0 0 0 1.5.86l12.5-7.5a1 1 0 0 0 0-1.72L8.5 3.64A1 1 0 0 0 7 4.5z"/></svg>';
function setPaused(p) {
  paused = p;
  if (p) { pauseSeq = seq; pausedNew = 0; updateState(); }
  else { pauseSeq = Infinity; rebuildView(); }
}
function updateState() {
  let label, cls;
  if (!connected) { label = 'Disconnected'; cls = ''; }
  else if (status.state === 'error') { label = 'Error'; cls = 'err'; }
  else if (paused) { label = pausedNew ? `Paused · ${fmt(pausedNew)} new` : 'Paused'; cls = 'paused'; }
  else if (status.state === 'demo') { label = 'Live · demo data'; cls = 'demo'; }
  else if (status.state === 'live') { label = 'Live'; cls = 'live'; }
  else { label = 'Starting…'; cls = ''; }
  $('dot').className = 'dot ' + cls;
  $('stateLabel').textContent = label;
  pauseBtn.innerHTML = paused ? `${PLAY_ICON}<span>Resume</span>` : `${PAUSE_ICON}<span>Pause</span>`;
  pauseBtn.classList.toggle('resume', paused);

  let b = '', bc = '';
  if (!connected) { b = 'Lost connection to esopen. If you stopped it, run <code>python3 esopen.py</code> again. Retrying…'; bc = 'muted'; }
  else if (status.state === 'error') { b = esc(status.message).replace(/`([^`]+)`/g, '<code>$1</code>'); bc = 'err'; }
  else if (status.state === 'demo') { b = 'Showing <b>demo data</b>. To watch your own Mac, stop this and run <code>python3 esopen.py</code> without <code>--demo</code>.'; bc = 'info'; }
  banner.className = 'banner' + (b ? ' show ' + bc : '');
  banner.innerHTML = b;
}
pauseBtn.addEventListener('click', () => setPaused(!paused));
$('export').addEventListener('click', exportCsv);
$('clear').addEventListener('click', () => {
  all = []; procSeen.clear(); if (selected) closeDrawer();
  if (paused) pauseSeq = seq;
  rebuildView();
});
$('tWrites').addEventListener('click', () => { prefs.writes = !prefs.writes; applyFilters(); });
$('tApple').addEventListener('click', () => { prefs.hideApple = !prefs.hideApple; applyFilters(); });
$('tFlag').addEventListener('click', () => { prefs.flagged = !prefs.flagged; applyFilters(); });
let qTimer;
qInput.addEventListener('input', () => { clearTimeout(qTimer); qTimer = setTimeout(applyFilters, 120); });
document.addEventListener('keydown', ev => {
  const inInput = ev.target === qInput;
  if (tab !== 'live') return;
  if (ev.key === '/' && !inInput) { ev.preventDefault(); qInput.focus(); qInput.select(); }
  else if (ev.key === 'Escape') { if (selected) closeDrawer(); else if (inInput) qInput.blur(); }
  else if (ev.key === ' ' && !inInput && ev.target.tagName !== 'BUTTON') { ev.preventDefault(); setPaused(!paused); }
});

// ---------------------------------------------------------------- stats + sparkline
const tw = { flag: [0, 0, $('sFlag')], rate: [0, 0, $('sRate')], match: [0, 0, $('sMatch')], procs: [0, 0, $('sProcs')], total: [0, 0, $('sTotal')], drop: [0, 0, $('sDrop')] };
function computeRates() {
  const cur = Math.floor(Date.now() / SPARK_MS);
  let a = 0, m = 0;
  for (let i = 1; i <= 4; i++) { const b = buckets.get(cur - i); if (b) { a += b[0]; m += b[1]; } }
  tw.rate[1] = a / 2; tw.match[1] = m / 2;
}
function drawSpark() {
  const cv = $('spark'), dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight;
  if (!w || !h) return;
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); }
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
  const now = Date.now(), cur = Math.floor(now / SPARK_MS), frac = (now % SPARK_MS) / SPARK_MS;
  const A = [], M = [];
  for (let i = SPARK_N; i >= 1; i--) { const b = buckets.get(cur - i); A.push(b ? b[0] : 0); M.push(b ? b[1] : 0); }
  const peak = Math.max(...A);
  const max = Math.max(4, peak) * 1.18, step = w / (SPARK_N - 2);
  const x = i => (i - frac) * step, y = v => h - 1.5 - v / max * (h - 5);
  const line = arr => { ctx.beginPath(); arr.forEach((v, i) => i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))); };
  const area = (arr, top, bottom) => {
    line(arr); ctx.lineTo(x(arr.length - 1), h); ctx.lineTo(x(0), h); ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, h); g.addColorStop(0, top); g.addColorStop(1, bottom); ctx.fillStyle = g; ctx.fill();
  };
  ctx.lineJoin = 'round'; ctx.lineCap = 'round';
  area(A, 'rgba(148,163,184,.20)', 'rgba(148,163,184,0)');
  line(A); ctx.strokeStyle = '#cfd6e0'; ctx.lineWidth = 1.25; ctx.stroke();
  area(M, 'rgba(37,99,235,.13)', 'rgba(37,99,235,0)');
  line(M); ctx.strokeStyle = '#2563eb'; ctx.lineWidth = 1.75; ctx.stroke();
  const lx = x(SPARK_N - 1), ly = y(M[SPARK_N - 1]);
  ctx.beginPath(); ctx.arc(lx, ly, 5, 0, Math.PI * 2); ctx.fillStyle = 'rgba(37,99,235,.15)'; ctx.fill();
  ctx.beginPath(); ctx.arc(lx, ly, 2.5, 0, Math.PI * 2); ctx.fillStyle = '#2563eb'; ctx.fill();
  const pk = `last 60s · peak ${fmt(peak * 1000 / SPARK_MS)}/s`;
  if ($('peak').textContent !== pk) $('peak').textContent = pk;
  for (const k of buckets.keys()) if (k < cur - SPARK_N - 2) buckets.delete(k);
}
function frame() {
  for (const k in tw) {
    const t = tw[k];
    t[0] += (t[1] - t[0]) * 0.14;
    if (Math.abs(t[1] - t[0]) < 0.5) t[0] = t[1];
    const s = fmt(Math.round(t[0]));
    if (t[2].textContent !== s) t[2].textContent = s;
  }
  drawSpark();
  requestAnimationFrame(frame);
}

// ---------------------------------------------------------------- connection
function connect() {
  const es = new EventSource('/events');
  es.onopen = () => { connected = true; updateState(); };
  es.onerror = () => {
    connected = false; updateState();
    // The browser stops retrying in some cases (e.g. server down when the page loaded); reconnect ourselves.
    if (es.readyState === EventSource.CLOSED) setTimeout(connect, 2000);
  };
  es.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.type === 'batch') {
      tw.total[1] = m.total; tw.flag[1] = m.flagged || 0;
      const dropped = (m.esDropped || 0) + (m.uiDropped || 0);
      tw.drop[1] = dropped; $('dropStat').hidden = !dropped;
      ingest(m.events);
    } else if (m.type === 'hello' || m.type === 'status') {
      if (m.type === 'hello') { home = m.home || ''; compileQuery(); }
      connected = true;
      status = { state: m.state, message: m.message };
      updateState(); render();
    }
  };
}

qInput.value = prefs.q;
compileQuery();
$('tWrites').classList.toggle('on', prefs.writes);
$('tApple').classList.toggle('on', prefs.hideApple);
$('tFlag').classList.toggle('on', prefs.flagged);
updateState(); render();
setInterval(computeRates, 250);
setInterval(computeTop, 1000);
setInterval(loadInsights, 3000);
requestAnimationFrame(frame);
connect();
loadInsights();
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
