#!/usr/bin/env python3
"""Stage 6 - in-game overlay cosmetics.

The overlay bundle is NOT inside app.asar. The launcher materialises it at

    %USERPROFILE%\\.lunarclient\\ui\\<sha1>\\static\\index.js

and the sibling .sha1 holds the directory's own 40-hex name rather than a content
digest of index.js, so rewriting the bundle does not trip the integrity check.
Because it is a plain file and not an asar entry, there is no per-file size/offset
header to preserve - these edits are free to change length.

Two cosmetic faults are addressed, both of them downstream of an authentication
cause that is server-side and therefore not locally satisfiable: the game asks
Mojang to join a serverId with a fabricated access token, Mojang answers 401, and
Lunar turns that into an endless popup/reconnect cycle.

  auth-toast-filter  drop the auth popup family before it reaches the toast store.
  connecting-label   stop the account chip from showing "Connecting..." whenever the
                     asset client sits in DISCONNECTED, which it always will here.
  *-invalid-row      three separate rows route a stale invalid flag to addAccount(),
                     which is the launcher's Microsoft login. All three now select.

Usage: python patch-overlay.py [--status|--apply|--revert]
"""

import argparse
import hashlib
import json
import os
import shutil
import sys

# The overlay bundle lives under the profile root, not under LOCALAPPDATA - the same
# tree that holds settings/game/accounts.json.
UI_DIR = os.path.join(os.path.expanduser("~"), ".lunarclient", "ui")
BUNDLE_NAME = "index.js"
BACKUP_NAME = "index.js.pristine"

# Drop toasts whose message is one of lunar-lang's auth popups. Every entry below is
# a verbatim value from lang/lunar/en_US.json under popups.{auth,refresh_auth,add_account}.
# The test short-circuits to True (swallow) before the dispatch on the right of ||.
AUTH_TOAST_RE = (
    r"/(Try restarting your game|authentication servers are currently not reachable"
    r"|must have the launcher open to signin|Unknown error occured while"
    r"|banned from playing online|Multiplayer is disabled|not purchased Minecraft"
    r"|Accounts file was empty)/"
)

SITES = [
    {
        "name": "auth-toast-filter",
        "note": "game-originated auth popups are swallowed before sendNotification",
        "find": "S2(O.notification,l=>{W2.dispatch(B31(l))})",
        "repl": (
            "S2(O.notification,l=>{var m=l&&typeof l.message==\"string\"?l.message:\"\";"
            + AUTH_TOAST_RE
            + ".test(m)||W2.dispatch(B31(l))})"
        ),
    },
    {
        "name": "connecting-label",
        "note": "only E==null (no account) shows Connecting; DISCONNECTED always will here",
        "find": (
            "connecting:!(s||l!=null&&l.loading)&&j==M3.DISCONNECTED||E==null"
        ),
        "repl": "connecting:E==null",
    },
    # An account the game has flagged invalid is one whose refresh the launcher could not
    # complete. Stock behaviour routes that click to addAccount(), which in the launcher is
    # the Microsoft device-code flow - so a stale flag turns "switch to this account" into
    # "sign in to Microsoft". The account still carries a valid access token here, so the
    # correct action is the same one a healthy row takes: select it.
    {
        "name": "switcher-invalid-row",
        "note": "account switcher row: invalid behaves like a valid row",
        "find": "if(C.invalid==!0){a==null||a(),l==null||l();return}",
        "repl": "if(C.invalid==!0){a==null||a(),(h=C.onMouseDown)==null||h.call(C);return}",
    },
    {
        "name": "chip-popover-invalid",
        "note": "account chip popover row -> selectAccount",
        "find": "if(r1.invalid==!0){O.accounts.addAccount();return}",
        "repl": "if(r1.invalid==!0){O.accounts.selectAccount(r1);return}",
    },
    {
        "name": "manager-popover-invalid",
        "note": "manage accounts popover row -> selectAccount",
        "find": "if(a.invalid==!0){O.accounts.addAccount();return}",
        "repl": "if(a.invalid==!0){O.accounts.selectAccount(a);return}",
    },
]


def locate_bundle():
    if not os.path.isdir(UI_DIR):
        return None, "ui dir missing: " + UI_DIR
    candidates = []
    for entry in sorted(os.listdir(UI_DIR)):
        path = os.path.join(UI_DIR, entry, "static", BUNDLE_NAME)
        if os.path.isfile(path):
            candidates.append(path)
    if not candidates:
        return None, "no " + BUNDLE_NAME + " under " + UI_DIR
    if len(candidates) > 1:
        return None, "ambiguous bundles: " + ", ".join(candidates)
    return candidates[0], None


def sha16(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def read_text(path):
    # The bundle is emitted as UTF-8; reading bytes and decoding strictly as utf-8 keeps
    # any escaped or multi-byte literal byte-exact across the round trip.
    return open(path, "rb").read().decode("utf-8")


def write_text(path, text):
    open(path, "wb").write(text.encode("utf-8"))


def site_state(text, site):
    found = text.count(site["find"])
    applied = text.count(site["repl"])
    if applied == 1 and found == 0:
        status = "APPLIED"
    elif found == 1 and applied == 0:
        status = "pending"
    elif found == 0 and applied == 0:
        status = "MISSING"
    else:
        status = "AMBIGUOUS"
    return status


def cmd_status(path):
    text = read_text(path)
    print("bundle :", path)
    print("bytes  :", os.path.getsize(path))
    print("sha256 :", sha16(path))
    print("backup :", "present" if os.path.isfile(os.path.join(os.path.dirname(path), BACKUP_NAME)) else "ABSENT")
    print()
    bad = 0
    for site in SITES:
        status = site_state(text, site)
        if status not in ("APPLIED",):
            bad += 1
        print("  %-18s %-10s %s" % (site["name"], status, site["note"]))
    print()
    print("result :", "clean" if not bad else "%d site(s) not applied" % bad)
    return 0 if not bad else 1


def cmd_apply(path):
    directory = os.path.dirname(path)
    backup = os.path.join(directory, BACKUP_NAME)
    if not os.path.isfile(backup):
        shutil.copy2(path, backup)
        print("backup ->", backup)
    else:
        # Always work from the pristine bytes so the run is idempotent.
        shutil.copy2(backup, path)
        print("restored from backup first (idempotent)")

    text = read_text(path)
    errors = []
    for site in SITES:
        found = text.count(site["find"])
        applied = text.count(site["repl"])
        if applied == 1 and found == 0:
            print("  %-18s already applied" % site["name"])
            continue
        if found != 1:
            errors.append("%s: %d occurrence(s) of find, want 1" % (site["name"], found))
            continue
        text = text.replace(site["find"], site["repl"], 1)
        print("  %-18s applied (+%d bytes)  %s"
              % (site["name"], len(site["repl"]) - len(site["find"]), site["note"]))

    if errors:
        for err in errors:
            print("  ERROR", err)
        return 2

    write_text(path, text)
    print()
    print("wrote", os.path.getsize(path), "bytes; sha256", sha16(path))
    return 0


def cmd_revert(path):
    directory = os.path.dirname(path)
    backup = os.path.join(directory, BACKUP_NAME)
    if not os.path.isfile(backup):
        print("no backup at", backup)
        return 2
    shutil.copy2(backup, path)
    print("reverted ->", path, os.path.getsize(path), "bytes; sha256", sha16(path))
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description="Stage 6 overlay cosmetics")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--revert", action="store_true")
    args = parser.parse_args(argv)

    path, err = locate_bundle()
    if err:
        print("ERROR:", err)
        return 2

    if args.revert:
        return cmd_revert(path)
    if args.apply:
        return cmd_apply(path)
    return cmd_status(path)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
