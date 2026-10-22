"""End-to-end test of the Madium installer against a scratch copy.

Runs Install-MadiumPatch.ps1 exactly the way install.cmd does, but against a copy of
the binary in a temp directory and on its own port, then checks that:

  * the installer exits 0
  * all eight sites are patched on disk
  * the backup holds the pristine bytes
  * the keypair and the public key were written
  * the endpoint process is alive and answers
  * a second install (re-patch) also succeeds
  * uninstall restores the pristine binary and stops the endpoint
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
INSTALLER = os.path.join(REPO, "Install-MadiumPatch.ps1")
PORT = 8791
STATE = os.path.join(tempfile.gettempdir(), "madium_install_state")

PRISTINE_SHA = "ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a"

failures = []


def check(label, condition, detail=""):
    mark = "PASS" if condition else "FAIL"
    if not condition:
        failures.append(label)
    print("  [{}] {}{}".format(mark, label, ("  -> " + detail) if detail else ""))
    return condition


def run_installer(target, extra=None, port=None):
    args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", INSTALLER, "-Target", target, "-Port", str(port or PORT),
            "-StateDir", STATE]
    if extra:
        args += extra
    result = subprocess.run(args, capture_output=True, text=True, timeout=180)
    if result.returncode != 0 and result.stderr.strip():
        print("   stderr: " + result.stderr.strip()[:400])
    return result


def main():
    scratch = tempfile.mkdtemp(prefix="madium_install_")
    target = os.path.join(scratch, "Madium.exe")
    shutil.rmtree(STATE, ignore_errors=True)

    # The starting point has to be the pristine build, so pick the copy whose
    # hash actually matches - a file of the right length can still be patched.
    import hashlib
    sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
    sources = [r"C:\Users\ezan\Documents\madium\madium\Bin\Madium.exe.bak",
               r"C:\Users\ezan\Documents\madium\madium\Bin\Madium.exe",
               r"C:\Users\ezan\Documents\madium\_t\Madium.pristine.exe"]
    pristine_src = None
    for src in sources:
        if os.path.exists(src) and sha(src) == PRISTINE_SHA:
            pristine_src = src
            break
    if pristine_src is None:
        print("  (no pristine copy found, skipping)")
        return 1
    shutil.copy2(pristine_src, target)

    print("=== A. scratch target ===")
    print("   %s" % target)
    print("   sha256 %s" % sha(target))

    print("\n=== B. run the installer (as install.cmd does) ===")
    result = run_installer(target)
    for line in (result.stdout or "").splitlines():
        print("   | " + line)
    if result.stderr.strip():
        print("   stderr: " + result.stderr.strip()[:300])
    check("installer exits 0", result.returncode == 0, "exit={}".format(result.returncode))

    print("\n=== C. every site patched on disk ===")
    sites = {
        "expiry": (0x22231E, b"\x90\x90"),
        "hwid":   (0x222207, b"\xEB\x2E"),
        "clock":  (0x22227A, b"\xEB\x71"),
        "status": (0x21EB1F, b"\xEB\x28"),
        "sig1":   (0x21E945, b"\x90\x90"),
        "sig2":   (0x2221D1, b"\x90\x90"),
    }
    data = open(target, "rb").read()
    for name, (off, want) in sites.items():
        got = data[off:off + 2]
        check("site {} patched".format(name), got == want,
              "{} != {}".format(got.hex(), want.hex()))
    check("auth host redirected",
          data[0xB2FB94:0xB2FB94 + 21] == ("http://127.0.0.1:{}".format(PORT)).encode(),
          data[0xB2FB94:0xB2FB94 + 26].split(b"\x00")[0].decode("ascii", "replace"))
    check("host length field updated",
          int.from_bytes(data[0xB2FBB8:0xB2FBC0], "little") == 21,
          str(int.from_bytes(data[0xB2FBB8:0xB2FBC0], "little")))
    check("pinned key replaced", data[0xB2FF16:0xB2FF16 + 32] !=
          bytes.fromhex("23572ca500262e26595b8667682fcaecb2a33264e1b242c11684333f46080125"))

    print("\n=== D. backup + state ===")
    backup = target + ".bak"
    check("backup exists", os.path.exists(backup))
    if os.path.exists(backup):
        check("backup holds the pristine bytes", sha(backup) == PRISTINE_SHA, sha(backup))
    check("keypair written", os.path.exists(os.path.join(STATE, "keypair.json")))
    check("public key written", os.path.exists(os.path.join(STATE, "keypair.pub")))
    check("no keypair leaked into the repo",
          not os.path.exists(os.path.join(REPO, "state", "keypair.json")))

    print("\n=== E. endpoint answers ===")
    time.sleep(2)
    ok = False
    try:
        with urllib.request.urlopen("http://127.0.0.1:{}/".format(PORT), timeout=6) as r:
            ok = r.status == 200
    except Exception as exc:
        print("   (endpoint error: %s)" % exc)
    check("endpoint is serving", ok)

    print("\n=== F. re-run the installer (re-patch over a patched binary) ===")
    result2 = run_installer(target)
    check("second install exits 0", result2.returncode == 0,
          "exit={}".format(result2.returncode))
    check("still all sites patched",
          all(open(target, "rb").read()[o:o + 2] == w for o, w in sites.values()))

    print("\n=== F2. re-patch onto a DIFFERENT port (host was already redirected) ===")
    result2b = run_installer(target, port=PORT + 1)
    for line in (result2b.stdout or "").splitlines()[-6:]:
        print("   | " + line)
    check("re-patch to a new port exits 0", result2b.returncode == 0,
          "exit={}".format(result2b.returncode))
    data2 = open(target, "rb").read()
    check("host now points at the new port",
          data2[0xB2FB94:0xB2FB94 + 21] == ("http://127.0.0.1:{}".format(PORT + 1)).encode(),
          data2[0xB2FB94:0xB2FB94 + 26].split(b"\x00")[0].decode("ascii", "replace"))
    check("host length field matches the new port",
          int.from_bytes(data2[0xB2FBB8:0xB2FBC0], "little") == len("http://127.0.0.1:{}".format(PORT + 1)))
    # put it back on the primary port for the remaining steps
    restore = run_installer(target, port=PORT)
    check("re-patch back to the primary port exits 0", restore.returncode == 0,
          "exit={}".format(restore.returncode))

    print("\n=== G. uninstall ===")
    result3 = run_installer(target, ["-Uninstall"])
    for line in (result3.stdout or "").splitlines():
        print("   | " + line)
    check("uninstall exits 0", result3.returncode == 0, "exit={}".format(result3.returncode))
    check("pristine binary restored", sha(target) == PRISTINE_SHA, sha(target))
    check("keypair removed", not os.path.exists(os.path.join(STATE, "keypair.json")))
    alive = False
    try:
        with urllib.request.urlopen("http://127.0.0.1:{}/".format(PORT), timeout=4) as r:
            alive = r.status == 200
    except Exception:
        alive = False
    check("endpoint stopped", not alive)

    shutil.rmtree(scratch, ignore_errors=True)

    print("\n" + "=" * 68)
    if failures:
        print("FAILED {}: {}".format(len(failures), ", ".join(failures)))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
