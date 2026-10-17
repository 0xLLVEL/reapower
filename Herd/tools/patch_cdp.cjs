"use strict";
/*
 * herd-pro / patch_cdp.cjs — runtime path, no archive is touched.
 *
 * Requires node (Herd's own RuntimeAsNode fuse means Herd.exe can run this too)
 * and a Herd started with an inspector:
 *
 *   Herd.exe --inspect=9333
 *   node patch_cdp.cjs --port 9333
 *
 * Herd's main bundle ships as V8 cached-data bytecode (out/main/index.jsc), so
 * there is nothing to decompile. LicenseManager instead lives in the bundle's
 * module closure, reachable only through the closures of the licensing IPC
 * handlers. This attaches to the inspector and walks
 *
 *   <handlerFn>.[[Scopes]] -> bundle scope -> LicenseManager -> .shared
 *
 * then shadows every Pro getter on LicenseManager.prototype with a hardcoded
 * Pro state and replaces every network validation path with a no-op.
 *
 * The shadow lives in the process's memory, so it is gone the moment Herd
 * exits. It is what this repository used to find the singleton, to verify the
 * shadow, and to check the IPC surface end to end; HerdShim.js is the same
 * payload, baked into app.asar so it survives a restart.
 *
 * usage:
 *   node patch_cdp.cjs [--port 9333] [--key HERD-PRO-...] [--wait 60]
 *   node patch_cdp.cjs --check          attach and report, install nothing
 */

const DEFAULT_PORT = 9333;
const DEFAULT_KEY = "HERD-PRO-4080-0000-1111-2222-3333-4444-5555";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const PORT = Number(arg("port", DEFAULT_PORT));
const KEY = arg("key", DEFAULT_KEY);
const WAIT_MS = Number(arg("wait", 60)) * 1000;
// --check attaches, walks the closures and reports what the process currently
// believes, without installing anything. Use it to prove a baked shim is live.
const MODE = process.argv.includes("--check") ? "check" : "patch";

function buildShadow(key) {
  return `
function () {
  const proto = Object.getPrototypeOf(this);
  const KEY = ${JSON.stringify(key)};
  const info = () => ({
    hasValidLicense: true,
    licenseKey: KEY,
    hasLicenseValidatedAt: Date.now(),
    licenseExpiresSoon: false,
    licenseExpiresIn: -1,
    licenseIsExpired: false,
    expiredLicenseKey: null,
    licenseIsLifetime: true,
    licenseRefreshStatus: null,
    lifetimeCelebrationPending: false,
  });
  const def = (n, g) => Object.defineProperty(proto, n, { get: g, configurable: true, enumerable: false });
  def("hasValidLicense", () => true);
  def("licenseKey", () => KEY);
  def("isLifetimeLicense", () => true);
  def("licenseExpiresSoon", () => false);
  def("licenseExpiresIn", () => -1);
  def("needsRenewalCopy", () => false);
  def("info", info);
  def("canReceiveTrialDumps", () => true);
  def("remainingTrialDumps", () => Number.MAX_SAFE_INTEGER);
  def("salePromoText", () => null);
  def("saleCheckoutUrl", () => null);
  def("siteInfoSalePayload", () => null);
  const noop = () => Promise.resolve(true);
  for (const m of ["validate","requestValidation","refreshLicenseAfterCheckout",
                   "refreshIfReturningFromCheckout","startValidating","stopValidating",
                   "startPinging","stopPinging","schedulePingRetry","ping",
                   "setRefreshStatus","activate","incrementDumps",
                   "markLicenseAsDeactivated"]) {
    try { Object.defineProperty(proto, m, { value: noop, configurable: true, writable: true }); } catch (e) {}
  }
  try { Object.defineProperty(proto, "deactivate", { value: () => Promise.resolve(false), configurable: true, writable: true }); } catch (e) {}
  this.refreshStatus = null;
  this.licenseRefreshStatus = null;
  this.lifetimeCelebrationPending = false;
  this.pingRetryArmed = false;
  return "shadowed";
}`;
}

async function findTarget(deadline) {
  while (Date.now() < deadline) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const t = list.find((x) => x.type === "node") || list[0];
      if (t && t.webSocketDebuggerUrl) return t;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 400));
  }
  return null;
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let id = 0;
    const pending = new Map();
    const guard = setTimeout(() => reject(new Error("ws open timeout")), 10000);
    ws.addEventListener("message", (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        pending.get(m.id)(m);
        pending.delete(m.id);
      }
    });
    ws.addEventListener("error", () => reject(new Error("ws error")));
    ws.addEventListener("close", () => reject(new Error("ws closed")));
    ws.addEventListener("open", () => {
      clearTimeout(guard);
      resolve({
        ws,
        send(method, params) {
          return new Promise((res) => {
            const i = ++id;
            const timer = setTimeout(() => {
              if (pending.delete(i)) res({ __timeout: method });
            }, 15000);
            pending.set(i, (m) => { clearTimeout(timer); res(m); });
            ws.send(JSON.stringify({ id: i, method, params: params || {} }));
          });
        },
      });
    });
  });
}

async function patch(api) {
  const props = (oid, own) =>
    api.send("Runtime.getProperties", { objectId: oid, ownProperties: own !== false, generatePreview: false })
      .then((r) => r.result || {});
  const call = async (oid, fn, byValue, awaitPromise) => {
    const r = await api.send("Runtime.callFunctionOn", {
      objectId: oid, functionDeclaration: fn, returnByValue: !!byValue, awaitPromise: !!awaitPromise,
    });
    return r.result || {};
  };

  const handler = await api.send("Runtime.evaluate", {
    expression: "require('electron').ipcMain._invokeHandlers.get('licensing.has-valid-license')",
    returnByValue: false, includeCommandLineAPI: true,
  });
  const handlerRemote = handler.result && handler.result.result;
  const handlerOid = handlerRemote && handlerRemote.objectId;
  if (!handlerOid) throw new Error("licensing IPC handler not found (Herd not fully started?)");

  const hp = await props(handlerOid, false);
  const scopes = (hp.internalProperties || []).find((x) => x.name === "[[Scopes]]");
  if (!scopes || !scopes.value || !scopes.value.objectId) throw new Error("no [[Scopes]] on handler");

  const sp = await props(scopes.value.objectId, true);
  const bundle = (sp.result || []).find((s) => s.name === "0");
  if (!bundle || !bundle.value || !bundle.value.objectId) throw new Error("bundle scope not found");

  const bp = await props(bundle.value.objectId, true);
  const cls = (bp.result || []).find((v) => v.name === "LicenseManager");
  if (!cls || !cls.value || !cls.value.objectId) throw new Error("LicenseManager not in bundle scope");

  const shared = await call(cls.value.objectId, "function(){ return this.shared; }");
  if (!shared.result || !shared.result.objectId) throw new Error("LicenseManager.shared unavailable");
  const instanceOid = shared.result.objectId;

  if (MODE === "check") {
    const read = await call(
      instanceOid,
      `function () {
        const out = {};
        for (const n of ["hasValidLicense","licenseKey","isLifetimeLicense","deviceName","deviceId",
                         "licenseExpiresSoon","licenseExpiresIn","needsRenewalCopy",
                         "canReceiveTrialDumps","remainingTrialDumps"]) {
          try { out[n] = this[n]; } catch (e) { out[n] = "<threw: " + e.message + ">"; }
        }
        try { out.info = this.info; } catch (e) { out.info = "<threw: " + e.message + ">"; }
        return JSON.stringify(out, null, 1);
      }`,
      true
    );
    const state = read.result && read.result.value;
    const parsed = typeof state === "string" ? JSON.parse(state) : state;
    return { instanceOid, mode: "check", state: parsed };
  }

  const installed = await call(instanceOid, buildShadow(KEY));
  if (!installed.result || installed.result.value !== "shadowed") throw new Error("shadow install failed");

  const state = await call(instanceOid, "function(){ return String(this.hasValidLicense); }", true);
  await call(instanceOid, "function(){ try { this.publishLicenseState(); } catch(e){} return true; }", true);

  // read the state back through the real IPC surface, not through the closure
  const verify = await api.send("Runtime.evaluate", {
    expression: `(async () => {
      const H = require('electron').ipcMain._invokeHandlers;
      const ev = { sender: null, reply: function(){}, returnValue: function(){}, send: function(){} };
      const r = await H.get('licensing.has-valid-license')(ev, {});
      const k = await H.get('licensing.license-key')(ev, {});
      const i = await H.get('licensing.info')(ev, {});
      return JSON.stringify({ hasValidLicense: r, licenseKey: k, info: i });
    })()`,
    awaitPromise: true, returnByValue: true, includeCommandLineAPI: true,
  });
  const value = verify.result && verify.result.result && verify.result.result.value;

  return {
    instanceOid,
    getterSays: state.result && state.result.value,
    ipcSays: typeof value === "string" ? JSON.parse(value) : value,
  };
}

(async () => {
  const deadline = Date.now() + WAIT_MS;
  let lastErr;
  while (Date.now() < deadline) {
    let api = null;
    try {
      // re-fetch every attempt: node mints a fresh session UUID per /json/list
      const target = await findTarget(Date.now() + 2000);
      if (!target) throw new Error(`no inspector on 127.0.0.1:${PORT} yet`);
      api = await connect(target.webSocketDebuggerUrl);
      const enabled = await api.send("Runtime.enable", {});
      if (enabled && enabled.__timeout) throw new Error("Runtime.enable timed out");
      const result = await patch(api);
      api.ws.close();
      api = null;
      console.log(`instance      ${result.instanceOid}`);
      if (result.mode === "check") {
        console.log("LicenseManager.shared:");
        console.log(JSON.stringify(result.state, null, 1));
        const ok = result.state.hasValidLicense === true;
        console.log(ok ? "PASS: LicenseManager reports a valid license" : "FAIL: LicenseManager reports no license");
        process.exit(ok ? 0 : 1);
      }
      const ok = result.ipcSays && result.ipcSays.hasValidLicense === true;
      console.log(`getter        hasValidLicense=${result.getterSays}`);
      console.log(`ipc           ${JSON.stringify(result.ipcSays)}`);
      console.log(ok ? "PASS: Herd Pro active" : "FAIL: ipc did not report Pro");
      process.exit(ok ? 0 : 1);
    } catch (e) {
      lastErr = e;
      if (api) { try { api.ws.close(); } catch (_) {} }
      await new Promise((r) => setTimeout(r, 750));
    }
  }
  console.error("FAIL:", lastErr && lastErr.message);
  process.exit(1);
})();
