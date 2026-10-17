// herd-pro — HerdShim.js
//
// Baked into app.asar as <payload> after out/main/index.js. Runs inside Herd's
// main process on every start; no launcher, no inspector port, no argv.
//
// Herd's main bundle ships as V8 cached-data bytecode (out/main/index.jsc), so
// LicenseManager is not reachable by name and there is nothing to decompile.
// It does live in the bundle's module closure, and the licensing IPC handlers
// close over it. The in-process inspector walks:
//
//   <handlerFn>.[[Scopes]] -> bundle scope -> LicenseManager -> .shared
//
// Once the singleton is in hand, every Pro accessor is shadowed on its
// prototype and every network validation path is replaced with a no-op, so
// nothing (ping, refresh, checkout return) can flip the state back.
(function () {
  "use strict";

  var LOG = null;
  try {
    LOG = require("path").join(require("electron").app.getPath("userData"), "herd-pro.log");
  } catch (e) {}
  function log(m) {
    try { require("fs").appendFileSync(LOG, "[" + new Date().toISOString() + "] " + m + "\n"); } catch (e) {}
    try { console.log("[herd-pro] " + m); } catch (e) {}
  }

  var LICENSE_KEY = "HERD-PRO-4080-0000-1111-2222-3333-4444-5555";

  var SHADOW_SRC = [
    "function () {",
    "  var proto = Object.getPrototypeOf(this);",
    "  var KEY = " + JSON.stringify(LICENSE_KEY) + ";",
    "  var info = function () { return {",
    "    hasValidLicense: true, licenseKey: KEY, hasLicenseValidatedAt: Date.now(),",
    "    licenseExpiresSoon: false, licenseExpiresIn: -1, licenseIsExpired: false,",
    "    expiredLicenseKey: null, licenseIsLifetime: true, licenseRefreshStatus: null,",
    "    lifetimeCelebrationPending: false }; };",
    "  var def = function (n, g) { Object.defineProperty(proto, n, { get: g, configurable: true, enumerable: false }); };",
    "  def('hasValidLicense', function () { return true; });",
    "  def('licenseKey', function () { return KEY; });",
    "  def('isLifetimeLicense', function () { return true; });",
    "  def('licenseExpiresSoon', function () { return false; });",
    "  def('licenseExpiresIn', function () { return -1; });",
    "  def('needsRenewalCopy', function () { return false; });",
    "  def('info', info);",
    "  def('canReceiveTrialDumps', function () { return true; });",
    "  def('remainingTrialDumps', function () { return Number.MAX_SAFE_INTEGER; });",
    "  def('salePromoText', function () { return null; });",
    "  def('saleCheckoutUrl', function () { return null; });",
    "  def('siteInfoSalePayload', function () { return null; });",
    "  var noop = function () { return Promise.resolve(true); };",
    "  ['validate','requestValidation','refreshLicenseAfterCheckout','refreshIfReturningFromCheckout',",
    "   'startValidating','stopValidating','startPinging','stopPinging','schedulePingRetry','ping',",
    "   'setRefreshStatus','activate','incrementDumps','markLicenseAsDeactivated'].forEach(function (m) {",
    "    try { Object.defineProperty(proto, m, { value: noop, configurable: true, writable: true }); } catch (e) {}",
    "  });",
    "  try { Object.defineProperty(proto, 'deactivate', { value: function () { return Promise.resolve(false); }, configurable: true, writable: true }); } catch (e) {}",
    "  this.refreshStatus = null;",
    "  this.licenseRefreshStatus = null;",
    "  this.lifetimeCelebrationPending = false;",
    "  this.pingRetryArmed = false;",
    "  return 'shadowed';",
    "}",
  ].join("\n");

  function post(session, method, params) {
    return new Promise(function (resolve, reject) {
      session.post(method, params || {}, function (err, result) {
        if (err) reject(err); else resolve(result || {});
      });
    });
  }

  function install() {
    var ipcMain = require("electron").ipcMain;
    if (!ipcMain || !ipcMain._invokeHandlers) { return Promise.resolve(false); }
    if (!ipcMain._invokeHandlers.has("licensing.has-valid-license")) return Promise.resolve(false);

    var session = new (require("inspector").Session)();
    session.connect();
    var handlerOid = null;

    return post(session, "Runtime.enable", {})
      .then(function () {
        globalThis.__herd_pro_handler = ipcMain._invokeHandlers.get("licensing.has-valid-license");
        return post(session, "Runtime.evaluate", {
          expression: "__herd_pro_handler", returnByValue: false, includeCommandLineAPI: true,
        });
      })
      .then(function (h) {
        handlerOid = h.result && h.result.objectId;
        if (!handlerOid) throw new Error("handler remote object unavailable");
        return post(session, "Runtime.getProperties", { objectId: handlerOid, ownProperties: false, generatePreview: false });
      })
      .then(function (hp) {
        var s = (hp.internalProperties || []).filter(function (x) { return x.name === "[[Scopes]]"; })[0];
        if (!s || !s.value || !s.value.objectId) throw new Error("no [[Scopes]]");
        return post(session, "Runtime.getProperties", { objectId: s.value.objectId, ownProperties: true, generatePreview: false });
      })
      .then(function (sp) {
        var bundle = (sp.result || []).filter(function (x) { return x.name === "0"; })[0];
        if (!bundle || !bundle.value || !bundle.value.objectId) throw new Error("bundle scope missing");
        return post(session, "Runtime.getProperties", { objectId: bundle.value.objectId, ownProperties: true, generatePreview: false });
      })
      .then(function (bp) {
        var cls = (bp.result || []).filter(function (x) { return x.name === "LicenseManager"; })[0];
        if (!cls || !cls.value || !cls.value.objectId) throw new Error("LicenseManager not in bundle scope");
        return post(session, "Runtime.callFunctionOn", {
          objectId: cls.value.objectId, functionDeclaration: "function () { return this.shared; }", returnByValue: false,
        });
      })
      .then(function (sr) {
        var inst = sr.result;
        if (!inst || !inst.objectId) throw new Error("LicenseManager.shared unavailable");
        return post(session, "Runtime.callFunctionOn", {
          objectId: inst.objectId, functionDeclaration: SHADOW_SRC, returnByValue: true,
        }).then(function (r) {
          var v = r.result && r.result.value;
          if (v !== "shadowed") throw new Error("shadow failed: " + JSON.stringify(r.result));
          log("shadow installed on LicenseManager.prototype");
          return post(session, "Runtime.callFunctionOn", {
            objectId: inst.objectId,
            functionDeclaration: "function () { try { this.publishLicenseState(); } catch (e) {} return String(this.hasValidLicense); }",
            returnByValue: true,
          });
        });
      })
      .then(function (r) {
        log("hasValidLicense => " + (r.result && r.result.value));
        try { session.disconnect(); } catch (e) {}
        delete globalThis.__herd_pro_handler;
        return true;
      })
      .catch(function (e) {
        log("install failed: " + (e && e.message));
        try { session.disconnect(); } catch (x) {}
        return false;
      });
  }

  function main() {
    var started = Date.now();
    var attempts = 0;
    (function tick() {
      attempts++;
      var p;
      try { p = install(); } catch (e) { log("install threw: " + (e && e.message)); return; }
      p.then(function (ok) {
        if (ok) { log("done after " + attempts + " attempt(s)"); return; }
        if (Date.now() - started > 120000) { log("gave up"); return; }
        setTimeout(tick, 250);
      });
    })();
  }

  try {
    var app = require("electron").app;
    if (app.whenReady) app.whenReady().then(main, main);
    else main();
  } catch (e) {
    log("boot error: " + (e && e.message));
  }
})();
