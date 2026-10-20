// rat-accounts.js - local account entry point for the launcher's account menu.
//
// Deliberately a CLASSIC script, not type="module": it has no imports or exports, so
// module semantics buy nothing and cost a whole class of failure around defer timing
// and module CORS on a file:// origin. main.html references this relatively, from
// /dist/html/, as "../assets/rat-accounts.js" - an absolute src there resolves against
// the filesystem root and 404s, which is how the first revision failed silently.
//
// It does not touch the React tree. It finds the launcher's own "Add Account" row by
// visible text and inserts a sibling, and re-runs on a timer as well as on mutation,
// because React replaces menu nodes on every state change and the rows only exist while
// the menu is open.
//
// Two entry points are provided on purpose. The menu item is the intended one. The
// corner chip is the fallback, and also the probe: if it is on screen then the file
// loaded and the bridge is present, which separates "module never ran" from "menu text
// did not match" in a single look at the window.
//
// Add path goes through the launcher's own auth module - window.lunar.auth.addAccount
// -> ipcRenderer.invoke("auth:addAccount", payload) -> the patched handler in the main
// process -> _Ee(), which writes accounts.json through the launcher's store. Nothing
// here writes the file, so the in-memory map and the file cannot disagree.

const LABEL = "Add Cracked Account";
const EXISTING = "Add Account";
const LINK = "Add Account (via Link)";
const MARK = "data-rat-accounts";
const LOG = "[rat-accounts]";

const css = `
.${MARK}-item{display:flex;align-items:center;gap:8px;padding:7px 12px;margin:2px 6px;
border-radius:6px;cursor:pointer;font-size:13px;color:#d7d9e0;user-select:none;white-space:nowrap}
.${MARK}-item:hover{background:rgba(255,255,255,.07)}
.${MARK}-dot{width:14px;text-align:center;opacity:.85}
.${MARK}-chip{position:fixed;right:14px;bottom:14px;z-index:2147482000;display:flex;align-items:center;
gap:7px;padding:7px 12px;border-radius:999px;cursor:pointer;user-select:none;
background:#15161c;border:1px solid rgba(85,255,255,.35);color:#55ffff;
font:600 12px/1 system-ui,-apple-system,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.5)}
.${MARK}-chip:hover{background:#1b1d24;border-color:#55ffff}
.${MARK}-chip[data-injected="1"]{opacity:.35}
.${MARK}-mask{position:fixed;inset:0;background:rgba(0,0,0,.62);z-index:2147483000;
display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,sans-serif}
.${MARK}-panel{width:320px;background:#1b1c22;border:1px solid rgba(255,255,255,.09);
border-radius:10px;padding:16px;box-shadow:0 18px 44px rgba(0,0,0,.55);color:#e6e8ef}
.${MARK}-h{font-size:14px;font-weight:600;margin:0 0 3px}
.${MARK}-s{font-size:11.5px;color:#9a9db0;margin:0 0 12px;line-height:1.45}
.${MARK}-in{width:100%;box-sizing:border-box;background:#101116;border:1px solid rgba(255,255,255,.12);
border-radius:6px;color:#e6e8ef;font-size:13px;padding:8px 10px;outline:none}
.${MARK}-in:focus{border-color:#55ffff}
.${MARK}-err{font-size:11.5px;color:#ff7a7a;margin:8px 0 0;min-height:14px;line-height:1.4}
.${MARK}-row{display:flex;gap:8px;margin-top:12px;justify-content:flex-end}
.${MARK}-btn{border:0;border-radius:6px;padding:7px 14px;font-size:12.5px;cursor:pointer}
.${MARK}-cancel{background:rgba(255,255,255,.08);color:#c9ccd8}
.${MARK}-go{background:#55ffff;color:#07101a;font-weight:600}
.${MARK}-go[disabled]{opacity:.5;cursor:default}
`;

function ensureStyle() {
  if (document.querySelector(`style[data-${MARK}]`)) return;
  const s = document.createElement("style");
  s.setAttribute("data-", MARK);
  s.textContent = css;
  (document.head || document.documentElement).appendChild(s);
}

// Collects every element whose visible text is exactly the target, then keeps the
// outermost. The launcher's row holds an icon and a label, so an innermost-first search
// would match the label span and insert the new item inside its own label.
//
// The outermost is the candidate that no OTHER candidate contains - `o.contains(el)`, not
// `el.contains(o)`. Reading it the other way round filters out exactly the element being
// looked for: the row contains the label, so the row is discarded and only the label
// survives, and the new item lands one level too deep to render as a menu entry.
let searchedText = 0;
let searchedOuter = 0;

function findRow(text) {
  const all = [];
  for (const el of document.querySelectorAll("div,button,span,li,a")) {
    if (el.getAttribute(MARK)) continue;
    if ((el.textContent || "").trim() !== text) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 40 || r.height < 10) continue;
    all.push(el);
  }
  const outer = all.filter((el) => !all.some((o) => o !== el && o.contains(el)));
  searchedText = all.length;
  searchedOuter = outer.length;
  return outer[0] || null;
}

function buildPanel() {
  const mask = document.createElement("div");
  mask.className = `${MARK}-mask`;
  mask.innerHTML =
    '<div class="' + MARK + '-panel" role="dialog" aria-modal="true">' +
    '<p class="' + MARK + '-h">Add cracked account</p>' +
    '<p class="' + MARK + '-s">Written into the launcher&#39;s own account store, so it ' +
    "appears in this menu and launches like any other. Singleplayer and " +
    "<code>online-mode=false</code> servers only.</p>" +
    '<input class="' + MARK + '-in" type="text" maxlength="16" spellcheck="false" ' +
    'autocomplete="off" placeholder="Minecraft username" />' +
    '<p class="' + MARK + '-err"></p>' +
    '<div class="' + MARK + '-row">' +
    '<button class="' + MARK + '-btn ' + MARK + '-cancel" type="button">Cancel</button>' +
    '<button class="' + MARK + '-btn ' + MARK + '-go" type="button">Add account</button>' +
    "</div></div>";

  const input = mask.querySelector("." + MARK + "-in");
  const err = mask.querySelector("." + MARK + "-err");
  const go = mask.querySelector("." + MARK + "-go");
  const close = () => mask.remove();

  mask.addEventListener("mousedown", (e) => {
    if (e.target === mask) close();
  });
  mask.querySelector("." + MARK + "-cancel").addEventListener("click", close);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.body.contains(mask)) close();
  });

  const validate = (v) => {
    const s = v.trim();
    if (!s) return "Enter a username.";
    if (!/^[A-Za-z0-9_]{3,16}$/.test(s))
      return "3-16 characters: letters, digits, underscore.";
    return "";
  };

  const submit = async () => {
    const problem = validate(input.value);
    if (problem) {
      err.textContent = problem;
      input.focus();
      return;
    }
    const username = input.value.trim();

    const api = window.lunar && window.lunar.auth && window.lunar.auth.addAccount;
    if (typeof api !== "function") {
      err.textContent = "Account bridge is not present on window.lunar.";
      console.warn(LOG, "window.lunar.auth.addAccount missing", Object.keys(window));
      return;
    }

    go.disabled = true;
    go.textContent = "Adding...";
    err.textContent = "";

    try {
      const uuid = await api({ username: username });
      console.log(LOG, "added", username, uuid || "");
      close();
    } catch (e) {
      console.warn(LOG, "add failed", e);
      err.textContent = "Rejected: " + (e && e.message ? e.message : String(e));
      go.disabled = false;
      go.textContent = "Add account";
      input.focus();
    }
  };

  go.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });

  document.body.appendChild(mask);
  input.focus();
}

let injected = false;

function inject() {
  // React replaces menu nodes on every state change, so an item that was inserted once
  // is gone the next time the dropdown opens. A sticky `injected` flag would leave the
  // menu permanently empty after the first re-render, which is why the flag is derived
  // from whether the node is still in the document rather than remembered.
  const existing = document.querySelector("." + MARK + "-item");
  if (existing && document.documentElement.contains(existing)) return true;
  injected = false;

  const anchor = findRow(EXISTING);
  const chip = document.querySelector("." + MARK + "-chip");
  if (!anchor) {
    // The console is not reachable from here, so the chip's tooltip carries the counts.
    // "0 matched" and "3 matched, 1 outermost" are different failures and it is the only
    // thing that separates a text mismatch from a tree-shape problem.
    if (chip)
      chip.title =
        'no "Add Account" row yet - text matches ' + searchedText + ", outermost " + searchedOuter;
    return false;
  }
  if (chip) chip.title = "Add a local Minecraft account";

  const item = document.createElement("div");
  item.className = MARK + "-item";
  item.setAttribute(MARK, "1");
  item.innerHTML = '<span class="' + MARK + '-dot">&#8250;</span><span>' + LABEL + "</span>";
  item.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    buildPanel();
  });

  anchor.insertAdjacentElement("afterend", item);
  injected = true;
  if (chip) chip.setAttribute("data-injected", "1");
  console.log(LOG, "menu item injected");
  return true;
}

function buildChip() {
  if (document.querySelector("." + MARK + "-chip")) return;
  const chip = document.createElement("div");
  chip.className = MARK + "-chip";
  chip.setAttribute(MARK, "1");
  chip.title = "Add a local Minecraft account";
  chip.textContent = "+ Add cracked account";
  chip.addEventListener("click", buildPanel);
  document.body.appendChild(chip);
  console.log(LOG, "chip mounted");
}

function start() {
  ensureStyle();
  buildChip();
  inject();

  // The menu rows only exist while the dropdown is open, and React replaces those nodes
  // on every state change, so neither a one-shot scan nor a MutationObserver alone is
  // enough - the observer misses work done before it attaches and the timer catches the
  // rest.
  let queued = false;
  const obs = new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      ensureStyle();
      buildChip();
      inject();
    });
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });

  const poll = setInterval(() => {
    ensureStyle();
    buildChip();
    if (inject()) clearInterval(poll);
  }, 600);

  console.log(LOG, "started", {
    lunar: !!(window.lunar && window.lunar.auth),
    addAccount: typeof (window.lunar && window.lunar.auth && window.lunar.auth.addAccount),
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
