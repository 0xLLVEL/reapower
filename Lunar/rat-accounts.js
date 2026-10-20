// rat-accounts.js - local account entry point for the launcher's account menu.
//
// Loaded from dist/html/main.html as a module. It does not touch the React tree: it
// watches the DOM for the launcher's own "Add Account" menu row and inserts a sibling
// beside it, so a re-render only costs a re-injection rather than a broken tree.
//
// The add path goes through the launcher's real auth module - window.lunar.auth.addAccount
// -> ipcRenderer.invoke("auth:addAccount", payload) -> the main process, which writes the
// account into its own store and flushes accounts.json. Nothing here writes the file
// directly, so the in-memory map and the file on disk cannot disagree.
//
// payload = { username } is handled by the addLocalAccount branch added to the auth
// module. Without a payload the call falls through to the original Microsoft flow, so
// the unmodified "Add Account" row still behaves exactly as shipped.

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

let styleEl = null;

function ensureStyle() {
  if (styleEl && document.head.contains(styleEl)) return;
  styleEl = document.createElement("style");
  styleEl.textContent = css;
  document.head.appendChild(styleEl);
}

// The launcher renders each row as a container holding an icon and a label, so the
// exact-text match hits both the row and its inner label span. Taking the outermost
// match is what makes the new item land as a sibling of the row instead of inside its
// own label. Rows are only visible while the menu is open, which is why the caller
// re-runs this on every mutation.
function findRow(text) {
  const all = [];
  for (const el of document.querySelectorAll("div,button,span,li,a")) {
    if (el.getAttribute(MARK)) continue;
    const t = (el.textContent || "").trim();
    if (t !== text && t !== LINK) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 40 || r.height < 10) continue;
    all.push(el);
  }
  const outer = all.filter((el) => !all.some((o) => o !== el && el.contains(o)));
  return outer.find((el) => (el.textContent || "").trim() === text) || null;
}

function buildPanel() {
  const mask = document.createElement("div");
  mask.className = `${MARK}-mask`;
  mask.innerHTML = `
    <div class="${MARK}-panel" role="dialog" aria-modal="true">
      <p class="${MARK}-h">Add cracked account</p>
      <p class="${MARK}-s">Written straight into the launcher's own account store, so it
        appears in this menu and launches like any other. Singleplayer and
        <code>online-mode=false</code> servers only.</p>
      <input class="${MARK}-in" type="text" maxlength="16" spellcheck="false"
             autocomplete="off" placeholder="Minecraft username" />
      <p class="${MARK}-err"></p>
      <div class="${MARK}-row">
        <button class="${MARK}-btn ${MARK}-cancel" type="button">Cancel</button>
        <button class="${MARK}-btn ${MARK}-go" type="button">Add account</button>
      </div>
    </div>`;

  const input = mask.querySelector(`.${MARK}-in`);
  const err = mask.querySelector(`.${MARK}-err`);
  const go = mask.querySelector(`.${MARK}-go`);
  const close = () => mask.remove();

  mask.addEventListener("mousedown", (e) => {
    if (e.target === mask) close();
  });
  mask.querySelector(`.${MARK}-cancel`).addEventListener("click", close);
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Escape" && document.body.contains(mask)) close();
    },
    { once: false }
  );

  // The launcher validates the name against Mojang's username shape. Checking it here
  // keeps a bad name from travelling to the main process and coming back as a throw.
  const validate = (v) => {
    const s = v.trim();
    if (!s) return "Enter a username.";
    if (!/^[A-Za-z0-9_]{3,16}$/.test(s)) return "3-16 characters, letters, digits and underscore.";
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
      err.textContent = "Account bridge is not available in this build.";
      console.warn(LOG, "window.lunar.auth.addAccount missing");
      return;
    }

    go.disabled = true;
    go.textContent = "Adding...";
    err.textContent = "";

    try {
      const uuid = await api({ username });
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
  return mask;
}

function inject() {
  const anchor = findRow(EXISTING);
  if (!anchor) return false;

  // "Add Account (via Link)" contains "Add Account" as a prefix, so confirm the anchor
  // is the plain row and not the link one before cloning its shape.
  if ((anchor.textContent || "").trim() === LINK) return false;
  if (anchor.nextElementSibling && anchor.nextElementSibling.getAttribute(MARK)) return true;

  ensureStyle();

  const item = document.createElement("div");
  item.className = `${MARK}-item`;
  item.setAttribute(MARK, "1");
  item.innerHTML = `<span class="${MARK}-dot">&#8250;</span><span>${LABEL}</span>`;
  item.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    buildPanel();
  });

  anchor.insertAdjacentElement("afterend", item);
  console.log(LOG, "menu item injected");
  return true;
}

function start() {
  ensureStyle();
  inject();

  // React replaces menu nodes on every state change, so the row has to be re-found and
  // re-attached. Observing subtree mutations is the only way to survive that without
  // holding a reference to a component that no longer exists.
  let queued = false;
  const obs = new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      inject();
    });
  });

  obs.observe(document.documentElement, { childList: true, subtree: true });
  console.log(LOG, "watching for the account menu");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
