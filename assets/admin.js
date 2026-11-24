// The admin dashboard. Everything shown that came from users (report text,
// types, reasons) is set as text, never parsed as HTML. Media is loaded only
// on the Media tab or when asked for, and is blurred until shown unless the
// admin switches blurring off; blobs banned as CSAM have no preview at all.
"use strict";

const $ = (id) => document.getElementById(id);
let stats = null;

// --- small helpers ---------------------------------------------------------

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false || c === "") continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

// Replaces a node's children, skipping what `el` skips and flattening lists.
function put(node, ...children) {
  node.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false && c !== ""));
}

// Lucide's icons, as much of them as is used here.
const ICONS = {
  more: [["circle", { cx: 12, cy: 12, r: 1 }], ["circle", { cx: 19, cy: 12, r: 1 }], ["circle", { cx: 5, cy: 12, r: 1 }]],
  eye: [["path", { d: "M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" }], ["circle", { cx: 12, cy: 12, r: 3 }]],
  eyeOff: [["path", { d: "M9.88 9.88a3 3 0 1 0 4.24 4.24" }], ["path", { d: "M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" }],
    ["path", { d: "M6.61 6.61A13.53 13.53 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" }], ["path", { d: "m2 2 20 20" }]],
  play: [["polygon", { points: "6 3 20 12 6 21 6 3" }]],
  x: [["path", { d: "M18 6 6 18" }], ["path", { d: "m6 6 12 12" }]],
};

function icon(name) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of ICONS[name]) {
    const part = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) part.setAttribute(k, v);
    svg.append(part);
  }
  return svg;
}

function when(seconds) {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

function bytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

const short = (hex) => `${hex.slice(0, 8)}…${hex.slice(-4)}`;
// A small JPEG of a stored picture or video, made by this server: 400 for
// a tile, 1280 for a picture to judge. The original is `url`.
const thumb = (b, side = 400) => `/api/thumb/${b.sha256}?side=${side}`;
const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const badge = (text, kind) => el("span", { class: kind ? `badge ${kind}` : "badge" }, text);
const lookupLink = (hex) =>
  el("a", { class: "mono", href: `#lookup/${encodeURIComponent(hex)}`, title: hex }, short(hex));
const button = (text, onclick, cls = "btn", extra = {}) =>
  el("button", { class: cls, type: "button", onclick, ...extra }, text);
const loading = (node) => node.replaceChildren(el("p", { class: "dim" }, "Loading…"));
const choice = (fieldset) => fieldset.querySelector("input:checked").value;

function table(heads, rows) {
  return el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, heads.map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, rows.map((cells) => el("tr", {}, cells.map((c) => el("td", {}, c))))),
  ));
}

// Messages: successes go away by themselves, errors stay until dismissed.
// One can offer a button, as Undo.
function say(text, bad = false, act = null) {
  const [here, other] = bad ? [$("alert"), $("status")] : [$("status"), $("alert")];
  other.replaceChildren();
  here.replaceChildren(el("div", { class: bad ? "toast bad" : "toast" },
    el("span", {}, text),
    act && button(act.label, () => { here.replaceChildren(); act.fn(); }, "toast-act"),
    button(icon("x"), () => here.replaceChildren(), "", { "aria-label": "Dismiss" }),
  ));
  clearTimeout(say.timer);
  if (!bad) say.timer = setTimeout(() => here.replaceChildren(), 5000);
}
const fail = (e) => say(e.message, true);

async function api(path, body) {
  const opts = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401) {
    showLogin($("app").hidden ? "" : "Your session ended. Sign in again.");
    throw new Error("Signed out");
  }
  if (!r.ok) throw new Error(r.headers.get("x-reason") || `${r.status} ${r.statusText}`);
  return r.json();
}

// A modal asking to confirm an action, optionally with a reason and a box
// to tick: the answer, or null if it was cancelled. With `run`, the action
// is done while it stays open, its button turned to `busy` and a line
// counting the seconds, so a long one (an account's thousands of files)
// shows it's at work; `run(answer, say)` can say what it's doing now. Its
// result is the answer's `result`; if it fails, the dialog says why.
function ask({ title, text = [], reason, check, action, danger = true, busy = "Working…", run }) {
  const d = $("dialog");
  let input = null, box = null;
  const fields = [];
  if (reason) {
    input = el("input", { type: "text", id: "dialog-reason", value: reason.value, required: reason.required, autocomplete: "off" });
    fields.push(el("div", { class: "field" }, el("label", { for: "dialog-reason" }, reason.label), input));
  }
  if (check) {
    box = el("input", { type: "checkbox", checked: check.checked });
    fields.push(el("label", { class: "check" }, box, check.label));
  }
  const ok = el("button", { type: "submit", class: danger ? "btn danger" : "btn primary" }, action);
  const status = el("p", { class: "dialog-status", role: "status", hidden: true });
  const form = el("form", {},
    el("h2", { id: "dialog-title" }, title),
    [text].flat().map((t) => el("p", {}, t)),
    fields,
    status,
    el("div", { class: "row end" }, button("Cancel", () => d.close(), "btn ghost"), ok),
  );
  d.replaceChildren(form);
  let working = false;
  const hold = (e) => { if (working) e.preventDefault(); };
  d.addEventListener("cancel", hold);
  return new Promise((resolve) => {
    let answer = null;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (working) return;
      if (input && reason.required && !input.value.trim()) { input.focus(); return; }
      const given = {
        reason: input ? input.value.trim() : "",
        checked: box ? box.checked : false,
      };
      if (!run) { answer = given; d.close(); return; }
      // Done while it's open, showing it's at work.
      working = true;
      const controls = [...form.querySelectorAll("button, input")];
      for (const c of controls) c.disabled = true;
      ok.replaceChildren(el("span", { class: "spinner", "aria-hidden": "true" }), busy);
      let doing = "Working";
      const started = Date.now();
      const tick = () => { status.textContent = `${doing}… ${Math.round((Date.now() - started) / 1000)}s`; };
      status.classList.remove("bad");
      status.hidden = false;
      tick();
      const clock = setInterval(tick, 1000);
      try {
        given.result = await run(given, (what) => { doing = what; tick(); });
        answer = given;
        working = false;
        d.close();
      } catch (err) {
        working = false;
        status.textContent = err.message || "That didn't work.";
        status.classList.add("bad");
        for (const c of controls) c.disabled = false;
        ok.replaceChildren(action);
      } finally {
        clearInterval(clock);
      }
    });
    d.addEventListener("close", () => { d.removeEventListener("cancel", hold); resolve(answer); }, { once: true });
    d.showModal();
    (input || ok).focus();
  });
}

// What each action does, said wherever it can be taken.
const HELP = {
  fine: "Mark it checked: Review won't show it again.",
  ban: "Delete it, and refuse it if anyone uploads it again. You get a few seconds to undo.",
  csam: "Only for child sexual abuse material: hides it, bans the uploader, and keeps a copy for your report.",
  remove: "Delete it, without banning it: it can be uploaded again.",
  banPubkey: "Stop this account uploading, and delete and ban every blob it owns.",
  unbanBlob: "Let it be uploaded again. What was deleted doesn't come back.",
  unbanPubkey: "Let this account upload again. Its blobs stay banned.",
  score: "Scan it now, and show how likely the scanner thinks it's explicit.",
  show: "Load it here, blurred until you show it if blurring is on.",
  open: "Open the file itself in a new tab, where it can't run script.",
};

// Wraps a button in a tooltip saying what it does, shown on hover and on
// keyboard focus, and read out as the button's description.
let tips = 0;
function tip(node, text, end = false) {
  const id = `tip-${++tips}`;
  node.setAttribute("aria-describedby", id);
  return el("span", { class: end ? "has-tip end" : "has-tip" }, node, el("span", { class: "tip", role: "tooltip", id }, text));
}

// A ⋯ button and the menu it opens, of [text, action, danger, help] items,
// with null for a divider. Arrow keys move through it and Escape closes it.
let openMenu = null;

function menu(name, items) {
  const list = el("div", { class: "menu", role: "menu", hidden: true });
  const trigger = button(icon("more"), () => (list.hidden ? open() : close()), "btn ghost icon sm",
    { "aria-label": `Actions for ${name}`, "aria-haspopup": "menu", "aria-expanded": "false" });
  const close = (refocus = false) => {
    list.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (openMenu === close) openMenu = null;
    if (refocus) trigger.focus();
  };
  const open = () => {
    if (openMenu) openMenu();
    list.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    openMenu = close;
    list.querySelector("button").focus();
  };
  for (const item of items) {
    if (!item) { list.append(el("hr")); continue; }
    const [text, fn, danger, help] = item;
    const id = help ? `tip-${++tips}` : undefined;
    list.append(button([el("span", {}, text), help && el("small", { id }, help)], () => { close(true); fn(); },
      danger ? "danger" : "", { role: "menuitem", tabindex: "-1", "aria-describedby": id }));
  }
  list.addEventListener("keydown", (e) => {
    const all = [...list.querySelectorAll("button")];
    const at = all.indexOf(document.activeElement);
    const to = { ArrowDown: at + 1, ArrowUp: at - 1, Home: 0, End: all.length - 1 }[e.key];
    if (to !== undefined) { e.preventDefault(); all[(to + all.length) % all.length].focus(); }
    if (e.key === "Escape" || e.key === "Tab") { e.preventDefault(); close(true); }
  });
  return [trigger, list];
}

document.addEventListener("click", (e) => {
  if (openMenu && !e.target.closest(".menu, [aria-haspopup=menu]")) openMenu();
});

// Puts media in `box`, blurred until its button shows it (unless blurring is
// switched off), and gives back that button.
function blurred(box, media) {
  const wrap = el("div", { class: "blur" });
  const label = el("span", { class: "label" }, "Show");
  const look = el("span", {}, icon("eye"), label);
  const toggle = el("button", { type: "button", class: "reveal", "aria-label": "Show" }, look);
  toggle.addEventListener("click", () => {
    const shown = wrap.classList.toggle("shown");
    look.firstChild.replaceWith(icon(shown ? "eyeOff" : "eye"));
    toggle.setAttribute("aria-label", shown ? "Blur" : "Show");
  });
  wrap.append(media, toggle);
  box.replaceChildren(wrap);
  return toggle;
}

// Blurring is one choice, wherever its switch is shown.
function setBlur(on) {
  document.body.classList.toggle("unblurred", !on);
  for (const box of document.querySelectorAll(".blur-toggle")) box.checked = on;
  localStorage.setItem("blur", on ? "1" : "0");
}

function blurSwitch() {
  const box = el("input", { type: "checkbox", role: "switch", class: "blur-toggle",
    checked: !document.body.classList.contains("unblurred") });
  box.addEventListener("change", () => setBlur(box.checked));
  return el("label", { class: "switch" }, box, el("span", { class: "track" }), "Blur");
}

// bech32 (NIP-19), just enough to read an npub.
function npubToHex(npub) {
  const CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const s = npub.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (!s.startsWith("npub1") || sep < 0) return null;
  const data = [];
  for (const c of s.slice(sep + 1)) {
    const v = CHARS.indexOf(c);
    if (v < 0) return null;
    data.push(v);
  }
  let acc = 0, bits = 0;
  const out = [];
  for (const v of data.slice(0, -6)) {
    acc = (acc << 5) | v;
    bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  if (out.length !== 32) return null;
  return out.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// bech32 (NIP-19) the other way: a hex pubkey as an npub.
function hexToNpub(hex) {
  const CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const data = [];
  let acc = 0, bits = 0;
  for (const byte of hex.match(/../g).map((h) => parseInt(h, 16))) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; data.push((acc >> bits) & 31); }
  }
  if (bits) data.push((acc << (5 - bits)) & 31);
  const polymod = (values) => {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
  };
  const hrp = [..."npub"].map((c) => c.charCodeAt(0));
  const mod = polymod([...hrp.map((c) => c >> 5), 0, ...hrp.map((c) => c & 31), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const check = [0, 1, 2, 3, 4, 5].map((i) => (mod >> (5 * (5 - i))) & 31);
  return "npub1" + [...data, ...check].map((v) => CHARS[v]).join("");
}

// --- profiles (kind 0), asked of the relays from this browser --------------
//
// The relays (admin.relays) are trusted to have checked signatures. What a
// profile says is shown as text; its pictures only if they're https.

const profiles = new Map();
let asking = new Map();

function profile(hex) {
  if (!profiles.has(hex)) {
    profiles.set(hex, new Promise((resolve) => asking.set(hex, resolve)));
    if (asking.size === 1) setTimeout(askRelays, 30);
  }
  return profiles.get(hex);
}

function askRelays() {
  const waiting = asking;
  asking = new Map();
  const authors = [...waiting.keys()];
  const newest = new Map();
  const relays = (stats && stats.relays) || [];
  let open = relays.length, finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    for (const [hex, resolve] of waiting) resolve(readProfile(newest.get(hex)));
  };
  const one = () => { if (--open <= 0) finish(); };
  if (!open) return finish();
  setTimeout(finish, 6000);
  for (const url of relays) {
    let ws, done = false;
    const close = () => { if (!done) { done = true; try { ws.close(); } catch { /* gone */ } one(); } };
    try { ws = new WebSocket(url); } catch { one(); continue; }
    const id = `p${Math.random().toString(36).slice(2, 10)}`;
    ws.onopen = () => ws.send(JSON.stringify(["REQ", id, { kinds: [0], authors, limit: authors.length }]));
    ws.onmessage = (m) => {
      let msg;
      try { msg = JSON.parse(m.data); } catch { return; }
      if (msg[0] === "EVENT" && msg[1] === id && msg[2] && msg[2].kind === 0) {
        const ev = msg[2], had = newest.get(ev.pubkey);
        if (waiting.has(ev.pubkey) && (!had || ev.created_at > had.created_at)) newest.set(ev.pubkey, ev);
      }
      if ((msg[0] === "EOSE" || msg[0] === "CLOSED") && msg[1] === id) close();
    };
    ws.onerror = close;
    ws.onclose = close;
    setTimeout(close, 5000);
  }
}

function readProfile(ev) {
  if (!ev) return null;
  let c;
  try { c = JSON.parse(ev.content); } catch { return null; }
  if (!c || typeof c !== "object") return null;
  const text = (v, n) => (typeof v === "string" && v.trim() ? v.trim().slice(0, n) : null);
  const https = (v) => {
    try { return typeof v === "string" && new URL(v).protocol === "https:" ? v : null; } catch { return null; }
  };
  return {
    name: text(c.display_name, 60) || text(c.name, 60),
    about: text(c.about, 400),
    picture: https(c.picture),
    banner: https(c.banner),
  };
}

// An avatar: the profile's picture, or a coloured initial until there is
// one, or if it won't load.
function avatar(hex, size = "sm") {
  const box = el("span", { class: `avatar ${size}`, "aria-hidden": "true" });
  box.style.setProperty("--hue", parseInt(hex.slice(0, 4), 16) % 360);
  box.textContent = hex.slice(0, 1).toUpperCase();
  profile(hex).then((p) => {
    if (p && p.name) box.textContent = [...p.name][0].toUpperCase();
    if (!p || !p.picture) return;
    // Not lazy: it isn't in the page until it has loaded.
    const img = el("img", { src: p.picture, alt: "", referrerpolicy: "no-referrer" });
    img.addEventListener("load", () => box.replaceChildren(img));
  });
  return box;
}

// A pubkey as Ditto shows one: avatar and name, linking to its page here.
function person(hex) {
  const name = el("span", { class: "who-name mono" }, short(hex));
  profile(hex).then((p) => {
    if (p && p.name) { name.textContent = p.name; name.classList.remove("mono"); }
  });
  return el("a", { class: "person", href: `#lookup/${encodeURIComponent(hex)}`, title: hex }, avatar(hex), name);
}

function ago(seconds) {
  const s = Math.max(0, Date.now() / 1000 - seconds);
  const units = [["year", 31536000], ["month", 2592000], ["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [unit, n] of units) if (s >= n) return `${plural(Math.floor(s / n), unit)} ago`;
  return "just now";
}

// --- signing in ------------------------------------------------------------

function showLogin(why = "") {
  $("app").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = why;
  document.title = "Sign in · Blossom admin";
}

async function signIn() {
  const btn = $("sign-in");
  $("login-error").textContent = "";
  if (!window.nostr) {
    $("login-error").textContent = "No Nostr extension (NIP-07) was found in this browser.";
    return;
  }
  btn.disabled = true;
  btn.textContent = "Waiting for your extension…";
  try {
    const ev = await window.nostr.signEvent({
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["u", `${location.origin}/api/login`], ["method", "POST"]],
      content: "",
    });
    const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(ev))));
    const r = await fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { Authorization: `Nostr ${b64}` },
    });
    if (!r.ok) throw new Error(r.headers.get("x-reason") || `${r.status}`);
    await start();
  } catch (e) {
    $("login-error").textContent = e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign in";
  }
}

async function signOut() {
  await api("/api/logout", {}).catch(() => {});
  showLogin();
}

async function start() {
  const me = await api("/api/session");
  stats = await api("/api/stats");
  put($("who"), person(me.pubkey));
  $("login").hidden = true;
  $("app").hidden = false;
  $("unlabelled-switch").hidden = !stats.labelling;
  showUnreported();
  showPurge();
  route();
}

// --- sections, one per #hash -----------------------------------------------

const TABS = {
  overview: "Home", review: "Review", media: "Media", reports: "Reports", lookup: "Search", bans: "Bans",
  evidence: "Evidence", usage: "Usage", help: "Help",
};
let mediaLoaded = false;
// The pages under Moderation, beside its own menu.
const MODERATION = ["review", "reports", "evidence", "bans"];

function route(focus = false) {
  if ($("app").hidden) return;
  // Going anywhere, from a link in it say, closes the lightbox.
  closeLightbox();
  const [name, ...rest] = location.hash.slice(1).split("/");
  const tab = name in TABS ? name : "overview";
  const moderating = MODERATION.includes(tab);
  for (const t of Object.keys(TABS)) $(`tab-${t}`).hidden = t !== tab;
  $("mod").hidden = !moderating;
  for (const a of document.querySelectorAll("nav a")) {
    const here = a.id === "nav-mod" ? moderating : a.getAttribute("href") === `#${tab}`;
    if (here) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  document.title = `${TABS[tab]} · Blossom admin`;
  let arg = rest.join("/");
  try { arg = decodeURIComponent(arg); } catch { /* shown as typed */ }
  const load = {
    overview: loadOverview,
    review: () => (review.loaded ? Promise.resolve(renderReview()) : loadReview()),
    media: () => (mediaLoaded ? Promise.resolve() : loadMedia(true)),
    reports: loadReports,
    lookup: () => (arg ? runLookup(arg) : Promise.resolve($("lookup-result").replaceChildren(
      el("p", { class: "card empty" }, "Search above for a file, by its hash or link, or an account, by its npub.")))),
    bans: loadBans,
    evidence: loadEvidence,
    help: () => Promise.resolve(),
    usage: loadUsage,
  }[tab];
  if (tab !== "review") leaveReview();
  load().catch(fail);
  if (focus) $(`h-${tab}`).focus();
}

function go(hash) {
  if (location.hash === `#${hash}`) route(true);
  else location.hash = hash;
}

async function loadOverview() {
  stats = await api("/api/stats");
  const s = stats.scan;
  // What needs doing first, each a big card that goes there.
  const next = (href, title, text, cta, primary = false) =>
    el("a", { class: primary ? "card next-card primary" : "card next-card", href },
      el("div", {}, el("h3", {}, title), el("p", { class: "dim" }, text)),
      el("span", { class: primary ? "btn primary" : "btn" }, cta));
  put($("next"),
    next("#review", "Review new uploads", "Look at new pictures and video, one at a time.", "Start", true),
    next("#reports", "Reports",
      stats.reports ? `${plural(stats.reports, "report")} from users.` : "No reports from users.",
      stats.reports ? "Open" : "Look"),
  );
  showOverview().catch(fail);
  const fact = (term, value, hint) => [el("dt", {}, term), el("dd", {}, value, hint && el("span", { class: "dim" }, ` · ${hint}`))];
  put($("server"),
    fact("Scanning", s ? `on, refusing scores of ${s.threshold.toFixed(3)} and over` : "off", !s && "set [scan] in the config"),
    fact("Bans", `${plural(stats.banned_blobs, "blob")}, ${plural(stats.banned_pubkeys, "pubkey")}`),
    fact("Labelling", stats.labelling ? "on" : "off", !stats.labelling && "needs scanning, admin.labels and admin.embeddings"),
    fact("Version", stats.version),
  );
  showUnreported();
}

// What's stored, at a glance: space by kind, uploads a day, and who uses
// the most. Worked out by the server now and then; a moment, the first time.
async function showOverview() {
  const box = $("overview");
  if (!box.children.length) put(box, el("div", { class: "card empty" }, "Adding things up…"));
  const o = await api("/api/overview");
  const share = (n) => (o.bytes ? (100 * n) / o.bytes : 0);
  const kinds = [["image", "Pictures"], ["video", "Video"], ["other", "Other files"]];
  const days = o.days.slice(-30);
  const busiest = Math.max(1, ...days.map((d) => d.files));
  const day = (t) => new Date(t * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
  const bar = (pct, cls = "") => {
    const b = el("span", { class: `fill ${cls}` });
    b.style.width = `${Math.max(pct, pct > 0 ? 1 : 0)}%`;
    return el("span", { class: "meter" }, b);
  };
  put(box, el("div", { class: "card overview" },
    el("div", { class: "overview-head" },
      el("div", {}, el("div", { class: "big-number" }, bytes(o.bytes)), el("div", { class: "dim" }, "stored")),
      el("div", { class: "overview-figures" },
        el("span", {}, el("b", {}, o.files.toLocaleString()), " files"),
        el("span", {}, el("b", {}, o.uploaders.toLocaleString()), " uploaders"),
        el("span", {}, el("b", {}, (stats.banned_blobs + stats.banned_pubkeys).toLocaleString()), " bans"))),
    // Space by kind, as one bar.
    el("div", { class: "split", role: "img", "aria-label": kinds.map(([k, n]) => `${n} ${bytes(o.kinds[k].bytes)}`).join(", ") },
      kinds.map(([k]) => {
        const part = el("span", { class: `part ${k}` });
        part.style.width = `${share(o.kinds[k].bytes)}%`;
        return part;
      })),
    el("div", { class: "split-legend" }, kinds.map(([k, name]) =>
      el("span", {}, el("i", { class: `dot ${k}` }), `${name} `, el("b", {}, bytes(o.kinds[k].bytes))))),
    el("div", { class: "overview-cols" },
      el("div", {},
        el("h4", {}, "Uploads, last 30 days"),
        el("div", { class: "chart", role: "img", "aria-label": `${days.reduce((n, d) => n + d.files, 0).toLocaleString()} uploads in the last 30 days` },
          days.map((d) => {
            const col = el("span", { class: "col", title: `${day(d.day)}: ${plural(d.files, "upload")}, ${bytes(d.bytes)}` });
            col.style.height = `${(100 * d.files) / busiest}%`;
            return col;
          })),
        el("div", { class: "chart-axis dim" }, el("span", {}, day(days[0].day)), el("span", {}, "today"))),
      el("div", {},
        el("h4", {}, "Using the most space"),
        o.top.length
          ? el("ol", { class: "top" }, o.top.slice(0, 5).map((t) => el("li", {},
            person(t.pubkey),
            el("span", { class: "dim small" }, `${plural(t.files, "file")} · `, el("b", {}, bytes(t.bytes))),
            bar(share(t.bytes)))))
          : el("p", { class: "dim" }, "Nobody yet."))),
    el("p", { class: "row dim small" }, el("span", { class: "grow" }, `As of ${ago(o.at)}.`), el("a", { href: "#usage" }, "All usage →"))));
}

// --- usage: everything the overview adds up, in full ----------------------

const monthName = (m) => {
  const [y, mo] = m.split("-").map(Number);
  return new Date(Date.UTC(y, mo - 1)).toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" });
};
const dayName = (t) => new Date(t * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });

// A bar chart: a column for each of `items`, as tall as `value` says, with
// `title` on hover, and the first and last labelled underneath.
function columns(items, value, title, label, tall = false) {
  const most = Math.max(1, ...items.map(value));
  return [
    el("div", { class: tall ? "chart tall" : "chart", role: "img", "aria-label": items.map(title).join("; ") },
      items.map((it) => {
        const col = el("span", { class: "col", title: title(it) });
        col.style.height = `${(100 * value(it)) / most}%`;
        return col;
      })),
    items.length > 0 && el("div", { class: "chart-axis dim" }, el("span", {}, label(items[0])), items.length > 1 && el("span", {}, label(items[items.length - 1]))),
  ];
}

// Rows of a name, its figures, and a bar for its share of `whole`.
function shares(items, name, figures, value, whole) {
  return el("ol", { class: "top" }, items.map((it) => {
    const fill = el("span", { class: "fill" });
    const pct = whole ? (100 * value(it)) / whole : 0;
    fill.style.width = `${Math.max(pct, pct > 0 ? 1 : 0)}%`;
    return el("li", {}, name(it), el("span", { class: "dim small" }, figures(it)), el("span", { class: "meter" }, fill));
  }));
}

async function loadUsage() {
  const box = $("usage");
  if (!box.children.length) put(box, el("div", { class: "card empty" }, "Adding things up…"));
  const u = await api("/api/usage");
  const card = (title, ...body) => el("div", { class: "card stack" }, el("h3", {}, title), ...body);
  const figure = (value, label) => el("div", { class: "stat" }, el("dt", {}, label), el("dd", {}, value));
  let total = 0;
  const growth = u.months.map((m) => ({ ...m, total: (total += m.bytes) }));
  const reads = u.reads;
  const cold = reads[4].bytes + reads[5].bytes;
  put(box,
    el("dl", { class: "card figures" },
      figure(bytes(u.bytes), "stored"),
      figure(u.files.toLocaleString(), "files"),
      figure(u.uploaders.toLocaleString(), "uploaders"),
      figure(bytes(u.files ? u.bytes / u.files : 0), "average file"),
      figure(bytes(u.shared.saved), "saved by sharing")),
    card("Storage over time",
      el("p", { class: "dim small" }, growth.length
        ? `${bytes(growth[growth.length - 1].total)} now, from ${bytes(growth[0].bytes)} in ${monthName(growth[0].month)}. Each bar is what was uploaded that month.`
        : "Nothing uploaded yet."),
      columns(u.months, (m) => m.bytes, (m) => `${monthName(m.month)}: ${plural(m.files, "file")}, ${bytes(m.bytes)}`, (m) => monthName(m.month), true)),
    el("div", { class: "pair" },
      card("Uploads, last 90 days",
        el("p", { class: "dim small" }, `${u.days.reduce((n, d) => n + d.files, 0).toLocaleString()} files, ${bytes(u.days.reduce((n, d) => n + d.bytes, 0))}.`),
        columns(u.days, (d) => d.files, (d) => `${dayName(d.day)}: ${plural(d.files, "file")}, ${bytes(d.bytes)}`, (d) => dayName(d.day))),
      card("How much is read",
        el("p", { class: "dim small" }, `${bytes(cold)} (${u.bytes ? Math.round((100 * cold) / u.bytes) : 0}%) hasn't been downloaded in 90 days, or at all since tracking began.`),
        shares(reads, (r) => el("span", {}, `Read ${r.label}`), (r) => `${plural(r.files, "file")} · ${bytes(r.bytes)}`, (r) => r.bytes, u.bytes))),
    el("div", { class: "pair" },
      card("What's stored",
        shares(u.types, (t) => el("span", { class: "mono" }, t.type), (t) => `${plural(t.files, "file")} · ${bytes(t.bytes)}`, (t) => t.bytes, u.bytes)),
      card("File sizes",
        shares(u.sizes, (s) => el("span", {}, s.label), (s) => `${plural(s.files, "file")} · ${bytes(s.bytes)}`, (s) => s.files, u.files))),
    el("div", { class: "pair" },
      card("Uploaders",
        shares(u.spread, (s) => el("span", {}, `With ${s.label}`), (s) => plural(s.uploaders, "uploader"), (s) => s.uploaders, u.uploaders),
        el("h4", {}, "New uploaders each month"),
        columns(u.months, (m) => m.new_uploaders, (m) => `${monthName(m.month)}: ${plural(m.new_uploaders, "new uploader")}`, (m) => monthName(m.month))),
      card("Using the most space",
        u.top.length
          ? shares(u.top, (t) => person(t.pubkey), (t) => `${plural(t.files, "file")} · ${bytes(t.bytes)}`, (t) => t.bytes, u.bytes)
          : el("p", { class: "dim" }, "Nobody yet."))),
    card("Moderation",
      el("p", { class: "dim small" },
        `${plural(u.bans.blobs, "file")} and ${plural(u.bans.pubkeys, "account")} banned, ` +
        `${u.bans.by_scanner.toLocaleString()} of the files by the scanner. ${plural(u.reports.total, "report")} kept.`),
      u.bans.months.length > 0 && [el("h4", {}, "Bans each month"),
        columns(u.bans.months, (m) => m.blobs + m.pubkeys, (m) => `${monthName(m.month)}: ${plural(m.blobs, "file")}, ${plural(m.pubkeys, "account")}`, (m) => monthName(m.month))],
      u.reports.months.length > 0 && [el("h4", {}, "Reports each month"),
        columns(u.reports.months, (m) => m.reports, (m) => `${monthName(m.month)}: ${plural(m.reports, "report")}`, (m) => monthName(m.month))]),
    el("p", { class: "dim small" }, `As of ${ago(u.at)}. Worked out again every five minutes, when someone looks.`));
}

// What's been banned as CSAM and not yet reported: a count by Evidence in
// the menu, and a reminder at the top of the overview.
function showUnreported() {
  const n = stats ? stats.unreported || 0 : 0;
  $("nav-evidence").hidden = !(stats && (stats.evidence || n));
  const count = (id, v, bad = false) => {
    $(id).textContent = v ? v.toLocaleString() : "";
    $(id).classList.toggle("bad", bad);
  };
  if (stats) {
    count("count-reports", stats.reports);
    count("count-bans", stats.banned_blobs + stats.banned_pubkeys);
    count("count-evidence", n || stats.evidence, n > 0);
  }
  $("unreported").hidden = !n;
  $("unreported").textContent = n;
  // Reported as soon as it reasonably can be: past a day, it says so louder.
  const oldest = stats && stats.oldest_unreported;
  const late = oldest && Date.now() / 1000 - oldest > 86400;
  put($("todo"), n > 0 && el("a", { class: late ? "todo late" : "todo", href: "#evidence" },
    el("span", {}, `${plural(n, "file")} banned as CSAM ${n === 1 ? "hasn't" : "haven't"} been reported to NCMEC yet` +
      (oldest ? `, the oldest banned ${ago(oldest)}.` : ".")),
    "Report now →"));
}

const YEAR = 365 * 24 * 3600;

async function loadEvidence() {
  const out = $("evidence-list");
  loading(out);
  const { items } = await api("/api/evidence");
  const unreported = items.filter((i) => !i.reported);
  stats.unreported = unreported.length;
  stats.oldest_unreported = unreported.length ? Math.min(...unreported.map((i) => i.banned)) : null;
  showUnreported();
  if (!items.length) { out.replaceChildren(el("p", { class: "card empty" }, "Nothing has been banned as CSAM.")); return; }
  out.replaceChildren(...items.map(evidenceCard));
}

function evidenceCard(e) {
  const reports = Array.isArray(e.reports) ? e.reports : [];
  const details = [
    `SHA-256: ${e.sha256}`,
    `File: ${e.type || "unknown type"}, ${e.size} bytes`,
    `First uploaded: ${when(e.uploaded)}`,
    `Uploaded by (Nostr pubkeys): ${e.owners.join(", ") || "unknown"}`,
    `Removed from public access: ${when(e.banned)}`,
    `User reports: ${reports.length}`,
    ...(e.context ? [`Other files from the uploader kept: ${e.context}`] : []),
  ].join("\n");
  const pre = el("pre", { class: "details", hidden: true }, details);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(details);
      say("Copied. Paste it into NCMEC's form.");
    } catch {
      pre.hidden = false;
      say("Couldn't copy here; select the text below instead.");
    }
  };
  const input = el("input", { type: "text", id: `report-${e.sha256}`, autocomplete: "off", inputmode: "numeric" });
  const save = async (ev) => {
    ev.preventDefault();
    const report = input.value.trim();
    if (!report) { input.focus(); return; }
    await api("/api/evidence/reported", { sha256: e.sha256, report });
    say("Saved. The copy is deleted in a year.");
    await loadEvidence();
  };
  return el("div", { class: "card stack" },
    el("div", { class: "row" },
      el("h3", { class: "grow mono" }, short(e.sha256)),
      e.reported ? badge("reported", "good") : badge(`not reported, banned ${ago(e.banned)}`, "bad")),
    el("dl", { class: "facts" },
      el("dt", {}, "Banned"), el("dd", {}, when(e.banned)),
      el("dt", {}, "File"), el("dd", {}, `${e.type || "unknown type"}, ${bytes(e.size)}, first uploaded ${when(e.uploaded)}`),
      el("dt", {}, "Uploaded by"), el("dd", {}, e.owners.length
        ? el("ul", { class: "people" }, e.owners.map((o) => el("li", {}, person(o), el("div", { class: "mono small dim" }, o))))
        : "unknown"),
      el("dt", {}, "User reports"), el("dd", {}, reports.length ? plural(reports.length, "report") : "none"),
      el("dt", {}, "Also kept"), el("dd", {}, e.context ? `${plural(e.context, "other file")} from the uploader` : "nothing else"),
      el("dt", {}, "On the server"), el("dd", { class: "mono" }, e.path),
      e.reported && [
        el("dt", {}, "NCMEC report"), el("dd", {}, `${e.reported.id}, made ${when(e.reported.at).slice(0, 10)}`),
        el("dt", {}, "Deleted on"), el("dd", {}, when(e.reported.at + YEAR).slice(0, 10)),
      ],
    ),
    !e.reported && [
      el("div", { class: "row" },
        button("Copy details", () => copy(), "btn primary"),
        el("a", { class: "btn ghost", href: "#help" }, "How to report")),
      pre,
      el("form", { class: "report", onsubmit: (ev) => save(ev).catch(fail) },
        el("div", { class: "field" }, el("label", { for: input.id }, "Reported? Enter NCMEC's report number"), input),
        el("button", { type: "submit", class: "btn" }, "Save")),
    ],
  );
}

async function loadReports() {
  const out = $("reports-list");
  loading(out);
  const rows = await api("/api/reports");
  if (!rows.length) { out.replaceChildren(el("p", { class: "empty" }, "Nothing flagged. All quiet.")); return; }
  out.replaceChildren(table(["Reported", "Type", "Blob", "Reporter", "Says", "Now"], rows.map((r) => [
    el("span", { class: "dim" }, when(r.created_at)),
    r.type ? badge(r.type, "accent") : "—",
    lookupLink(r.sha256),
    typeof r.reporter === "string" && /^[0-9a-f]{64}$/.test(r.reporter) ? person(r.reporter) : "—",
    el("div", { class: "says" }, typeof r.content === "string" ? r.content.slice(0, 300) : ""),
    r.banned ? badge("banned", "bad") : r.stored ? badge("stored") : badge("gone", "good"),
  ])));
}

let allBans = [];

async function loadBans() {
  loading($("bans-list"));
  allBans = await api("/api/bans");
  renderBans();
}

function renderBans() {
  const q = $("bans-filter").value.trim().toLowerCase();
  const kind = choice($("bans-kind"));
  const rows = allBans.filter((b) => (!kind || b.kind === kind) &&
    (!q || b.target.includes(q) || b.reason.toLowerCase().includes(q)));
  const shown = rows.slice(0, 500);
  if (!allBans.length) { $("bans-list").replaceChildren(el("p", { class: "empty" }, "No bans yet.")); return; }
  if (!rows.length) { $("bans-list").replaceChildren(el("p", { class: "empty" }, "No bans match.")); return; }
  put($("bans-list"),
    table(["Banned", "What", "Reason", el("span", { class: "vh" }, "Actions")], shown.map((b) => [
      el("span", { class: "dim" }, when(b.at)),
      el("span", { class: "row" }, badge(b.kind), b.kind === "pubkey" ? person(b.target) : lookupLink(b.target)),
      b.reason,
      tip(button("Unban", () => unban(b.kind, b.target).then((done) => done && loadBans()).catch(fail), "btn ghost sm"),
        b.kind === "pubkey" ? HELP.unbanPubkey : HELP.unbanBlob, true),
    ])),
    rows.length > shown.length && el("p", { class: "dim small" }, `The newest 500 of ${rows.length.toLocaleString()} are shown.`),
  );
}

// --- purging: what a cache in front still holds -----------------------------
//
// Blobs are served to be cached for a year, so a cache in front of this
// server (stats.cdn, as admin.cdn names it) may serve one long after it's
// deleted here. Each deletion's addresses gather in a list, kept in this
// browser, that the header offers to purge in the cache's own dashboard,
// 30 at a time as Cloudflare's custom purge takes them.

const PURGE_KEY = `purge:${location.host}`;
const PURGE_AT_ONCE = 30;

function purgeList() {
  try { return JSON.parse(localStorage.getItem(PURGE_KEY)) || []; } catch { return []; }
}

function setPurgeList(urls) {
  if (urls.length) localStorage.setItem(PURGE_KEY, JSON.stringify(urls));
  else localStorage.removeItem(PURGE_KEY);
  showPurge();
}

// This browser's own copies of what was deleted, dropped: each address is
// fetched afresh, past what's stored, so the browser keeps the server's 404
// in place of the picture. A few at a time, in the background.
function forget(addresses) {
  const left = [...(addresses || [])];
  const next = () => {
    const u = left.shift();
    if (!u) return;
    fetch(u, { cache: "reload", mode: "no-cors", credentials: "omit" }).catch(() => {}).finally(next);
  };
  for (let i = 0; i < 4; i++) next();
}

// Adds what a ban or removal took to the list, if there's a cache to purge.
function toPurge(urls) {
  if (!urls || !urls.length || !stats || !stats.cdn) return;
  setPurgeList([...new Set([...purgeList(), ...urls])]);
}

// A sentence for after a deletion: what's left to purge from the cache.
function purgeHint(r) {
  if (!r || !stats || !stats.cdn) return "";
  const left = (r.urls || []).length;
  return left ? ` Purge ${left === 2 ? "it" : "them"} from ${stats.cdn} too: Purge, top right.` : "";
}

function showPurge() {
  const n = purgeList().length;
  const b = $("purge");
  b.hidden = !n || !stats || !stats.cdn;
  b.textContent = `Purge ${n.toLocaleString()}`;
  b.title = stats && stats.cdn ? `Addresses ${stats.cdn} may still serve` : "";
}

function openPurge() {
  const d = $("dialog");
  const urls = purgeList();
  const cdn = stats.cdn;
  let from = 0;
  const area = el("textarea", { class: "urls", readonly: true, rows: 9, "aria-label": "Addresses to purge", spellcheck: "false" });
  const where = el("p", { class: "dim small" });
  const copy = el("button", { type: "button", class: "btn primary" });
  const show = () => {
    const batch = urls.slice(from, from + PURGE_AT_ONCE);
    area.value = batch.join("\n");
    where.textContent = `${from + 1}–${from + batch.length} of ${urls.length.toLocaleString()}` +
      (from + PURGE_AT_ONCE < urls.length ? " · copying moves on to the next 30" : "");
    copy.textContent = `Copy ${batch.length}`;
  };
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(area.value); } catch { area.select(); }
    say(`Copied. Paste them into ${cdn}'s purge.`);
    if (from + PURGE_AT_ONCE < urls.length) { from += PURGE_AT_ONCE; show(); }
  });
  d.replaceChildren(el("form", { onsubmit: (e) => e.preventDefault() },
    el("h2", { id: "dialog-title" }, `Purge from ${cdn}`),
    el("p", {}, `These files are deleted here, but ${cdn} may keep serving its copies for up to a year.`),
    cdn === "Cloudflare"
      ? el("p", {}, "In Cloudflare: Caching → Configuration → Purge Cache → Custom Purge. Paste the addresses, 30 at a time.")
      : el("p", {}, "Purge these addresses in it."),
    area, where,
    el("div", { class: "row end" },
      button("Close", () => d.close(), "btn ghost"),
      button("All purged", () => { setPurgeList([]); d.close(); say("Cleared."); }, "btn"),
      copy)));
  show();
  d.showModal();
  copy.focus();
}

// --- quick decisions: fine, and banned with a moment to undo ---------------
//
// Review and the lightbox share these. Looks fine marks a blob checked;
// a ban waits a few seconds to be undone, then is carried out, labelled
// explicit first if labelling is on.

const UNDO_FOR = 5000;
let waiting = null;

function looksFine(b) {
  api("/api/reviewed", { blobs: [b.sha256] }).catch(fail);
  if (stats && stats.labelling) api("/api/label", { blobs: [b.sha256], label: "clean" }).catch(fail);
}

// Bans `b` after UNDO_FOR, unless undone. One waits at a time: a new one
// carries out the last at once.
function banLater(b, { onUndo, onDone } = {}) {
  commitBan().catch(fail);
  waiting = { b, onUndo, onDone, timer: setTimeout(() => commitBan().catch(fail), UNDO_FOR) };
  say("Not allowed: it'll be banned.", false, { label: "Undo", fn: undoBan });
}

async function commitBan() {
  const p = waiting;
  if (!p) return;
  waiting = null;
  clearTimeout(p.timer);
  // Its Undo is over.
  if ($("status").textContent.includes("it'll be banned")) $("status").replaceChildren();
  // Labelled first: the scanner learns from the file, which the ban takes.
  if (stats && stats.labelling) await api("/api/label", { blobs: [p.b.sha256], label: "explicit" }).catch(fail);
  const r = await api("/api/ban", { blobs: [p.b.sha256], reason: "Not allowed" });
  toPurge(r.urls);
  forget(r.urls);
  if (p.onDone) p.onDone();
}

function undoBan() {
  const p = waiting;
  if (!p) return;
  waiting = null;
  clearTimeout(p.timer);
  if (p.onUndo) p.onUndo();
  say("Undone.");
}

// What can be done to a stored blob, the same wherever it's shown: a Media
// tile's menu, the lightbox, its own page. `on` hears what became of it:
// `done("Banned" | "Removed" | null)` (null for an undo), `checked()`,
// and `banned()` once a ban is carried out. Each says whether it was done.
function blobActions(b, on = {}) {
  const done = (what) => on.done && on.done(what);
  return {
    fine() {
      looksFine(b);
      b.checked = true;
      if (on.checked) on.checked();
      return true;
    },
    ban() {
      done("Banned");
      banLater(b, { onUndo: () => done(null), onDone: on.banned });
      return true;
    },
    async remove() {
      const a = await ask({
        title: "Remove it?",
        text: "It's deleted for everyone who uploaded it, but not banned, so it can be uploaded again.",
        action: "Remove",
        busy: "Removing…",
        run: (given, doing) => { doing("Removing"); return api("/api/remove", { blobs: [b.sha256] }); },
      });
      if (!a) return false;
      toPurge(a.result.urls);
      forget(a.result.urls);
      done("Removed");
      if (purgeHint(a.result)) say(`Removed.${purgeHint(a.result)}`);
      return true;
    },
    async csam() {
      await commitBan();
      if (!(await banCsam(b.sha256, { stay: true }))) return false;
      done("Banned");
      return true;
    },
  };
}

// The same, as menu items; `then` runs after each that's done.
function blobMenu(act, then = () => {}) {
  const run = (fn) => async () => {
    try { if (await fn()) then(); } catch (e) { fail(e); }
  };
  return [
    ["Looks fine", run(act.fine)],
    ["Ban", run(act.ban), true],
    ["Remove…", run(act.remove), true],
    null,
    ["Child abuse…", run(act.csam), true],
  ];
}

// --- review: one upload at a time ------------------------------------------
//
// New pictures and video, newest first, that nobody has reviewed or
// labelled. Looks fine marks one checked, never to be shown here again; Not
// allowed bans it after a few seconds' chance to undo. With labelling on,
// each teaches the scanner too.

const review = { queue: [], at: 0, next: null, loaded: false, loading: false, done: 0 };

async function loadReview(fresh = true) {
  if (review.loading) return;
  review.loading = true;
  if (fresh) Object.assign(review, { queue: [], at: 0, next: null });
  if (!review.queue.length) put($("review"), el("p", { class: "card empty" }, "Finding new uploads…"));
  try {
    // A page may come back short of new ones; look a little further back.
    for (let i = 0; i < 4; i++) {
      const q = new URLSearchParams({ kind: "media", new: "1" });
      if (review.next) q.set("before", review.next);
      const page = await api(`/api/media?${q}`);
      const seen = new Set(review.queue.map((b) => b.sha256));
      review.queue.push(...page.blobs.filter((b) => !seen.has(b.sha256)));
      review.next = page.next;
      if (!review.next || review.queue.length - review.at >= 10) break;
    }
  } finally {
    review.loading = false;
    review.loaded = true;
  }
  renderReview();
}

function renderReview() {
  const box = $("review");
  const b = review.queue[review.at];
  const left = review.queue.length - review.at;
  if (!b) {
    put(box, el("div", { class: "card review-done" },
      el("div", { class: "big-check", "aria-hidden": "true" }, "✓"),
      el("h3", {}, "All caught up"),
      el("p", { class: "dim" }, review.done ? `You reviewed ${plural(review.done, "upload")}. Nice work.` : "There's nothing new to review."),
      button("Check again", () => loadReview(true).catch(fail), "btn")));
    return;
  }
  if (left < 5 && review.next && !review.loading) loadReview(false).catch(fail);
  const name = short(b.sha256);
  const type = b.media || b.type || "";
  const pic = el("div", { class: "review-pic" });
  blurred(pic, type.startsWith("video/")
    ? el("video", { src: b.url, poster: thumb(b, 1280), controls: true, muted: true, preload: "none", "aria-label": `Video ${name}` })
    : el("img", { src: thumb(b, 1280), alt: `Upload ${name}` }));
  put(box, el("div", { class: "review" },
    el("div", { class: "review-top" },
      el("span", { class: "dim" }, `${review.done ? `${review.done.toLocaleString()} reviewed · ` : ""}${left}${review.next ? "+" : ""} to go`),
      el("span", { class: "grow" }),
      blurSwitch()),
    el("div", { class: "card review-card" },
      pic,
      el("div", { class: "review-meta" },
        lookupLink(b.sha256),
        el("span", { class: "dim" }, `${bytes(b.size)} · ${ago(b.uploaded)}`))),
    el("div", { class: "review-actions" },
      button([el("span", { class: "glyph" }, "✓"), "Looks fine", el("kbd", {}, "1")], () => decide("fine"), "btn big good"),
      button([el("span", { class: "glyph" }, "✕"), "Not allowed", el("kbd", {}, "2")], () => decide("ban"), "btn big bad")),
    el("div", { class: "review-more" },
      button(["Skip ", el("kbd", {}, "space")], () => decide("skip"), "btn ghost sm"),
      button("Child abuse…", () => decide("csam"), "btn ghost sm warn"))));
}

async function decide(what) {
  const b = review.queue[review.at];
  if (!b) return;
  if (what === "csam") {
    await commitBan();
    try {
      if (!(await banCsam(b.sha256, { stay: true }))) return;
    } catch (e) { fail(e); return; }
  } else if (what === "fine") {
    looksFine(b);
  } else if (what === "ban") {
    banLater(b, {
      onUndo: () => {
        review.queue.splice(review.at, 0, b);
        review.done = Math.max(0, review.done - 1);
        renderReview();
      },
    });
  }
  if (what !== "skip") review.done++;
  review.at++;
  renderReview();
}

// Leaving Review: the waiting ban is carried out, and sent on.
function leaveReview() {
  commitBan().catch(fail);
}

document.addEventListener("keydown", (e) => {
  if ($("tab-review").hidden || $("dialog").open) return;
  if (e.target.closest("input, textarea, select, [contenteditable]") || e.metaKey || e.ctrlKey || e.altKey) return;
  const key = { "1": "fine", f: "fine", "2": "ban", x: "ban", " ": "skip" }[e.key.toLowerCase()];
  if (key) { e.preventDefault(); decide(key).catch(fail); }
  if (e.key.toLowerCase() === "u" || e.key.toLowerCase() === "z") { e.preventDefault(); undoBan(); }
});
window.addEventListener("pagehide", leaveReview);

// Presses `btn` when it scrolls near view, so a list loads more as it's read
// to its end: once for a button that's replaced after, or each time.
function loadOnSight(btn, once = false) {
  const io = new IntersectionObserver((entries) => {
    if (!btn.isConnected) return io.disconnect();
    if (entries.some((e) => e.isIntersecting) && !btn.hidden && !btn.disabled) {
      if (once) io.disconnect();
      btn.click();
    }
  }, { rootMargin: "800px 0px" });
  io.observe(btn);
}

// --- lightbox: Ditto's gallery, with the quick decisions --------------------
//
// One picture or video at a time, full screen, from a grid of tiles. Swipe
// or arrow keys to move, swipe down or Escape to close. Fine and Ban are at
// the bottom, as in Review, with Remove and Child abuse… under ⋯.

const lb = { tiles: [], at: 0, grid: null, shown: new Set(), drag: null, sliding: false };
const SWIPE = 60;

function openLightbox(t) {
  lb.grid = t.parentElement;
  lb.tiles = visibleTiles();
  lb.at = Math.max(0, lb.tiles.indexOf(t));
  const d = $("lightbox");
  // Messages, Undo among them, show over the lightbox while it's open; only
  // the panel beside them is redrawn.
  d.replaceChildren(el("div", { class: "lb-panel" }), TOASTS);
  d.showModal();
  renderLightbox();
}

const visibleTiles = () => [...lb.grid.children].filter((t) => !t.hidden && t._blob);

function closeLightbox() {
  const d = $("lightbox");
  if (d.open) d.close();
}

const TOASTS = $("toasts");

$("lightbox").addEventListener("close", () => {
  document.body.append(TOASTS);
  $("lightbox").replaceChildren();
});

// A slide: the picture or video, blurred until shown unless blurring is
// off, and what's become of it, if anything.
function slide(t, current) {
  const b = t._blob;
  const type = b.media || b.type || "";
  const name = short(b.sha256);
  const media = type.startsWith("video/")
    ? el("video", { src: current ? b.url : undefined, poster: thumb(b, 1280), controls: true, playsinline: true, preload: "none", "aria-label": `Video ${name}` })
    : el("img", { src: thumb(b, 1280), alt: `Upload ${name}`, draggable: "false" });
  const wrap = el("div", { class: lb.shown.has(b.sha256) ? "blur shown" : "blur" }, media);
  if (current) {
    wrap.append(button(el("span", {}, icon("eye"), "Show"), () => {
      lb.shown.add(b.sha256);
      wrap.classList.add("shown");
    }, "reveal lb-reveal"));
  }
  const gone = t.querySelector(".gone");
  return el("div", { class: "lb-slot" }, wrap, gone && el("div", { class: "lb-gone" }, gone.textContent));
}

function renderLightbox() {
  const d = $("lightbox").querySelector(".lb-panel");
  if (!d) return;
  const t = lb.tiles[lb.at];
  if (!t) return closeLightbox();
  const b = t._blob;
  const strip = el("div", { class: "lb-strip" });
  for (const i of [lb.at - 1, lb.at, lb.at + 1]) {
    if (!lb.tiles[i]) continue;
    const s = slide(lb.tiles[i], i === lb.at);
    s.style.transform = `translateX(${(i - lb.at) * 100}%)`;
    strip.append(s);
  }
  // The next few pictures, fetched ahead so a swipe lands on one.
  for (const i of [lb.at + 1, lb.at + 2, lb.at - 1]) {
    const n = lb.tiles[i] && lb.tiles[i]._blob;
    if (n) new Image().src = thumb(n, 1280);
  }
  const stage = el("div", { class: "lb-stage" }, strip);
  swipes(stage, strip);
  const gone = t.classList.contains("done");
  const owners = Array.isArray(b.owners) ? b.owners : [];
  const [more, list] = menu(short(b.sha256),
    blobMenu(t._act, () => step(1)).filter((i) => i && !["Looks fine", "Ban"].includes(i[0])));
  // A round button, as tall as Fine and Ban beside it.
  more.className = "lb-btn lb-more-btn";
  put(d,
    el("div", { class: "lb-top" },
      el("span", { class: "lb-count" }, `${lb.at + 1} / ${lb.tiles.length}${lb.grid === $("media-grid") && mediaNext ? "+" : ""}`),
      el("span", { class: "grow" }),
      button(icon(document.body.classList.contains("unblurred") ? "eyeOff" : "eye"), () => {
        setBlur(document.body.classList.contains("unblurred"));
        renderLightbox();
      }, "lb-btn", { "aria-label": "Blur on or off", title: "Blur on or off" }),
      el("a", { class: "lb-btn", href: b.url, target: "_blank", rel: "noopener noreferrer", "aria-label": "Open the file", title: "Open the file" }, "↗"),
      button(icon("x"), closeLightbox, "lb-btn", { "aria-label": "Close", title: "Close (Esc)" })),
    stage,
    lb.at > 0 && button("‹", () => step(-1), "lb-nav prev", { "aria-label": "Previous" }),
    lb.at < lb.tiles.length - 1 && button("›", () => step(1), "lb-nav next", { "aria-label": "Next" }),
    el("div", { class: "lb-bottom" },
      el("div", { class: "lb-who" },
        owners[0] && person(owners[0]),
        el("span", {}, `${bytes(b.size)} · ${ago(b.uploaded)}`)),
      el("div", { class: "lb-actions" },
        button([el("span", { class: "glyph" }, "✓"), "Fine", el("kbd", {}, "1")], () => decideHere("fine"), "btn good", { disabled: gone }),
        button([el("span", { class: "glyph" }, "✕"), "Ban", el("kbd", {}, "2")], () => decideHere("ban"), "btn bad", { disabled: gone }),
        el("span", { class: "lb-more" }, more, list))));
}

// Fine or Ban the one showing, then on to the next.
function decideHere(what) {
  const t = lb.tiles[lb.at];
  if (!t || t.classList.contains("done")) return;
  t._act[what]();
  // Undone, the lightbox goes back to it.
  if (what === "ban" && waiting) {
    const undone = waiting.onUndo;
    waiting.onUndo = () => {
      if (undone) undone();
      const i = lb.tiles.indexOf(t);
      if ($("lightbox").open && i >= 0) { lb.at = i; renderLightbox(); }
    };
  }
  step(1);
}

// To the next (1) or last (-1), sliding there, and loading older ones as
// the end of what's loaded nears.
async function step(dir) {
  if (lb.sliding) return;
  const to = lb.at + dir;
  if (dir > 0 && to >= lb.tiles.length - 3 && lb.grid === $("media-grid") && mediaNext) {
    await loadMedia(false).catch(fail);
    lb.tiles = visibleTiles();
  }
  const strip = $("lightbox").querySelector(".lb-strip");
  if (!lb.tiles[to] || !strip) {
    if (strip) { strip.style.transition = "transform .2s ease"; strip.style.transform = "none"; }
    return;
  }
  lb.sliding = true;
  strip.style.transition = "transform .22s ease";
  strip.style.transform = `translateX(${-dir * 100}%)`;
  setTimeout(() => {
    lb.sliding = false;
    lb.at = to;
    renderLightbox();
  }, 220);
}

// Swipe sideways to move, down to close, as Ditto's lightbox does. A tap
// beside the picture closes it too.
function swipes(stage, strip) {
  stage.addEventListener("pointerdown", (e) => {
    if (e.target.closest("video, button, a, .menu") || lb.sliding) return;
    lb.drag = { x: e.clientX, y: e.clientY, axis: null, id: e.pointerId };
    stage.setPointerCapture(e.pointerId);
  });
  stage.addEventListener("pointermove", (e) => {
    const g = lb.drag;
    if (!g || g.id !== e.pointerId) return;
    const dx = e.clientX - g.x, dy = e.clientY - g.y;
    if (!g.axis && Math.hypot(dx, dy) > 8) g.axis = Math.abs(dx) > Math.abs(dy) ? "x" : "y";
    strip.style.transition = "none";
    if (g.axis === "x") strip.style.transform = `translateX(${dx}px)`;
    if (g.axis === "y" && dy > 0) {
      strip.style.transform = `translateY(${dy}px)`;
      $("lightbox").style.setProperty("--fade", Math.max(0.3, 1 - dy / 400));
    }
  });
  const end = (e) => {
    const g = lb.drag;
    if (!g || g.id !== e.pointerId) return;
    lb.drag = null;
    const dx = e.clientX - g.x, dy = e.clientY - g.y;
    $("lightbox").style.removeProperty("--fade");
    if (g.axis === "x" && Math.abs(dx) > SWIPE) return step(dx < 0 ? 1 : -1);
    if (g.axis === "y" && dy > SWIPE * 1.6) return closeLightbox();
    if (!g.axis && e.target.classList.contains("lb-slot")) return closeLightbox();
    strip.style.transition = "transform .2s ease";
    strip.style.transform = "none";
  };
  stage.addEventListener("pointerup", end);
  stage.addEventListener("pointercancel", end);
}

$("lightbox").addEventListener("keydown", (e) => {
  if ($("dialog").open || e.target.closest("input, textarea") || e.metaKey || e.ctrlKey || e.altKey) return;
  const k = e.key.toLowerCase();
  const act = { arrowright: () => step(1), arrowleft: () => step(-1), "1": () => decideHere("fine"), "2": () => decideHere("ban"), u: undoBan }[k];
  if (act) { e.preventDefault(); act(); }
});

// --- media -----------------------------------------------------------------

let mediaNext = null;

async function loadMedia(fresh) {
  const grid = $("media-grid"), more = $("media-more");
  if (fresh) { mediaNext = null; grid.replaceChildren(); }
  mediaLoaded = true;
  more.disabled = true;
  $("media-status").textContent = "Loading…";
  try {
    const q = new URLSearchParams({ kind: choice($("media-kind")) });
    if (mediaNext) q.set("before", mediaNext);
    const page = await api(`/api/media?${q}`);
    mediaNext = page.next;
    grid.append(...(await showable(page.blobs)).map(tile));
  } finally {
    more.disabled = false;
    more.hidden = !mediaNext;
    filterMedia();
  }
}

// Uploads since the newest shown, added at the top; what's shown stays.
async function checkNewMedia() {
  if (!mediaLoaded) return loadMedia(true);
  const grid = $("media-grid");
  const shown = new Set([...grid.children].map((t) => t.dataset.hash));
  const page = await api(`/api/media?${new URLSearchParams({ kind: choice($("media-kind")) })}`);
  const fresh = [];
  for (const b of page.blobs) {
    if (shown.has(b.sha256)) break;
    fresh.push(b);
  }
  grid.prepend(...(await showable(fresh)).map(tile));
  filterMedia();
  say(fresh.length ? `${plural(fresh.length, "new upload")}, at the top.` : "Nothing new since.");
}

function filterMedia() {
  const unlabelled = $("media-unlabelled").checked;
  let shown = 0;
  for (const t of $("media-grid").children) {
    t.hidden = t.classList.contains("unreadable") || (unlabelled && !!t.dataset.label);
    if (!t.hidden) shown++;
  }
  $("media-status").textContent = shown
    ? `${shown.toLocaleString()} shown`
    : mediaNext ? "None among the newest; load older ones." : "Nothing here.";
}

// Which of `blobs` can be shown, their thumbnails all tried at once before
// any is shown: an encrypted attachment that claims to be a picture has
// none, and isn't shown at all. One slower than `wait` is shown, and its
// tile hides itself if it fails after.
function showable(blobs, wait = 4000) {
  return Promise.all(blobs.map((b) => {
    if (!(b.media || b.type || "").startsWith("image/")) return true;
    return new Promise((resolve) => {
      const img = new Image();
      const timer = setTimeout(() => resolve(true), wait);
      img.onload = () => { clearTimeout(timer); resolve(true); };
      img.onerror = () => { clearTimeout(timer); resolve(false); };
      img.src = thumb(b);
    });
  })).then((ok) => blobs.filter((_, i) => ok[i]));
}

// A tile whose picture won't show, an encrypted attachment that claims to
// be one most likely: out of the grid, and out of the lightbox's way.
function unreadable(t) {
  t.classList.add("unreadable");
  t.hidden = true;
  if (t.parentElement === $("media-grid")) filterMedia();
}

function tile(b) {
  const t = el("li", { class: "tile", "data-hash": b.sha256, "data-label": b.label || undefined });
  const name = short(b.sha256);
  // What the bytes are, when the server has looked, over what was declared.
  const type = b.media || b.type || "";
  // A thumbnail, blurred unless blurring is off: a video's is its first
  // frame, or if there's none a placeholder, and the video itself isn't
  // loaded until it's opened. Either opens the lightbox.
  const video = type.startsWith("video/");
  const placeholder = () => el("div", { class: "video-ph", "aria-hidden": "true" }, icon("play"));
  const pic = el("div", { class: "pic" },
    el("div", { class: "blur" }, el("img", {
      src: thumb(b),
      alt: `${video ? "Video" : "Image"} ${name}`,
      onerror: (e) => video ? e.target.parentElement.replaceWith(placeholder()) : unreadable(t),
    })),
    button(el("span", {}, video ? [icon("play"), "Play"] : [icon("eye"), "View"]), () => openLightbox(t), "open",
      { "aria-label": `Open ${name}` }));
  const badges = el("div", { class: "badges" });
  const showBadges = () => put(badges,
    b.label && badge(b.label, b.label === "explicit" ? "bad" : "good"),
    !b.label && b.checked && badge("checked", "good"),
    b.unscanned && badge("unscanned"),
  );
  showBadges();
  const note = el("p", { class: "note", role: "status" });

  // Marked banned or removed, or not (an undo): `what` says which.
  const done = (what) => {
    for (const g of pic.querySelectorAll(".gone")) g.remove();
    if (what) pic.append(el("div", { class: "gone" }, what));
    t.classList.toggle("done", !!what);
    trigger.disabled = !!what;
  };
  // What the lightbox needs to show it, and to mark it.
  t._blob = b;
  t._done = done;
  t._checked = () => { b.checked = true; showBadges(); };
  t._act = blobActions(b, { done, checked: () => t._checked() });
  const items = blobMenu(t._act);
  const [trigger, list] = menu(name, items);

  t.append(pic, badges, el("div", { class: "bar" },
    el("div", { class: "who" }, lookupLink(b.sha256), el("span", {}, `${bytes(b.size)} · ${when(b.uploaded).slice(0, 10)}`)),
    trigger,
    list,
  ), note);
  return t;
}

// --- lookups ---------------------------------------------------------------

function parseTarget(text) {
  const t = text.trim();
  if (t.startsWith("npub1")) {
    const hex = npubToHex(t);
    return hex ? { kind: "pubkey", hex } : null;
  }
  const m = t.toLowerCase().match(/[0-9a-f]{64}/);
  if (!m) return null;
  // A URL is a blob; a bare 64-hex string could be either, so it's tried as
  // a blob first.
  return { kind: /^[0-9a-f]{64}$/.test(t.toLowerCase()) ? "either" : "blob", hex: m[0] };
}

const lookup = (text) => go(`lookup/${encodeURIComponent(text)}`);
const again = () => runLookup($("lookup-input").value).catch(fail);

async function runLookup(text) {
  $("lookup-input").value = text;
  const out = $("lookup-result");
  const target = parseTarget(text);
  if (!target) {
    out.replaceChildren(el("p", { class: "notice bad" }, "That isn't a blob's hash or URL, a hex pubkey, or an npub."));
    return;
  }
  loading(out);
  if (target.kind === "pubkey") return renderPubkey(await api(`/api/pubkey/${target.hex}`));
  const b = await api(`/api/blob/${target.hex}`);
  // Bare hex that names no blob here is taken for a pubkey.
  if (target.kind === "either" && !b.stored && !b.ban && !b.reports.length) {
    return renderPubkey(await api(`/api/pubkey/${target.hex}`));
  }
  renderBlob(b);
}

// Runs an action from a lookup, then shows the lookup again as it now is.
const redo = (fn) => () => fn().then((done) => done && again()).catch(fail);

function renderBlob(b) {
  const s = b.stored;
  const csam = b.ban && b.ban.reason === "CSAM";
  const preview = el("div", { class: "preview" });
  const type = s ? s.type || "" : "";
  const media = type.startsWith("image/") || type.startsWith("video/");
  const show = () => {
    const name = short(b.sha256);
    const m = type.startsWith("video/")
      ? el("video", { src: s.url, poster: thumb(b, 1280), controls: true, muted: true, preload: "none", "aria-label": `Video ${name}` })
      : el("img", { src: thumb(b, 1280), alt: `Image ${name}` });
    blurred(preview, m).focus();
  };
  // The same actions as a Media tile's, as buttons. What became of it shows
  // at once; the page is read again once a ban is carried out.
  const state = el("span", {}, b.ban ? badge("banned", "bad") : s ? badge("stored", "good") : badge("not stored"));
  const act = blobActions({ sha256: b.sha256, ...(s || {}) }, {
    done: (what) => {
      put(state, what ? badge(what.toLowerCase(), "bad") : badge("stored", "good"));
      for (const x of buttons) x.disabled = !!what;
    },
    checked: () => put(state, badge("checked", "good")),
    banned: again,
  });
  // Remove and Child abuse are done when they return: read the page again.
  const press = (fn, reread = false) => async () => {
    try { if ((await fn()) && reread) again(); } catch (e) { fail(e); }
  };
  const buttons = b.ban ? [] : [
    s && tip(button("Looks fine", press(act.fine), "btn"), HELP.fine),
    tip(button("Ban", press(act.ban), "btn danger"), HELP.ban),
    s && tip(button("Remove…", press(act.remove, true), "btn ghost warn"), HELP.remove),
    tip(button("Child abuse…", press(act.csam, true), "btn soft-danger"), HELP.csam),
  ].filter(Boolean).map((w) => w.querySelector("button"));
  const actions = b.ban
    ? [tip(button("Unban", redo(() => unban("blob", b.sha256))), HELP.unbanBlob)]
    : buttons.map((x) => x.parentElement);
  $("lookup-result").replaceChildren(el("div", { class: "card stack" },
    el("div", { class: "row" }, el("h3", { class: "grow" }, "Blob"), state),
    el("dl", { class: "facts" },
      el("dt", {}, "SHA-256"), el("dd", { class: "mono" }, b.sha256),
      s && [el("dt", {}, "Stored"), el("dd", {}, `${bytes(s.size)}, ${s.type || "no type"}, first uploaded ${when(s.uploaded)}${s.unscanned ? ", not scanned yet" : ""}`)],
      el("dt", {}, "Uploaded by"), el("dd", {}, b.owners.length ? el("ul", { class: "people" }, b.owners.map((o) => el("li", {}, person(o)))) : "—"),
      b.ban && [el("dt", {}, "Ban"), el("dd", {}, `${when(b.ban.at)}${b.ban.reason ? `: ${b.ban.reason}` : ""}`)],
      el("dt", {}, "Reports"), el("dd", {}, b.reports.length
        ? el("ul", {}, b.reports.map((r) => el("li", {}, `${when(r.created_at)} · ${r.type || "no type"} · ${typeof r.content === "string" ? r.content.slice(0, 200) : ""}`)))
        : "None"),
    ),
    el("div", { class: "row" },
      actions,
      s && stats && stats.scan && media && tip(button("Check score", async () => {
        try {
          const r = await api(`/api/score/${b.sha256}`);
          say(r.score === null ? r.outcome : `It scores ${r.score.toFixed(3)}${r.refused ? ", over the line: it would be refused." : ", under the line."}`);
        } catch (e) { fail(e); }
      }, "btn ghost"), HELP.score),
      s && !csam && (media
        ? tip(button("Show", show, "btn ghost"), HELP.show)
        : tip(el("a", { class: "btn ghost", href: s.url, target: "_blank", rel: "noopener noreferrer" }, "Open in a new tab"), HELP.open)),
    ),
    csam && el("p", { class: "notice bad" }, "Banned as CSAM: there's no preview, by design. ",
      el("a", { href: "#evidence" }, "See Evidence")),
    preview,
  ));
}

function renderPubkey(p) {
  put($("lookup-result"), profileCard(p), p.blobs.length > 0 && theirBlobs(p.pubkey, p.blobs, p.next));
}

// A pubkey's profile, as Ditto shows one, with what they've stored here.
function profileCard(p) {
  const banner = el("div", { class: "profile-banner" });
  const npub = hexToNpub(p.pubkey);
  const name = el("h3", { class: "profile-name" }, `${npub.slice(0, 12)}…${npub.slice(-4)}`);
  const about = el("p", { class: "profile-about", hidden: true });
  const none = el("span", { class: "badge", hidden: true }, "no Nostr profile");
  profile(p.pubkey).then((prof) => {
    if (!prof) { none.hidden = false; name.textContent = "Anonymous"; name.classList.add("dim"); return; }
    if (prof.name) name.textContent = prof.name;
    if (prof.about) { about.textContent = prof.about; about.hidden = false; }
    if (prof.banner) {
      const img = el("img", { src: prof.banner, alt: "", referrerpolicy: "no-referrer" });
      img.addEventListener("load", () => banner.replaceChildren(img));
    }
  });
  const copyNpub = async () => {
    try { await navigator.clipboard.writeText(npub); say("Copied the npub."); }
    catch { say("Couldn't copy here.", true); }
  };
  const s = p.stats;
  const figure = (n, label) => el("span", {}, el("b", {}, n), ` ${label}`);
  return el("div", { class: "card profile" },
    banner,
    el("div", { class: "profile-top" },
      avatar(p.pubkey, "lg"),
      el("div", { class: "profile-actions" },
        p.ban
          ? tip(button("Unban", redo(() => unban("pubkey", p.pubkey))), HELP.unbanPubkey, true)
          : tip(button("Ban", redo(() => banPubkey(p.pubkey, p.owned)), "btn danger"), HELP.banPubkey, true)),
    ),
    el("div", { class: "profile-body" },
      el("div", { class: "row" }, name, none, p.ban && badge("banned", "bad")),
      el("button", { type: "button", class: "npub", title: "Copy the npub", onclick: copyNpub },
        `${npub.slice(0, 16)}…${npub.slice(-6)}`),
      about,
      s && el("div", { class: "profile-stats" },
        figure(p.owned.toLocaleString(), p.owned === 1 ? "file" : "files"),
        figure(bytes(s.bytes), "stored"),
        figure(s.media.toLocaleString(), "pictures & video"),
        figure(s.reports.toLocaleString(), s.reports === 1 ? "report" : "reports"),
        s.first && el("span", { class: "dim" }, ago(s.first) === ago(s.last)
          ? `uploaded ${ago(s.last)}`
          : `first upload ${ago(s.first)}, latest ${ago(s.last)}`)),
      p.ban && el("p", { class: "notice bad" }, `Banned ${when(p.ban.at)}${p.ban.reason ? `: ${p.ban.reason}` : ""}`),
    ),
  );
}

// A pubkey's blobs: their pictures and video as the Media tab shows them,
// or every blob as a list. The choice is remembered.
// Only this card is redrawn, for older files or the other view, so the
// profile above, and where the page is scrolled to, stay as they are.
function theirBlobs(pubkey, blobs, next) {
  const view = localStorage.getItem("pubkeyView") || "grid";
  const redraw = (b, n) => card.replaceWith(theirBlobs(pubkey, b, n));
  const older = next && button("Load older", async () => {
    older.disabled = true;
    try {
      const more = await api(`/api/pubkey/${pubkey}?cursor=${next}`);
      redraw(blobs.concat(more.blobs), more.next);
    } catch (e) { older.disabled = false; fail(e); }
  });
  const choose = el("fieldset", { class: "seg" }, el("legend", { class: "vh" }, "Show as"),
    ["grid", "list"].map((v) => el("label", {},
      el("input", { type: "radio", name: "pubkey-view", value: v, checked: v === view }),
      el("span", {}, v === "grid" ? "Grid" : "List"))));
  choose.addEventListener("change", () => {
    localStorage.setItem("pubkeyView", choice(choose));
    redraw(blobs, next);
  });
  const media = blobs.filter((r) => /^(image|video)\//.test(r.type || ""));
  const others = blobs.length - media.length;
  let body;
  if (view === "grid") {
    body = [
      media.length
        ? el("ul", { class: "grid", "aria-label": "Their pictures and video" }, media.map(tile))
        : el("p", { class: "dim" }, "None of these are pictures or video."),
      others > 0 && el("p", { class: "dim small" },
        `${plural(others, "other file")} ${others === 1 ? "isn't a picture or video" : "aren't pictures or video"}. List shows every file.`),
    ];
  } else {
    body = table(["Uploaded", "Blob", "Type", "Size"], blobs.map((r) => [
      el("span", { class: "dim" }, when(r.uploaded)),
      lookupLink(r.sha256),
      r.type || "—",
      bytes(r.size),
    ]));
  }
  if (older) loadOnSight(older, true);
  const card = el("div", { class: "card stack" },
    el("div", { class: "toolbar" }, el("h3", { class: "grow" }, "Their files, newest first"),
      view === "grid" && blurSwitch(), choose),
    body,
    older && el("div", { class: "row center more" }, older),
  );
  return card;
}

// --- actions: each says whether it was done --------------------------------

// Bans a blob as child sexual abuse material. Then to Evidence, where it's
// reported, unless `stay` (as in Review, which carries on). Whether it was.
async function banCsam(hash, { stay = false } = {}) {
  const a = await ask({
    title: "Is this child sexual abuse material?",
    text: [
      "It will be hidden from everyone, and whoever uploaded it banned. A locked copy of it, and of everything else they uploaded, is kept for the report you'll make next. It won't be shown here again.",
      "For anything else, use Ban.",
    ],
    action: "Yes, ban it",
    busy: "Banning…",
    run: (given, doing) => {
      doing("Keeping a copy, then deleting");
      return api("/api/csam", { sha256: hash });
    },
  });
  if (!a) return false;
  const r = a.result;
  toPurge(r.urls);
  forget(r.urls);
  const here = r.kept ? "Banned, and a copy kept. Next: report it to NCMEC from Evidence." : "Banned. It wasn't stored here, so there's nothing to keep.";
  say(`${here}${purgeHint(r)}`);
  if (r.kept) {
    stats.unreported = (stats.unreported || 0) + 1;
    stats.oldest_unreported = stats.oldest_unreported || Math.floor(Date.now() / 1000);
    stats.evidence = (stats.evidence || 0) + 1;
  }
  showUnreported();
  if (!stay && r.kept) go("evidence");
  return true;
}

async function banPubkey(pubkey, owned) {
  const a = await ask({
    title: `Ban ${short(pubkey)}?`,
    text: `They can't upload any more, and their ${plural(owned, "file")} are deleted and banned.`,
    reason: { label: "Reason (optional)" },
    action: owned ? `Ban and delete ${plural(owned, "file")}` : "Ban",
    busy: "Banning…",
    run: (given, doing) => {
      doing(owned ? `Deleting ${plural(owned, "file")}` : "Banning");
      return api("/api/ban", { pubkeys: [pubkey], reason: given.reason });
    },
  });
  if (!a) return false;
  const r = a.result;
  toPurge(r.urls);
  forget(r.urls);
  say(`Banned; ${plural(r.removed, "file")} deleted.${purgeHint(r)}`);
  return true;
}

async function unban(kind, hex) {
  const target = kind === "pubkey" ? { pubkeys: [hex] } : { blobs: [hex] };
  const a = await ask({
    title: `Unban ${short(hex)}?`,
    text: kind === "pubkey" ? "It can upload again. Its blobs stay banned." : "It can be uploaded again.",
    action: "Unban",
    danger: false,
    busy: "Unbanning…",
    run: () => api("/api/unban", target),
  });
  if (!a) return false;
  say("Unbanned.");
  return true;
}

// --- start -----------------------------------------------------------------

setBlur(localStorage.getItem("blur") !== "0");
$("sign-in").addEventListener("click", signIn);
$("sign-out").addEventListener("click", signOut);
$("purge").addEventListener("click", openPurge);
// Skips to the content without changing the #hash, which names the section.
document.querySelector(".skip").addEventListener("click", (e) => {
  e.preventDefault();
  $("main").focus();
});
$("blur-media").addEventListener("change", (e) => setBlur(e.target.checked));
$("media-unlabelled").addEventListener("change", filterMedia);
$("media-reload").addEventListener("click", () => checkNewMedia().catch(fail));
$("media-kind").addEventListener("change", () => loadMedia(true).catch(fail));
$("media-more").addEventListener("click", () => loadMedia(false).catch(fail));
loadOnSight($("media-more"));
$("bans-filter").addEventListener("input", renderBans);
$("bans-kind").addEventListener("change", renderBans);
$("lookup-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const text = $("lookup-input").value.trim();
  if (text) lookup(text);
});
// "/" goes to the search bar, from anywhere but a field or a dialog.
document.addEventListener("keydown", (e) => {
  if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey || $("app").hidden) return;
  if (e.target.closest("input, textarea, select, [contenteditable]") || $("dialog").open || $("lightbox").open) return;
  e.preventDefault();
  $("lookup-input").focus();
  $("lookup-input").select();
});
window.addEventListener("hashchange", () => route(true));
start().catch(() => showLogin());
