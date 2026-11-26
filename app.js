'use strict';

/*
 * Inventar – Suche in einer verschlüsselten Inventarliste.
 * Die Liste liegt nur verschlüsselt (AES-GCM, Schlüssel per PBKDF2 aus dem Passwort)
 * in data.enc.json. Entschlüsselt wird ausschließlich hier im Browser.
 */

const DATA_URL = 'data.enc.json';
const KEY_STORE = 'inventar-key-v1';

const $ = (id) => document.getElementById(id);
let items = [];

/* ---------- Hilfsfunktionen: Base64 ---------- */
const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const bytesToB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));

/* ---------- Speicher (kann im privaten Modus fehlen) ---------- */
function storeGet() {
  try { return JSON.parse(localStorage.getItem(KEY_STORE) || 'null'); } catch { return null; }
}
function storeSet(v) {
  try { localStorage.setItem(KEY_STORE, JSON.stringify(v)); } catch { /* egal */ }
}
function storeClear() {
  try { localStorage.removeItem(KEY_STORE); } catch { /* egal */ }
}

/* ---------- Krypto ---------- */
async function deriveKey(password, enc) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(enc.salt), iterations: enc.iter },
    base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
}

async function decrypt(key, enc) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(enc.iv) }, key, b64ToBytes(enc.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

async function loadEncrypted() {
  const res = await fetch(DATA_URL, { cache: 'no-cache' });
  if (!res.ok) throw new Error('Daten konnten nicht geladen werden (' + res.status + ').');
  return res.json();
}

/* ---------- Normalisierung & Suche ---------- */
const FOLD = { 'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss' };

// Liefert den normalisierten Text plus Zuordnung jedes Zeichens zur Originalposition
// (für die Markierung der Treffer).
function normalizeMapped(str) {
  let norm = '';
  const map = [];
  const lower = str.toLowerCase();
  for (let i = 0; i < lower.length; i++) {
    const ch = lower[i];
    let out = FOLD[ch];
    if (out === undefined) {
      out = ch.normalize('NFD').replace(/[̀-ͯ]/g, '');
      if (!/^[a-z0-9]*$/.test(out)) out = ' ';
    }
    for (const c of out) { norm += c; map.push(i); }
  }
  return { norm, map };
}
const normalize = (s) => normalizeMapped(s).norm.replace(/\s+/g, ' ').trim();

// Damerau-Levenshtein (optimal string alignment), bricht früh ab
function distance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev2 = new Array(b.length + 1);
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    for (let j = 0; j <= b.length; j++) prev2[j] = prev[j];
    prev = cur;
  }
  return prev[b.length];
}

function prepareItems(raw) {
  return raw.map((it, idx) => {
    const { norm, map } = normalizeMapped(it.name);
    const words = norm.split(/\s+/).filter(Boolean);
    return { ...it, idx, norm, map, words, compact: words.join('') };
  });
}

// Bewertet ein Suchwort gegen einen Gegenstand. 0 = kein Treffer.
function scoreToken(t, it) {
  if (/^\d+$/.test(t) && normalize(String(it.box)) === t) return 90;
  let best = 0;
  for (const w of it.words) {
    if (w === t) return 100;
    if (w.startsWith(t)) best = Math.max(best, 80);
  }
  if (best) return best;
  if (it.norm.includes(t) || it.compact.includes(t)) return 60;

  // Tippfehler-Toleranz erst ab 4 Zeichen
  if (t.length < 4) return 0;
  const max = t.length >= 8 ? 2 : 1;
  for (const w of it.words) {
    const d = Math.min(
      distance(t, w, max),
      w.length > t.length ? distance(t, w.slice(0, t.length), max) : max + 1);
    if (d <= max) best = Math.max(best, 45 - d * 10);
    // Teilwort in zusammengesetzten Wörtern (z. B. "schraubenzieher")
    if (!best && w.length > t.length + 1) {
      for (let s = 1; s + t.length <= w.length; s++) {
        if (distance(t, w.substr(s, t.length), max) <= max) { best = 25; break; }
      }
    }
  }
  return best;
}

function parseQuery(q) {
  let n = normalize(q);
  // "kiste 12", "k 12", "nr 12", "#12" → Kistennummer
  n = n.replace(/^(kiste|kisten|k|nr|nummer)\s+(?=\d+$)/, '');
  return n ? n.split(' ') : [];
}

function search(q) {
  const tokens = parseQuery(q);
  if (!tokens.length) return null;
  const hits = [];
  for (const it of items) {
    let total = 0;
    let ok = true;
    for (const t of tokens) {
      const s = scoreToken(t, it);
      if (!s) { ok = false; break; }
      total += s;
    }
    if (ok) hits.push({ it, score: total });
  }
  hits.sort((a, b) => b.score - a.score || compareBox(a.it.box, b.it.box) || a.it.name.localeCompare(b.it.name, 'de'));
  return { tokens, hits };
}

function compareBox(a, b) {
  return String(a).localeCompare(String(b), 'de', { numeric: true });
}

/* ---------- Darstellung ---------- */
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function highlight(it, tokens) {
  const ranges = [];
  for (const t of tokens) {
    let from = 0;
    let pos;
    while (t && (pos = it.norm.indexOf(t, from)) !== -1) {
      ranges.push([it.map[pos], it.map[pos + t.length - 1] + 1]);
      from = pos + t.length;
    }
  }
  if (!ranges.length) return escapeHtml(it.name);
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [ranges[0]];
  for (const r of ranges.slice(1)) {
    const last = merged[merged.length - 1];
    if (r[0] <= last[1]) last[1] = Math.max(last[1], r[1]); else merged.push(r);
  }
  let html = '';
  let i = 0;
  for (const [s, e] of merged) {
    html += escapeHtml(it.name.slice(i, s)) + '<mark>' + escapeHtml(it.name.slice(s, e)) + '</mark>';
    i = e;
  }
  return html + escapeHtml(it.name.slice(i));
}

function row(it, tokens) {
  return '<li><span class="qty">' + escapeHtml(String(it.qty)) + '×</span>' +
    '<span class="name">' + highlight(it, tokens) + '</span>' +
    '<span class="box"><small>Kiste</small><b>' + escapeHtml(String(it.box)) + '</b></span></li>';
}

function render() {
  const q = $('q').value;
  $('clear').hidden = !q;
  const res = search(q);
  const list = $('results');

  if (!res) {
    // Keine Suche: alles nach Kisten gruppiert
    const sorted = [...items].sort((a, b) => compareBox(a.box, b.box) || a.name.localeCompare(b.name, 'de'));
    let html = '';
    let current = null;
    for (const it of sorted) {
      if (it.box !== current) {
        current = it.box;
        html += '<li class="group">Kiste ' + escapeHtml(String(current)) + '</li>';
      }
      html += row(it, []);
    }
    list.innerHTML = html;
    const boxes = new Set(items.map((i) => i.box)).size;
    $('status').textContent = items.length + ' Gegenstände in ' + boxes + ' Kisten';
    return;
  }

  if (!res.hits.length) {
    list.innerHTML = '<li class="empty">Nichts gefunden.</li>';
    $('status').textContent = 'Keine Treffer';
    return;
  }
  list.innerHTML = res.hits.map((h) => row(h.it, res.tokens)).join('');
  const boxes = [...new Set(res.hits.map((h) => h.it.box))].sort(compareBox);
  $('status').textContent = res.hits.length + (res.hits.length === 1 ? ' Treffer' : ' Treffer') +
    ' · ' + (boxes.length === 1 ? 'Kiste ' : 'Kisten ') + boxes.join(', ');
}

function showApp(data) {
  items = prepareItems(data.items || []);
  if (data.updated) {
    const d = new Date(data.updated);
    $('updated').textContent = 'Stand: ' + (isNaN(d) ? data.updated : d.toLocaleDateString('de-DE'));
  }
  $('login').hidden = true;
  $('app').hidden = false;
  render();
}

function showLogin(message) {
  $('app').hidden = true;
  $('login').hidden = false;
  const err = $('login-error');
  err.hidden = !message;
  err.textContent = message || '';
  setTimeout(() => $('password').focus(), 50);
}

/* ---------- Start ---------- */
let encrypted = null;

async function start() {
  try {
    encrypted = await loadEncrypted();
  } catch (e) {
    showLogin('Keine Verbindung und noch keine gespeicherten Daten. Bitte einmal mit Internet öffnen.');
    return;
  }
  const stored = storeGet();
  if (stored && stored.salt === encrypted.salt) {
    try {
      const key = await crypto.subtle.importKey('raw', b64ToBytes(stored.key), 'AES-GCM', false, ['decrypt']);
      showApp(await decrypt(key, encrypted));
      return;
    } catch { /* Passwort geändert → neu fragen */ }
  }
  storeClear();
  showLogin('');
}

$('login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('login-btn');
  const pw = $('password').value;
  if (!encrypted) { start(); return; }
  btn.disabled = true;
  btn.textContent = 'Entsperre …';
  try {
    const key = await deriveKey(pw, encrypted);
    const data = await decrypt(key, encrypted);
    storeSet({ salt: encrypted.salt, key: bytesToB64(await crypto.subtle.exportKey('raw', key)) });
    $('password').value = '';
    showApp(data);
  } catch {
    showLogin('Falsches Passwort.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Entsperren';
  }
});

$('q').addEventListener('input', render);
$('clear').addEventListener('click', () => { $('q').value = ''; render(); $('q').focus(); });
$('logout').addEventListener('click', () => {
  if (!confirm('Passwort auf diesem Gerät vergessen? Du musst es danach neu eingeben.')) return;
  storeClear();
  items = [];
  $('results').innerHTML = '';
  $('q').value = '';
  showLogin('');
});

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

start();
