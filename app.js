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
// Zwei Schreibweisen: "ä" → "ae" (Standard) und "ä" → "a" (locker),
// damit "kölsch", "koelsch" und "kolsch" gleichermaßen finden.
const FOLD = { 'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss' };
const FOLD_LOOSE = { 'ä': 'a', 'ö': 'o', 'ü': 'u', 'ß': 'ss' };

// Liefert den normalisierten Text plus Zuordnung jedes Zeichens zur Originalposition
// (für die Markierung der Treffer).
function normalizeMapped(str, fold = FOLD) {
  let norm = '';
  const map = [];
  const lower = str.toLowerCase();
  for (let i = 0; i < lower.length; i++) {
    const ch = lower[i];
    let out = fold[ch];
    if (out === undefined) {
      out = ch.normalize('NFD').replace(/[̀-ͯ]/g, '');
      if (!/^[a-z0-9]*$/.test(out)) out = ' ';
    }
    for (const c of out) { norm += c; map.push(i); }
  }
  return { norm, map };
}
const normalize = (s, fold) => normalizeMapped(s, fold).norm.replace(/\s+/g, ' ').trim();

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

const splitWords = (s) => s.split(/\s+/).filter(Boolean);

function prepareItems(raw) {
  return raw.map((it, idx) => {
    const { norm, map } = normalizeMapped(it.name);
    const { norm: loose, map: lmap } = normalizeMapped(it.name, FOLD_LOOSE);
    const words = splitWords(norm);
    const lwords = splitWords(loose);
    return {
      ...it, idx, norm, map, loose, lmap, words, lwords,
      compact: words.join(''), lcompact: lwords.join(''),
      boxNorm: normalize(String(it.box)),
    };
  });
}

// Bewertet ein Suchwort gegen einen Gegenstand.
// Ergebnis: { score, fuzzy } – score 0 = kein Treffer, fuzzy = nur ähnlich (Tippfehler).
function scoreToken(t, it) {
  if (/^\d+$/.test(t.n) && it.boxNorm === t.n) return { score: 110, fuzzy: false };

  let best = 0;
  for (const [ws, q] of [[it.words, t.n], [it.lwords, t.l]]) {
    for (const w of ws) {
      if (w === q) return { score: 100, fuzzy: false };
      if (w.startsWith(q)) best = Math.max(best, 80);
    }
  }
  if (best) return { score: best, fuzzy: false };
  if (it.norm.includes(t.n) || it.compact.includes(t.n) ||
      it.loose.includes(t.l) || it.lcompact.includes(t.l)) return { score: 60, fuzzy: false };

  // Tippfehler-Toleranz erst ab 4 Zeichen
  if (t.n.length < 4) return { score: 0, fuzzy: true };
  const q = t.n;
  const max = q.length >= 6 ? 2 : 1;
  for (const w of it.words) {
    const d = Math.min(
      distance(q, w, max),
      w.length > q.length ? distance(q, w.slice(0, q.length), max) : max + 1);
    if (d <= max) best = Math.max(best, 45 - d * 10);
    // Teilwort mit Tippfehler in zusammengesetzten Wörtern (z. B. "kreuzschraubenzieher")
    if (!best && q.length >= 6 && w.length > q.length + 1) {
      for (let s = 1; s + q.length <= w.length; s++) {
        if (distance(q, w.substr(s, q.length), 1) <= 1) { best = 25; break; }
      }
    }
  }
  return { score: best, fuzzy: true };
}

function parseQuery(q) {
  // "kiste 12", "k 12", "nr 12", "#12" → Kistennummer
  const strip = (s) => s.replace(/^(kiste|kisten|k|nr|nummer)\s+(?=\d+$)/, '');
  const n = splitWords(strip(normalize(q)));
  const l = splitWords(strip(normalize(q, FOLD_LOOSE)));
  if (n.length !== l.length) return n.map((x) => ({ n: x, l: x }));
  return n.map((x, i) => ({ n: x, l: l[i] }));
}

function search(q) {
  // "kiste 4" → nur der Inhalt von Kiste 4
  const box = normalize(q).match(/^(?:kiste|kisten|k|nr|nummer)\s*(\d+)$/);
  if (box) {
    const hits = items.filter((it) => it.boxNorm === box[1])
      .sort((a, b) => a.name.localeCompare(b.name, 'de'))
      .map((it) => ({ it, score: 0, fuzzy: false }));
    return { tokens: [], hits, fuzzy: false };
  }
  const tokens = parseQuery(q);
  if (!tokens.length) return null;
  let hits = [];
  for (const it of items) {
    let total = 0;
    let fuzzy = false;
    let ok = true;
    for (const t of tokens) {
      const r = scoreToken(t, it);
      if (!r.score) { ok = false; break; }
      total += r.score;
      fuzzy = fuzzy || r.fuzzy;
    }
    if (ok) hits.push({ it, score: total, fuzzy });
  }
  // Gibt es echte Treffer, werden reine Ähnlichkeitstreffer ausgeblendet.
  if (hits.some((h) => !h.fuzzy)) hits = hits.filter((h) => !h.fuzzy);
  hits.sort((a, b) => b.score - a.score || compareBox(a.it.box, b.it.box) || a.it.name.localeCompare(b.it.name, 'de'));
  return { tokens, hits, fuzzy: hits.length > 0 && hits.every((h) => h.fuzzy) };
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
  const find = (text, map, q) => {
    let from = 0;
    let pos;
    while (q && (pos = text.indexOf(q, from)) !== -1) {
      ranges.push([map[pos], map[pos + q.length - 1] + 1]);
      from = pos + q.length;
    }
  };
  for (const t of tokens) {
    find(it.norm, it.map, t.n);
    find(it.loose, it.lmap, t.l);
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
  const qty = it.qty ? escapeHtml(String(it.qty)) + '×' : '';
  return '<li><span class="qty">' + qty + '</span>' +
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
  $('status').textContent = (res.fuzzy ? 'Ähnliche Treffer: ' : '') + res.hits.length + ' Treffer' +
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
