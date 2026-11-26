#!/usr/bin/env node
// Verschlüsselt die Inventarliste für die App.
//
//   node tools/verschluesseln.mjs inventar.txt
//
// Format pro Zeile:  <Menge>x <Name> (<Kistennummer>)   – Menge optional
//   z. B.            3x Verlängerungskabel (12)
//                    Luftballons (4)
// Leere Zeilen und Zeilen mit # am Anfang werden ignoriert.
//
// Das Passwort wird abgefragt oder aus der Umgebungsvariable INVENTAR_PASSWORT gelesen.
// Ergebnis: data.enc.json (nur diese Datei kommt ins Repository, NIE die Klartextliste).

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'data.enc.json');
const ITERATIONS = 600000;

const LINE = /^\s*(?:(\d+(?:[.,]\d+)?)\s*[x×*]\s*)?(.+?)\s*\(\s*(?:kiste\s*)?([^()]+?)\s*\)\s*$/i;

export function parseList(text) {
  const items = [];
  const errors = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const m = line.match(LINE);
    if (!m) { errors.push(`Zeile ${i + 1}: "${line}"`); return; }
    items.push({ qty: m[1] ? m[1].replace('.', ',') : '', name: m[2], box: m[3] });
  });
  return { items, errors };
}

async function askPassword(prompt) {
  if (process.env.INVENTAR_PASSWORT) return process.env.INVENTAR_PASSWORT;
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  rl._writeToOutput = (s) => { if (s.includes(prompt)) rl.output.write(s); };
  const answer = await new Promise((r) => rl.question(prompt, r));
  rl.close();
  process.stdout.write('\n');
  return answer;
}

const b64 = (b) => Buffer.from(b).toString('base64');

async function main() {
  const args = process.argv.slice(2);
  const newSalt = args.includes('--neues-salz');
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) {
    console.error('Aufruf: node tools/verschluesseln.mjs <liste.txt> [--neues-salz]');
    process.exit(2);
  }

  const { items, errors } = parseList(readFileSync(file, 'utf8'));
  if (errors.length) {
    console.error('Diese Zeilen haben nicht das Format "[<Menge>x] <Name> (<Kiste>)":');
    errors.forEach((e) => console.error('  ' + e));
    process.exit(1);
  }
  if (!items.length) { console.error('Die Liste ist leer.'); process.exit(1); }

  const password = await askPassword('Passwort: ');
  if (password.length < 8) { console.error('Das Passwort muss mindestens 8 Zeichen haben.'); process.exit(1); }

  // Salz beibehalten, damit gespeicherte Schlüssel auf den Geräten gültig bleiben,
  // solange das Passwort gleich bleibt.
  let salt;
  if (!newSalt && existsSync(OUT)) {
    try { salt = Buffer.from(JSON.parse(readFileSync(OUT, 'utf8')).salt, 'base64'); } catch { /* neu */ }
  }
  if (!salt || salt.length !== 16) salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

  const payload = JSON.stringify({ updated: new Date().toISOString().slice(0, 10), items });
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(payload));

  writeFileSync(OUT, JSON.stringify({
    v: 1, kdf: 'PBKDF2-SHA256', iter: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct),
  }) + '\n');

  const boxes = new Set(items.map((i) => i.box)).size;
  console.log(`OK: ${items.length} Gegenstände in ${boxes} Kisten → ${path.relative(process.cwd(), OUT)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
