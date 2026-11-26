# Inventar

Kleine Web-App zum Durchsuchen der Inventarliste: In welcher Kiste liegt was?

- Läuft im Browser auf dem Handy, lässt sich auf den Startbildschirm legen und funktioniert offline.
- Die Liste liegt **nur verschlüsselt** im Repository (`data.enc.json`, AES-256-GCM, Schlüssel per PBKDF2 aus dem Passwort). Ohne Passwort ist sie nicht lesbar.
- Suche: Teilwörter („schraube“ findet „Akkuschrauber“), Umlaute egal („aussen“ = „außen“), kleine Tippfehler werden toleriert, eine Zahl oder „Kiste 12“ zeigt den Inhalt dieser Kiste.

## Liste aktualisieren

1. Liste als Textdatei speichern, z. B. `inventar.txt` (wird von Git ignoriert), eine Zeile pro Gegenstand:
   ```
   3x Verlängerungskabel (12)
   1x Akkuschrauber (3)
   ```
2. Verschlüsseln (Node.js ≥ 18):
   ```
   node tools/verschluesseln.mjs inventar.txt
   ```
   Dabei das bisherige Passwort verwenden, sonst müssen alle Geräte das neue Passwort eingeben.
3. Nur `data.enc.json` committen und pushen. **Nie die Klartextliste committen**, denn das Repository ist öffentlich.

## Veröffentlichen (GitHub Pages)

Settings → Pages → „Deploy from a branch“ → Branch wählen, Ordner `/ (root)`.

## Auf dem Handy installieren

- **iPhone (Safari):** Teilen-Symbol → „Zum Home-Bildschirm“.
- **Android (Chrome):** Menü ⋮ → „App installieren“ bzw. „Zum Startbildschirm hinzufügen“.

Das Passwort wird einmal pro Gerät eingegeben und danach gespeichert. Über „Passwort vergessen lassen“ unten in der App kann man es wieder entfernen.
