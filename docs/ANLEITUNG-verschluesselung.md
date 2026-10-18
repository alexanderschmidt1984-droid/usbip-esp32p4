# usbip-esp32p4 – Verschlüsselung im lokalen Netz (TLS & HTTPS)

Beide Funktionen sind **im Auslieferungszustand aus** und werden in der Weboberfläche unter *Einstellungen → Encryption (local network)* geschaltet. Build mit ESP-IDF v6.0.2 für ESP32-P4 Rev 3.x: **fehlerfrei, ohne Warnungen**. Auf echter Hardware noch nicht getestet.

## Einspielen

| Was du schon eingespielt hast | Patch |
|---|---|
| Verbesserungen + WireGuard | `usbip-esp32p4-tls.patch` |
| Verbesserungen + WireGuard + TLS (vorige Version) | `usbip-esp32p4-windows.patch` (nur Windows-Umschalter) |
| noch gar nichts | `usbip-esp32p4-komplett.patch` (enthält alles) |

```fish
cd ~/esp/usbip-esp32p4
git apply ~/Downloads/usbip-esp32p4-tls.patch      # bzw. komplett.patch auf frischem origin/main
git add -A; git commit -m "TLS + HTTPS"
. ~/esp/esp-idf/export.fish
rm -rf build sdkconfig        # wichtig: neue mbedTLS-Optionen aus sdkconfig.defaults übernehmen
idf.py set-target esp32p4
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```
(Die Meldungen „trailing whitespace“ beim Einspielen stammen aus dem Original-Code der WireGuard-Bibliothek und sind harmlos.)

## 1. USB/IP über TLS

```
PC: usbip attach -r 127.0.0.1 ─▶ stunnel ══TLS 1.2 (PSK)══▶ Board :3241 ─▶ USB/IP-Server
```

**Modi** (wirken sofort, ohne Neustart):
| Modus | Port 3240 (Klartext) | Port 3241 (TLS) |
|---|---|---|
| Off | offen | aus |
| Additional | offen | an |
| TLS only | lehnt alle Clients ab | an |

### Einrichtung am PC (Linux / CachyOS)
1. `sudo pacman -S stunnel`
2. In der Weboberfläche auf **Show key & stunnel config** klicken. Dort steht die fertige Konfiguration mit der IP des Boards und dem Schlüssel.
3. Die beiden Teile als Dateien anlegen:
```fish
sudo nano /etc/stunnel/usbip.conf     # Block "[usbip] …" einfügen
sudo nano /etc/stunnel/usbip.psk      # Zeile "usbip:<Schlüssel>" einfügen
sudo chmod 600 /etc/stunnel/usbip.psk
```
4. Als Dienst starten, damit es nach jedem Neustart läuft:
```fish
sudo tee /etc/systemd/system/usbip-stunnel.service >/dev/null <<'EOF'
[Unit]
Description=stunnel TLS wrapper for usbip-esp32p4
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/stunnel /etc/stunnel/usbip.conf
Type=forking
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now usbip-stunnel
```
5. Benutzen – immer über `127.0.0.1`:
```fish
usbip list -r 127.0.0.1
sudo usbip attach -r 127.0.0.1 -b 1-1
```
6. Läuft es, auf **TLS only** umstellen. Danach ist kein unverschlüsselter Zugriff mehr möglich.


### Einrichtung am PC (Windows 10 ab 1903 / Windows 11)

1. **usbip-win2** installieren, in einer Admin-Konsole: `winget install vadimgrn.usbip-win2` (oder Installer von GitHub). Die Treiber sind von Microsoft signiert, Testsignatur-Modus ist nicht nötig.
2. **stunnel** installieren (Windows-Installer von stunnel.org).
3. Weboberfläche → *Show key & stunnel config* → **Windows 10/11** wählen. Der angezeigte Block enthält die Windows-Pfade.
4. Den `[usbip]`-Block in `stunnel.conf` einfügen und die Beispiel-Dienste darin löschen. Die Schlüsselzeile `usbip:<Schlüssel>` als `usbip.psk` daneben speichern.
   - 32-Bit-Installer: `C:\Program Files (x86)\stunnel\config\`
   - 64-Bit-Installer: `C:\Program Files\stunnel\config\` → dann beide Pfade im Block anpassen.
5. Als Dienst einrichten (Admin-Konsole im stunnel-`bin`-Ordner):
```bat
stunnel.exe -install
net start stunnel
```
6. Verbinden:
```bat
usbip.exe list -r 127.0.0.1
usbip.exe attach -r 127.0.0.1 -b 1-1
```
Fehlersuche: stunnel-Symbol im Infobereich → *Show Log Window*, oder die Windows-Ereignisanzeige.

**WireGuard unter Windows:** offiziellen Client von wireguard.com installieren, Tunnel-Datei importieren. Danach `usbip.exe attach -r <Tunnel-IP-des-Boards> -b …`.

**Details:**
- **Schlüssel:** Das Board erzeugt beim ersten Start einen zufälligen Schlüssel mit 32 Zeichen. **New key** erzeugt einen neuen, danach muss die `.psk`-Datei am PC angepasst werden. Angezeigt wird der Schlüssel nur nach Login und nur auf Klick.
- **Verschlüsselung:** bevorzugt ECDHE-PSK-ChaCha20-Poly1305. Damit sind auch alte Mitschnitte nicht nachträglich entschlüsselbar, selbst wenn der Schlüssel später bekannt wird.
- **IP-Freigabeliste:** Sie gilt für die echte IP des TLS-Clients. In der Geräteliste der Weboberfläche erscheinen TLS-Clients als `127.0.0.1`, weil das Board intern über diese Adresse weiterleitet.
- **Fehlersuche:** `journalctl -u usbip-stunnel`. Am Board steht im Ereignislog „handshake failed (wrong key?)“, wenn der Schlüssel nicht passt.

## 2. HTTPS für die Weboberfläche

1. Haken bei **HTTPS for this web UI** setzen → *Save Encryption*. Das Board erzeugt dabei ein eigenes Zertifikat (ECDSA P-256, gültig bis 2049).
2. Den angezeigten **SHA-256-Fingerabdruck** notieren und das Board neu starten (Einstellungen → System → Restart).
3. Danach erreichst du die Weboberfläche unter `https://<IP>/`. Port 80 ist dann aus.
4. Der Browser warnt einmal („nicht vertrauenswürdig“), weil das Zertifikat selbstsigniert ist. In den Zertifikatsdetails des Browsers den Fingerabdruck vergleichen. Stimmt er überein, die Ausnahme dauerhaft bestätigen.

- **Neues Zertifikat:** *New certificate* erzeugt ein neues (aktiv nach Neustart).
- **Absicherung beim Start:** Startet HTTPS nicht, fällt das Board automatisch auf HTTP zurück und schreibt einen Eintrag ins Ereignislog. So sperrst du dich nicht aus.
- **Notfall:** `idf.py -p /dev/ttyACM0 erase-flash flash` setzt alles auf Werkszustand zurück.

## Wann was?

| Ziel | Empfehlung |
|---|---|
| Nur im Heimnetz, USB/IP verschlüsseln | TLS „only“ + stunnel |
| Weboberfläche absichern (Passwort nicht im Klartext) | HTTPS |
| Von unterwegs / alles in einem | WireGuard (siehe `ANLEITUNG-wireguard.md`) |

Alles lässt sich kombinieren. TLS-Verbindungen laufen auch durch den WireGuard-Tunnel.
