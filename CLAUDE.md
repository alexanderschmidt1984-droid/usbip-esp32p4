# usbip-esp32p4-plus – Projektkontext für Claude Code

Arbeitsversion von ringof/usbip-esp32p4 (USB/IP-Server auf ESP32-P4), Branch `improvements`.
Hardware: Waveshare ESP32-P4-ETH, **Chip-Rev v3.2**, 16 MB Flash (Header), 32 MB PSRAM, IP101-PHY.
ESP-IDF v6.0.3. Persönliches und echte Netzwerkwerte stehen in `CLAUDE.local.md` (nicht im Repo);
IP-Adressen hier sind Beispielwerte (Heimnetz 192.168.1.0/24, Board 192.168.1.50).

Neue Features erst auf Hardware prüfen – Kompilieren allein hat hier mehrfach nicht gereicht.

## Bauen / Flashen / Log
```sh
. ~/esp/esp-idf/export.sh      # fish: export.fish
idf.py set-target esp32p4      # nur nach rm -rf build sdkconfig
idf.py build
sudo fuser -k /dev/ttyACM0     # Port war mehrfach belegt (altes picocom/monitor)
idf.py -p /dev/ttyACM0 flash
timeout 30 idf.py -p /dev/ttyACM0 monitor --no-reset   # oder picocom -b 115200 --logfile ~/esp-log.txt /dev/ttyACM0
```
Backtrace dekodieren: `riscv32-esp-elf-addr2line -pfiaC -e build/usbip-esp32p4.elf <Adressen>`.

## Hardware-Teststand (2026-10-18)
1. v1 (a7e59a8): Reset kurz nach `esp_pm_configure` – **Fehldiagnose**: Ursache war der `sodium_init()`-Abbruch
   in `wg_tunnel_init` (siehe 2.), der direkt danach läuft. DFS ist auf Rev 3.2 / PSRAM 200 MHz stabil (s. 7.).
2. v2 (06037ce): `abort()` in `wg_tunnel_init` → `sodium_init()` (libsodium randombytes → /dev/urandom fehlt).
3. v3 (5522366): sodium_init entfernt – **bootet stabil** (Got IP per DHCP 192.168.1.50, Web-UI Port 80,
   USB/IP 3240, mDNS). `usbip list` zeigt Gerät.
4. v4: USB-Stick (23a9:ef18, Mass Storage) brach nach Attach ab (vhci `recv xbuf, 0`): IN >16 KiB wurde
   gekürzt, Rest landete im CSW-URB, `actual_length` > angefordert. Fix: `MAX_TRANSFER_SIZE` 128 KiB +
   `-EOVERFLOW` statt Übergröße. **Attach, Partitionserkennung, Mount bestätigt.**
   Stick 346d:5678 (exFAT): Lesen 200 MB `iflag=direct` 2× md5-gleich, **5,7 MB/s**; Schreiben 100 MB
   `oflag=direct,fsync` + Rücklesen md5-gleich, **4,3 MB/s**. Kein Fehler, kein Reboot, internes RAM stabil
   (416 KB). Grenze: IP101 = 100 Mbit.
   YubiKey 5 (1050:0407, FW 5.2.6, Full Speed): `fido2-token -I` ok, **OTP und FIDO2 (webauthn.io) mit
   Berührung ok**. Unlinks (`status -104`) beim Schließen von hidraw = normal (Cancel-Pfad funktioniert).
   Abziehen im Betrieb: ENODEV → Verbindung sauber zu, kein Reboot, RAM wieder freigegeben (411→427 KB),
   Key nach Wiederanstecken erneut exportierbar (Re-Attach am PC manuell). **Basis damit komplett getestet.**
   (Stick mit Partitionstyp 0xef wird von udisks ausgeblendet → nicht in Dolphin, kein USB/IP-Problem.)
   `CONFIG_USB_HOST_DWC_DMA_CAP_MEMORY_IN_PSRAM=y` getestet → **Gerät wird gar nicht mehr erkannt**, nicht verwenden.
5. WireGuard (fe17eed): (a) Boot-Loop beim Tunnelstart – esp_netif (IDF 6) las `netif->state` des WG-netif
   als esp_netif → Fix `CONFIG_LWIP_PPP_SUPPORT=y` (aktiviert `LWIP_ESP_NETIF_DATA`, `#error` in wg_tunnel.c).
   (b) Handshake ok, aber keine Daten: Default-Allowed-IP = eigene /32 + MAX_SRC_IPS 1 → mit FIX 1 alles
   verworfen → Default jetzt Tunnel-Subnetz (PATCHED.md Fix 8). **Bestätigt:** PC als Gegenstelle
   (`/etc/wireguard/wg-usbip.conf`, 10.8.0.1, UDP 51820, UFW-Regel nur für die Board-IP), Board 10.8.0.2:
   Ping, Web-UI, `usbip list` + YubiKey-Attach über Tunnel ok.
- Web-UI-Fixes (2114cfe): Capture-Polling nur mit Capture, Settings lädt sequenziell (WebSocket wurde
  wegen `max_open_sockets` 7 per LRU geschlossen). Sobald ein Passwort gesetzt ist, liefert die UI ohne
  Login überall 401 (auch `/api/system/info`).
   Nach Neustart des PC-Tunnels meldet sich das Board erst nach ≤ ~2 min neu an (Rekey nach
   REKEY_AFTER_TIME, normal); „no handshake“ war hier die UFW (UDP 51820 vom Board).
6. TLS (stunnel 5.82 am PC, PSK-Datei vom Nutzer selbst angelegt): Modus **Additional** und **TLS only**
   bestätigt (TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256, YubiKey-Attach über 127.0.0.1). TLS only lehnt
   Klartext auf 3240 ab („Unknown Op Common Status“ am PC), **WireGuard-Verbindungen sind ausgenommen**
   (bestätigt: list/attach über 10.8.0.2). ACL/Log/Geräteliste sehen bei TLS die echte Client-IP
   (Proxy-Port-Map in sec_tls), nicht 127.0.0.1. Geräteliste zeigt Schloss „· TLS“ / „· WireGuard“
   (Feld `tr`), Sidebar „Über HTTPS verschlüsselt“ – beides im Browser bestätigt. HTTPS selbst noch offen.
   Arch hat kein `stunnel@`-Template → `/etc/stunnel/stunnel.conf` + `stunnel.service`.
7. Stromsparen (DFS, `components/power_mgr`): **ab Werk an**, in Settings → System abschaltbar (live, NVS
   `power/save`; aus = min=max=400 MHz). Gemessen mit `CONFIG_PM_PROFILING` (nur Testbuild): Leerlauf
   **100 MHz** (nicht 40 – der EMAC-Treiber hält dauerhaft einen APB_FREQ_MAX-Lock), 400 MHz bei laufendem
   Task und solange ein Gerät exportiert ist. Boot, Ping/HTTP/usbip-Last, Enumeration im Leerlauf und
   YubiKey-Attach ohne Absturz. `esp_clk_cpu_freq()` liest aus einem Task immer 400 (FreeRTOS-rtos-Locks) →
   Web-UI zeigt den Modus (`esp_pm_impl_get_cpu_freq`). Grünes Blatt „Energiesparen an“ in der Sidebar.
8. ACL: Einträge IP **oder MAC** + Kommentar (NVS `acl/entries`, altes `allowlist`-Blob wird übernommen –
   Migration nicht auf Hardware getestet). MAC über ARP-Tabelle (`tcpip_api_call`, kein Core-Locking), nur
   im selben LAN. Mit MAC-Eintrag getestet ok. Passwort muss beim Setzen zweimal eingegeben werden.
9. Transfer-Engine (08b544e): 120-s-Zwangsabbruch nur noch für Control/OUT; Bulk-/Interrupt-IN darf
   unbegrenzt warten (YubiKey ep 0x81 brach vorher alle 2 min ab). **Bestätigt:** > 3 min angehängt, OTP ok.
10. Werksreset ohne Web-UI (9df6c1a): RESET 5× (Abstand je < 5 s, Strom aus/ein zählt auch; SW-Restart/
   Absturz nicht), NVS-Zähler `boot/taps`. PSRAM-Memtest aus → Zähler läuft nach ~0,67 s.
   **Bestätigt** (2026-10-19): Drücken etwa alle 2 s (min. 1 s, max. 5 s) – schneller bricht den Start ab,
   bevor gezählt wird. Bootloader-Log auf WARN → Zähler nach ~0,70 s.
   BOOT-Taste (GPIO 35) geht nicht: RMII TXD1 + Download-Modus beim Einschalten.
   Alternative per Kabel: `idf.py -p /dev/ttyACM0 erase-region 0x9000 0x6000` (nur NVS).
11. HTTPS (Port 443, selbstsigniert ECDSA P-256): **bestätigt** mit Firefox (Ausnahme bei
   `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT`), Login, wss-Live-Daten, Settings ohne Abbruch. Nur TLS 1.2,
   ECDHE-ECDSA-CHACHA20-POLY1305. Port 80 leitet mit 301 auf https weiter (kleiner 2. httpd, nur bei HTTPS).
   Zertifikat ohne SAN (für Firefox egal, Chrome meckert zusätzlich über den Namen).
12. Original-Bugfixes auf Hardware: **#4 ISO-Prüfung** per Testclient (Scratchpad `tests/usbip_fuzz.py`):
   1000/−5 Pakete, negative Länge → Verbindung zu; ISO-Längen 4×1 GiB und OUT 200 KiB → `-EINVAL`, Strom
   bleibt synchron – 7/7. **Client-Limit (#7)** 4 gleichzeitig, 5. abgewiesen, kein Zählerleck (30 Kurzverb.).
   **#2 Abbruch** (Detach/Abziehen mitten in dd lesen/schreiben): kein Absturz. Dabei gefunden: nach Detach
   hing der Stick mitten im Befehl (30-s-Timeouts, Linux-Reset kommt über USB/IP nicht an) → Board setzt
   jetzt nach **jeder** vom Client beendeten Sitzung den Root-Port zurück (wie Ab-/Anstecken, ~0,7 s), nicht
   bei Abziehen und nicht, solange ein anderes Gerät exportiert ist. **Bestätigt** (A/B/C).
   **#5** leeres Passwort beim Speichern → altes Passwort bleibt, leeres gibt 401 ✅. **#6** statische IP
   nach Neustart angewendet (IP nach 3,2 s, kein DHCP) ✅ – statische IP außerhalb des DHCP-Bereichs des
   Routers wählen (oder DHCP + Reservierung im Router). **#7** Hostname aus NVS (`usbip-gw`,
   mDNS/Router) ✅. **#1** mit Hub: Kartenleser 3× neu verbunden, während der Stick las → kein Absturz,
   „USB reset skipped (other device in use)“ ✅. Stick fiel danach vom Hub (Hub ohne Netzteil: auch
   FS-Rückfall und 2 Neustarts ohne Panic = Strom) – mit aktivem Hub wiederholen.
13. Hub + Full/Low-Speed-Geräte (YubiKey): esp-usb 1.6.0 hat **keinen Transaction Translator** →
   abgelehnt. `usb_host_config_t.fsls_only` (Hub-Kompatibilität) braucht `USB_DWC_HAL_INIT_HAS_CONFIG`
   aus ESP-IDF – **nicht in v6.0.2/v6.0.3/v6.1**, nur `release/v6.0`-Branch/master (vermutl. v6.0.4).
   Code ist drin, aber nur bei IDF-Unterstützung sichtbar (Panel „USB-Hub“, default aus), Fallback bei
   Installationsfehler. Getestet: auf 6.0.2 blieb USB mit der Option ganz aus → deshalb das Gate.
14. Logs/Abstürze (c9dc832): 2048 Ereignisse + 1 MB System-Log im PSRAM, Export als .txt (Dashboard).
   Letzte 4 KB in RTC-RAM (`RTC_NOINIT`) überstehen Absturz/SW-Restart → „Log vor letztem Neustart“,
   Neustartgrund + Absturzzähler (NVS `boot/crashes`, nur bei Absturz geschrieben). Bestätigt mit SW-Restart.
   Backtrace geht nicht ins Log (Panic schreibt direkt seriell) → dafür wäre ein Core Dump nötig (offen).
15. Web-UI 12 Sprachen (de en fr es it pt da sv ru uk tr ar, ar = RTL), maschinell übersetzt. Texte per
   Ausgangstext-Lookup, Hilfe pro Block (Befehle unverändert). Pflege: `tools/i18n/` – neue Texte in
   HTML/JS, dann `python3 tools/i18n/i18n.py --list`, in `tr/*.txt` ergänzen, `i18n.py` baut `lang/*.json`.
   Nummern in `keys.json` nie umsortieren. Lokal mit headless Firefox geprüft, auf dem Board noch offen.
16. Softwarekomponenten mit Versionen in Settings → System und `docs/KOMPONENTEN.md`.
17. Geschwindigkeit (Stick 346d:5678, 100 Mbit): Lesen 5,7 → 7,8 MB/s (eventfd-Wecken) → **9,3 MB/s** mit
   „Schnelles Lesen“ (experimentell, ab Werk aus, NVS `usb/fastrd`); Schreiben 4,3 → **5,9 MB/s** (eventfd,
   64-KB-TCP-Puffer, Bulk-OUT in 16-KB-Stücken). md5 jeweils gleich. Schreiben begrenzt vermutl. der Stick.
18. Übergabe gleicher PC LAN↔WireGuard: Gerät wird übernommen (alte Sitzung zu, kein Port-Reset), **0,12 s**
   bestätigt. Fremde PCs werden weiter abgewiesen (Log-Eintrag).
19. Web-UI (2026-10-19, alles am Board bestätigt): Einstellungen als Reiter (Start · Netzwerk · Anmeldung ·
   Sicherheit · Geräte · System), Badge USB/IP-Schutz (WireGuard/TLS/unverschlüsselt), angemeldeter
   Benutzer unten links, Sprachwechsel auch für JS-Texte, SD-Capture wieder einkompiliert (nur Admin),
   WireGuard-ACL-Hinweis, verschlüsselte Sicherung `.usbipbak` (AES-256-GCM, PBKDF2 50000, TLV –
   unbekannte Einträge werden übersprungen → auch mit neuerer Firmware lesbar).
   **Gastzugang:** ohne Anmeldung = `guest` (fester Name, kein Passwort, nur Ansicht, abschaltbar).
   Ohne Admin (Werksreset) nur „Ersteinrichtung“: Admin anlegen oder Sicherung einspielen. Admin lässt sich
   nicht mehr abschalten. Anmelden über `/login` (erzwingt Basic-Auth), Abmelden per XHR mit `guest:` an
   `/logout`. Lehre: Firefox füllte früher den Zuschauernamen ins Admin-Feld → Admin umbenannt, ausgesperrt.
   `max_uri_handlers` 64 (48 reichte nicht mehr: „no slots left“).
- Nächster Schritt: offen ist Capture mit SD-Karte am Board. Bei ESP-IDF ≥ v6.0.4: Hub-Kompatibilität testen.
- Hinweis: `idf.py monitor` ohne `--no-reset` startet das Board neu (trennt laufende USB/IP-Sitzungen).

## Was in `improvements` steckt (Details in docs/)
- Bugfixes transfer_engine (gemeinsame URB-Tabelle, UAF bei Cancel, OUT >16 KiB, ISO-Prüfung), statische IP angewendet,
  PR #10 (Hostname/max Clients), Rev-3-Konfiguration.
- Sicherheit Web-UI: gesalzener Hash, Lockout, CSRF-Header `X-USBIP-CSRF` + Origin, Schreiben erst nach Passwort,
  ACL schützt Web-UI (Anti-Lockout). Geräte-Filter VID:PID. Capture default aus.
- WireGuard: `components/wg_tunnel` + vendored `components/wireguard` (esphome/wireguard 0.4.8 mit 7 FIX(usbip),
  siehe PATCHED.md). Default aus, Web-UI-Panel.
- TLS: `components/sec_tls` – USB/IP über TLS-PSK auf 3241 (Proxy via Loopback), Modi off/additional/only;
  HTTPS mit On-Device-Zertifikat (nach Neustart). Default aus. stunnel-Snippets Linux/Windows in Web-UI.
- Stromsparen (DFS) per Web-UI schaltbar, ab Werk an. ACL mit IP-/MAC-Einträgen und Kommentar.
- Gastzugang ohne Passwort, Ersteinrichtung, verschlüsselte Einstellungs-Sicherung, Geräte-Übergabe LAN↔WireGuard,
  Schnelles Lesen (experimentell).
- Testreihenfolge: Basis → WireGuard → TLS/HTTPS → DFS (erledigt).

## Lizenz
Original-Projekt hat **keine Lizenz** → Repo bleibt privat, bis der Autor eine Lizenz ergänzt.
