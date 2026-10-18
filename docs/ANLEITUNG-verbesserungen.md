# usbip-esp32p4 – Verbesserungs-Patch

Basis: `ringof/usbip-esp32p4` (origin/main) · getestet: Build mit ESP-IDF v6.0.2, Ziel ESP32-P4 Rev ≥ 3.0 (dein v3.2) – **fehlerfrei, ohne Warnungen**. Auf echter Hardware noch nicht getestet.

## Einspielen (fish-Shell)

```fish
cd ~/esp/usbip-esp32p4
git stash push -u -m vor-patch          # deine lokalen Rev3-Änderungen sichern (sind im Patch enthalten)
git fetch origin
git switch -c verbesserungen origin/main
git apply ~/Downloads/usbip-esp32p4-verbesserungen.patch
git add -A; git commit -m "Verbesserungen"

. ~/esp/esp-idf/export.fish
rm -rf build sdkconfig dependencies.lock
idf.py set-target esp32p4
idf.py build
idf.py -p /dev/ttyACM0 erase-flash flash monitor   # erase-flash empfohlen (neues Passwort-Format)
```

Zurück zur alten Version: `git switch main` (bzw. dein vorheriger Branch) und neu bauen/flashen.

## Behobene Fehler

| # | Fehler | Folge vorher |
|---|---|---|
| 1 | Bei jeder neuen Verbindung wurde die **gemeinsame URB-Tabelle gelöscht** | Absturz/Datenmüll, sobald ein 2. Client verbindet, während der 1. überträgt |
| 2 | Abgebrochene, aber noch laufende USB-Transfers wurden sofort freigegeben (**Use-after-free**) | sporadische Abstürze bei Unlink/Timeout/Trennen |
| 3 | OUT-Transfers > 16 KiB | USB/IP-Datenstrom gerät aus dem Takt, Verbindung hängt |
| 4 | ISO-Paketanzahl und -längen ungeprüft | Pufferüberlauf durch fehlerhafte/bösartige Clients |
| 5 | Auth speichern mit leerem Passwort | Passwort-Hash wurde überschrieben |
| 6 | **Statische IP** aus der Weboberfläche | wurde gespeichert, aber nie angewendet |
| 7 | Hostname/max. Clients (Kconfig) ignoriert, toter Code (Community-PR #10) | übernommen |
| 8 | Mitschnitt-Code wurde auch ausgeschaltet kompiliert | jetzt nur bei Bedarf |

## Neue Funktionen

- **Sicherheits-Paket:** Passwort gesalzen + 4096-fach gehasht · 5 Fehlversuche → 30 s Sperre pro IP · CSRF-Schutz (Header + Origin-Prüfung) · **Änderungen erst möglich, wenn ein Web-Passwort gesetzt ist** (abschaltbar: `USBIP_WEBUI_REQUIRE_PASSWORD`) · im „Closed“-Modus schützt die IP-Liste auch die Weboberfläche; deine eigene IP wird beim Umschalten automatisch eingetragen (kein Aussperren).
- **Geräte-Freigabeliste (VID:PID):** Einstellungen → „Device Filter“, z. B. `1050:*` = alle YubiKeys. Andere Geräte werden ignoriert (Hubs immer erlaubt). Werksvorgabe per menuconfig `USBIP_DEVICE_ALLOWLIST`.
- **Mitschnitt standardmäßig aus** (`CONFIG_CAPTURE_ENABLED`), weil er auch Sicherheitsschlüssel-Verkehr aufzeichnet.
- **Stromsparen:** CPU taktet im Leerlauf auf 40 MHz herunter, volle 360 MHz automatisch, solange ein Gerät angebunden ist. Kein Light-Sleep → Board bleibt erreichbar. Abschaltbar: `USBIP_POWER_SAVE`.
- `espressif/usb` ≥ 1.6.0 (Hub-/Enumerations-Fixes).

## Erster Start – was anders ist

1. Weboberfläche öffnen → Einstellungen → Authentication: Haken setzen, Benutzer + Passwort vergeben, speichern. Vorher werden alle anderen Änderungen mit „password required“ abgelehnt.
2. Danach fragt der Browser nach dem Login.
3. Passwort vergessen / ausgesperrt: `idf.py -p /dev/ttyACM0 erase-flash flash` setzt alles zurück.
4. Statische IP wirkt nach Neustart; ungültige Eingaben → automatisch DHCP.

## Quellen

- [ringof/usbip-esp32p4 – Issues](https://github.com/ringof/usbip-esp32p4/issues) (#3 Lazy Claim, #6 Claim-Policy, #9 toter Code)
- [ringof/usbip-esp32p4 – PR #10](https://github.com/ringof/usbip-esp32p4/pull/10)
- [espressif/esp-usb – Changelog usb host](https://github.com/espressif/esp-usb/blob/master/host/usb/CHANGELOG.md)
