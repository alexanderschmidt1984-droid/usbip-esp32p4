# usbip-esp32p4-plus – private Arbeitsversion

Basis: [ringof/usbip-esp32p4](https://github.com/ringof/usbip-esp32p4) (Branch `main` = unveränderter Original-Stand).
Branch `improvements` = Bugfixes, Sicherheits-Paket, Geräte-Filter, Stromsparen, WireGuard, TLS/HTTPS.

| Anleitung | Inhalt |
|---|---|
| [ANLEITUNG-verbesserungen.md](ANLEITUNG-verbesserungen.md) | Bugfixes, Sicherheits-Paket, Geräte-Filter, Stromsparen |
| [ANLEITUNG-wireguard.md](ANLEITUNG-wireguard.md) | WireGuard-Tunnel, Fritzbox / Linux-Server, Bibliotheks-Fixes |
| [ANLEITUNG-verschluesselung.md](ANLEITUNG-verschluesselung.md) | USB/IP über TLS (stunnel, Linux + Windows), HTTPS |

## Bauen (CachyOS, fish)
```fish
. ~/esp/esp-idf/export.fish
rm -rf build sdkconfig
idf.py set-target esp32p4
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

## Status / Lizenz
- Auf Hardware noch **nicht** getestet (nur Build mit ESP-IDF v6.0.2, ESP32-P4 Rev 3.x).
- Das Original-Projekt hat derzeit **keine Lizenz** → dieses Repo bleibt privat, bis der Autor eine Lizenz ergänzt.
- Fremdkomponenten: ESP-IDF/esp-usb/mdns/ip101 (Apache-2.0), mbedTLS (Apache-2.0 OR GPL-2.0+),
  lwIP (BSD-3), WireGuard-Bibliothek in `components/wireguard` (BSD-3, mit Fixes, siehe `PATCHED.md`),
  libsodium (ISC) / ESPHome-Port (MIT).
