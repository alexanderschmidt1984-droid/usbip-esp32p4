# Verwendete Komponenten und Versionen

Stand 2026-10-18. Die Versionen auf dem Board zeigt die Web-UI unter Settings → System → „Softwarekomponenten“
(`/api/system/components`, Werte beim Build aus ESP-IDF bzw. `dependencies.lock`).

## Auf dem Board (Firmware)
| Komponente | Version | Lizenz |
|---|---|---|
| ESP-IDF | v6.0.2 | Apache-2.0 |
| FreeRTOS (ESP-IDF) | V10.5.1 | MIT |
| lwIP | 2.2.0 | BSD-3-Clause |
| Mbed TLS (TF-PSA-Crypto 1.1.0) | 4.1.0 | Apache-2.0 OR GPL-2.0-or-later |
| espressif/usb (USB-Host) | 1.6.0 | Apache-2.0 |
| espressif/mdns | 1.14.0 | Apache-2.0 |
| espressif/ip101 (Ethernet-PHY) | 1.1.0 | Apache-2.0 |
| WireGuard (esphome-libs/wireguard, vendored in `components/wireguard`) | 0.4.8 (9b7660f) + 8 Fixes, siehe `PATCHED.md` | BSD-3-Clause |
| esphome/libsodium | 1.10021.12 | ISC |

Hinweis: Hub-Kompatibilität (`fsls_only`) braucht `USB_DWC_HAL_INIT_HAS_CONFIG` aus ESP-IDF – erst nach v6.0.3/v6.1
(Branch `release/v6.0`, vermutlich v6.0.4).

## Am PC getestet mit
| Programm | Version | Zweck |
|---|---|---|
| usbip (usbip-utils, Kernelmodul vhci-hcd) | 2.0, Kernel 7.2.10 (CachyOS) | USB/IP-Client |
| usbip-win2 | noch nicht getestet | USB/IP-Client Windows |
| stunnel | 5.82 | USB/IP über TLS |
| wireguard-tools | 1.0.20260223 | WireGuard-Gegenstelle |
| Firefox | 157.0.1 | Web-UI, HTTPS |

## Web-UI-Sprachen
12 Sprachen (de, en, fr, es, it, pt, da, sv, ru, uk, tr, ar), maschinell übersetzt, nicht gegengelesen.
Quellen und Werkzeug: `tools/i18n/` (`python3 tools/i18n/i18n.py` prüft und baut `frontend/lang/*.json`).
