# usbip-esp32p4 – WireGuard-Tunnel

Komponente: **esphome/wireguard v0.4.8** (06.10.2026, aktuellste Version; gepflegter Fork von trombik/esp_wireguard, unterstützt ESP-IDF 6 / mbedTLS 4). Sie liegt **mit 7 Sicherheitsfixes** als `components/wireguard` im Projekt (Details in `components/wireguard/PATCHED.md`), nur libsodium kommt aus der Registry. Build mit ESP-IDF v6.0.2 für ESP32-P4 Rev 3.x: **fehlerfrei, ohne Warnungen**. Auf echter Hardware noch nicht getestet.

## Prinzip

Das Board baut den Tunnel **selbst nach außen** auf. Am Standort des Boards braucht es keine Portfreigabe. Über die Tunnel-Adresse erreichst du dann:
- USB/IP (Port 3240): `usbip attach -r <Tunnel-IP> -b <busid>`
- die Weboberfläche: `http://<Tunnel-IP>/`

Ein- und ausschalten: Weboberfläche → Einstellungen → **WireGuard Tunnel** → Haken setzen → *Save WireGuard*.

## Einspielen

**Du hast den alten WireGuard-Patch schon eingespielt?** Dann nur die Fixes:
```fish
git apply ~/Downloads/usbip-esp32p4-wireguard-fixes.patch
```
**Variante A – du hast den ersten Patch (Verbesserungen) eingespielt, aber noch kein WireGuard:**
```fish
cd ~/esp/usbip-esp32p4
git apply ~/Downloads/usbip-esp32p4-wireguard.patch
```
**Variante B – direkt alles auf einmal** (statt beider Einzel-Patches):
```fish
cd ~/esp/usbip-esp32p4
git stash push -u -m vor-patch
git fetch origin
git switch -c verbesserungen origin/main
git apply ~/Downloads/usbip-esp32p4-komplett.patch
```
Danach bei beiden Varianten:
```fish
git add -A; git commit -m "WireGuard"
. ~/esp/esp-idf/export.fish
rm -rf build sdkconfig dependencies.lock     # Komponenten-Manager lädt esphome/libsodium
idf.py set-target esp32p4
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

## Gegenstelle einrichten

### Variante 1: Fritzbox (einfachster Weg)
1. Fritzbox: *Internet → Freigaben → VPN (WireGuard) → Verbindung hinzufügen → Einzelgerät verbinden* → Konfiguration als Datei herunterladen.
2. Werte aus der Datei in die Weboberfläche des Boards übertragen:

| Fritzbox-Datei | Feld in der Weboberfläche |
|---|---|
| `[Interface] PrivateKey` | Advanced → *Import private key* |
| `[Interface] Address` (z. B. 192.168.178.201) | *Tunnel address* |
| Netzmaske des Heimnetzes | *Tunnel netmask* (`255.255.255.0`) |
| `[Peer] PublicKey` | *Peer public key* |
| `[Peer] PresharedKey` | Advanced → *Preshared key* |
| `[Peer] Endpoint` (xyz.myfritz.net:Port) | *Peer endpoint* + *Peer port* |

3. Speichern. Der Status sollte nach einigen Sekunden auf **connected** springen.

⚠ Das Netz am Standort des Boards darf **nicht** denselben Adressbereich haben wie dein Heimnetz. Steht dort auch eine Fritzbox mit 192.168.178.x, gibt es einen Konflikt. Dann ändert man einen der beiden Adressbereiche.

### Variante 2: eigener Linux-Server (z. B. dein Server mit Caddy/Docker)
1. Am Board: Einstellungen → WireGuard → **Generate**. Der private Schlüssel bleibt auf dem Board. Den öffentlichen Schlüssel kopierst du mit **Copy**.
2. Auf dem Server in `/etc/wireguard/wg0.conf`:
```ini
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <Server-Privatschlüssel>
# damit Laptop (10.8.0.3) und Board (10.8.0.2) sich gegenseitig erreichen:
PostUp = sysctl -w net.ipv4.ip_forward=1

[Peer]   # usbip-esp32p4
PublicKey = <öffentlicher Schlüssel vom Board>
AllowedIPs = 10.8.0.2/32

[Peer]   # dein Laptop
PublicKey = <Laptop-Schlüssel>
AllowedIPs = 10.8.0.3/32
```
3. Am Board eintragen: Peer public key = öffentlicher Schlüssel des Servers, Endpoint = Server-Domain, Port 51820, Tunnel address 10.8.0.2, Netmask 255.255.255.0, Keepalive 25. *Peer config snippet* zeigt den passenden `[Peer]`-Block für den Server.
4. UDP-Port 51820 am Server öffnen.

## Behobene Fehler in der WireGuard-Bibliothek

| # | Fehler (Original v0.4.8) | Fix |
|---|---|---|
| 1 | „Allowed IPs“-Prüfung verglich die **Ziel**- statt der Quell-Adresse → gefälschte Absender möglich | prüft jetzt die Quell-Adresse |
| 2 | Endpunkt-Wechsel und Keepalives wurden vor dem Replay-Check verarbeitet → Tunnel umleitbar | Replay-Check zuerst, auch für Keepalives |
| 3 | Gefälschte Cookie-Antworten änderten den Endpunkt | Endpunkt nur noch bei authentischen Daten |
| 4 | Handshake-Ratenbegrenzung rechnete falsch herum (griff nie) | korrigiert |
| 5 | Lesen über Pufferende bei inneren Paketen < 20 Byte | Mindestlänge geprüft |
| 6 | Innere IPv6-Pakete ungefiltert angenommen | werden verworfen |
| 7 | Replay-Fenster nur 32 Pakete, 64-Bit-Differenz abgeschnitten | 2048 Pakete wie Linux, per Test mit 200.000 Zufallspaketen geprüft |

## Verhalten & Hinweise

- **Uhrzeit:** Vor dem Tunnelaufbau holt sich das Board die Uhrzeit per NTP (`pool.ntp.org`, änderbar in menuconfig). Ohne Uhrzeit lehnt die Gegenstelle den Handshake ab. Status dann: „waiting for time sync“.
- **Automatische Wiederverbindung:** Kommt 2 min lang kein erster Handshake zustande, oder bleibt die Gegenstelle 5 min still, baut das Board den Tunnel neu auf. Dabei wird auch eine DynDNS-Adresse neu aufgelöst.
- **IP-Freigabeliste (Closed-Modus):** Dort die Tunnel-IP deines Laptops eintragen (z. B. 10.8.0.3 bzw. die IP aus dem Heimnetz).
- **Schlüssel:** Der private Schlüssel wird nie über die Weboberfläche ausgegeben. Er liegt aber unverschlüsselt im Flash, weil die NVS-Verschlüsselung aus ist. Einschalten geht über `CONFIG_NVS_ENCRYPTION` mit HMAC-eFuse-Schlüssel. Das brennt eFuses und ist **nicht umkehrbar**, deshalb habe ich es nicht voreingestellt.
- **Was über Distanz geht:** YubiKey, USB-Seriell- und Programmieradapter funktionieren über den Tunnel gut, Webcams und Audio meist nicht (zu hohe Latenz).
- **Ausbauen:** In menuconfig `USBIP_WIREGUARD` abschalten, dann wird der Code gar nicht kompiliert.

## Quellen
- [esphome-libs/wireguard (GitHub)](https://github.com/esphome-libs/wireguard)
- [esphome/wireguard – ESP Component Registry](https://components.espressif.com/components/esphome/wireguard)
- [trombik/esp_wireguard – Original](https://components.espressif.com/components/trombik/esp_wireguard)
