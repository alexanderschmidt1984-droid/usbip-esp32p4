# Vendored esphome/wireguard 0.4.8 (commit 9b7660f) with security fixes

Source: https://github.com/esphome-libs/wireguard (BSD-3-Clause, see LICENSE).
This copy overrides the registry package. All changes are marked `FIX(usbip)`:

1. Inner-packet source filter compared the DESTINATION address instead of the
   SOURCE address (cryptokey routing bypass / source spoofing).
2. Endpoint roaming and keep-alives were processed before the replay check
   (replayed packets could redirect the tunnel).
3. Cookie replies no longer change the peer endpoint (forgeable by on-path observers).
4. Handshake rate limit computed `last - now` instead of `now - last` (never triggered).
5. IPv4 header was read from decrypted packets shorter than 20 bytes (over-read).
6. Inner IPv6 packets were accepted without any source filtering - now dropped.
7. Replay window widened from 32 to 2048 packets; 64-bit counter difference no
   longer truncated; counters >= REJECT_AFTER_MESSAGES rejected.
