---
name: ge550
description: "Manage the TP-Link Archer GE550 router from CLI: backup/restore config, read/write 211 admin endpoints, control Wi-Fi (bands, TWT, OFDMA, MLO, Smart Connect), VPN server+client, USB/SMB/Time Machine, traffic + game stats. Uses tplinkrouterc6u; secrets from Keychain."
allowed-tools: Bash(python3 ~/.claude/skills/ge550/scripts/*), Bash(security find-generic-password *)
---

# GE550

TP-Link Archer GE550 (firmware 1.1.x). Password in Keychain: `admin / tplink-ge550-192.168.0.1`.

`G=~/.claude/skills/ge550/scripts/ge550.py` then `python3 $G <cmd>`. Add `--yes` to apply writes (otherwise dry-run). `--json` works in any position. Override host via `--host https://...`.

## Inspect
- `status` / `clients` / `net` / `dhcp-leases` / `dhcp-reservations` / `traffic` / `game-stats [--appid N]`
- `mlo-clients` — cross-references raw associated STAs with smart_network tagging: real MLO multi-link vs. single-link clients hiding on the MLO SSID (Wi-Fi 6E radios, Pixel 6 Pro etc.)

## Wi-Fi
- `wifi <band> on|off --yes` — bands: `2g`, `5g`, `6g`, `guest-2g/5g/6g`, `iot-2g/5g`
- `twt [on|off] --yes` / `ofdma [all|ofdma|mu_mimo|off] --yes` / `mlo [on|off] --yes` / `smart-connect [on|off] --yes`

## System
- `backup [--out PATH]` — default → iCloud `GE550 router backup/`
- `restore <file.bin> --yes` / `reboot --yes`
- `reboot-schedule` / `auto-upgrade` / `led-schedule` — read-only

## USB / SMB
- `disk-list` / `disk-scan --yes` / `disk-eject <serial> --yes`
- `share-config` / `share-tree <uuid> [path]` / `time-machine`

## VPN
- `vpn-status` / `vpn-server <openvpn|pptp> on|off --yes` / `vpn-client on|off --yes`
- `vpn-client-server <id> on|off --yes` / `vpn-client-allow <mac> on|off --yes`

## Escape
- `raw '<admin/...?form=...>' [--data 'operation=...']` — escape hatch to any of 211 endpoints (`references/routes.json`)

Full docs: README.md. Protocol notes: references/protocol.md.
