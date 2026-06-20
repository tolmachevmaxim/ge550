# ge550 — TP-Link Archer GE550 Agent Skill

A dependency-light [Agent Skill](https://agentskills.io) to manage a **TP-Link Archer GE550** router through its local HTTPS API: read/write 200+ admin endpoints, control Wi-Fi bands / MLO / OFDMA / Smart Connect, VPN, USB/SMB, and read traffic + client stats — with automatic redaction of passwords/keys in all output. The `SKILL.md` entry point follows the cross-vendor Agent Skills standard (Claude Code / Codex / Cursor / Gemini).

> Configure your router URL with `--host` (default `https://192.168.0.1`). The admin password is read from the macOS Keychain or the `TP_PASS` env var — never hardcoded. Uses the `tplinkrouterc6u` library.

---

# GE550 — TP-Link Archer GE550 CLI

Thin Python CLI wrapping [`tplinkrouterc6u`](https://github.com/AlexandrErohin/TP-Link-Archer-C6U) for the TP-Link Archer GE550 (firmware 1.1.x).

The router's HTTPS admin API is undocumented, encrypted (per-session AES + RSA + sequence counter), and stateful — `tplinkrouterc6u` handles all of that. For features the library doesn't expose, the CLI talks to endpoints discovered from the router's Vite-built JS bundle (211 routes total — see `references/routes.json`).

## Setup

Save the local admin password (the one you type on `https://192.168.0.1/`) into Keychain once:

```zsh
read -rs "TP_PASS?GE550 local password: "; echo
security add-generic-password -a admin -s tplink-ge550-192.168.0.1 -w "$TP_PASS" -U
unset TP_PASS
```

Install the dependency:

```bash
pip install tplinkrouterc6u  # install in your Python venv
```

## Global flags

All commands accept the following (in any position):

| Flag | Default | Purpose |
|---|---|---|
| `--host URL` | `https://192.168.0.1` | Router URL |
| `--user NAME` | `admin` | Admin user |
| `--verify-ssl` | off | Verify TLS (router uses self-signed cert) |
| `--timeout SEC` | `20` | HTTP timeout |
| `--json` | (auto) | JSON output |
| `--yes` | off | Apply mutating actions (without it write commands are **dry-run**) |
| `-v`, `--verbose` | off | Debug logging |

## Inspect commands

```bash
G=~/.claude/skills/ge550/scripts/ge550.py
python3 $G status                 # firmware + Wi-Fi/guest/iot + LAN/WAN + load + clients counts
python3 $G clients                # full per-device list: mac/ip/host/band/signal/down_speed/up_speed/...
python3 $G net                    # IPv4 status: WAN conn-type, DNS primary/secondary, netmask
python3 $G dhcp-leases            # active DHCP leases
python3 $G dhcp-reservations      # static DHCP reservations
python3 $G traffic                # per-client traffic + top talkers
python3 $G game-stats             # list games; add --appid N for per-device records
python3 $G mlo-clients            # cross-reference: real MLO vs single-link clients on MLO SSID
```

## Wi-Fi

Toggle any of 9 networks:

```bash
python3 $G wifi 5g off --yes
python3 $G wifi guest-6g on --yes
python3 $G wifi iot-2g on --yes
```

Bands accepted: `2g`/`2.4g`, `5g`, `6g`, `guest-2g/5g/6g`, `iot-2g/5g`.
(Library has no `IOT_6G`, hence the limited iot set.)

Advanced radio toggles (omit value = read; with value = write):

```bash
python3 $G twt                    # read TWT enable
python3 $G twt on --yes           # turn TWT on
python3 $G ofdma                  # read setting (all/ofdma/mu_mimo/off)
python3 $G ofdma all --yes
python3 $G mlo                    # read MLO host SSID (psk_key masked)
python3 $G smart-connect on --yes # band steering
```

## Backup / restore

Backup writes a config `.bin` (~44 KB). Default destination is the iCloud Drive folder used historically: `~/Library/Mobile Documents/com~apple~CloudDocs/GE550 router backup/`. Filename: `backup-Archer GE550-YYYY-MM-DD.bin` (suffixed with `-HHMM` if same-day file already exists).

```bash
python3 $G backup
python3 $G backup --out /tmp/my.bin --overwrite
python3 $G restore /path/to/backup.bin --yes    # router reboots ~120s
```

## Reboot / scheduling

```bash
python3 $G reboot --yes
python3 $G reboot-schedule       # read current cron-like schedule
python3 $G auto-upgrade          # read auto-firmware-upgrade schedule
python3 $G led-schedule          # read LED + LED night-mode schedule
```

`reboot-schedule` **write** is intentionally not exposed yet: the payload fields (weekday/hour/minute/mode) need a live read of a configured schedule to pin down. Use `raw 'admin/reboot?form=set' --data 'operation=write&...'` if you need it now.

## USB / SMB / Time Machine

```bash
python3 $G disk-list                       # list USB disks + metadata
python3 $G disk-scan --yes                 # trigger rescan
python3 $G disk-eject <serial> --yes       # safely eject
python3 $G share-config                    # folder_sharing settings overview (SMB/DLNA/auth/media/mode)
python3 $G share-tree <uuid> [path]        # browse a shared mount
python3 $G time-machine                    # Time Machine settings + contents
```

## VPN

```bash
python3 $G vpn-status                                  # both server + client status
python3 $G vpn-server openvpn on --yes                 # toggle OpenVPN server
python3 $G vpn-server pptp on --yes                    # toggle PPTP server
python3 $G vpn-client on --yes                         # master switch (use router as VPN client)
python3 $G vpn-client-server <server_id> on --yes      # pick which configured remote VPN to use
python3 $G vpn-client-allow <MAC> on --yes             # per-device whitelist for VPN tunnel
```

**Note:** library declares `VPN.IPSEC` but `set_vpn()` only handles `OPEN_VPN` and `PPTP` — the CLI exposes only the two that work.

## Raw escape hatch

```bash
python3 $G raw 'admin/wireless?form=mlo_host'                    # read
python3 $G raw 'admin/dhcps?form=client' --data 'operation=load'
python3 $G raw 'admin/wireless?form=guest' --data 'operation=write&isolate=on' --yes
```

The 211 endpoints are catalogued in `references/routes.json`. Operations vary per form (`read`, `write`, `set`, `add`, `delete`, `load`, `factory`, `scan`, `remove`…) — inspect the JS bundle (or just try `read` first). `raw` does NOT enforce dry-run; you supply the full body. Avoid `operation=factory` (factory reset) unless you mean it.

## Output safety

- Recursively redacts `password`, `psk`, `psk_key`, `pwd`, `secret`, `stok`, `sysauth`, `key`, `wpa_key`, `sae_key`, `pre_shared_key`, `passphrase`, `auth_token` in any JSON output (e.g. `mlo` always masks `psk_key`).
- Mutating subcommands except `raw` require `--yes`; without it they print the planned change and exit.
- The router only allows ONE active admin session — every CLI invocation logs in fresh, which **kicks any logged-in browser session out**. Batch operations in one Python session when scripting.

## Known footguns

- **TP-Link `tplinkrouterc6u` issue [#119](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/issues/119):** the `smart_network` group (`game_accelerator`, `game_statistic`) silently disables itself for the rest of the session after the first error. The CLI traps that in `game-stats`, but if `status` ever returns mysterious `None`s for game-accelerator fields, reauthorize.
- **`Connection.GUEST_6G.is_guest_wifi()` returns False** due to a typo in the library's enum helper (cosmetic).
- **AFC (6 GHz standard-power)** is intentionally NOT wrapped — wrong lat/lon/power-class can disable the 6 GHz radio without surfacing an error in the UI. Use `raw 'admin/afc?form=settings'` only after a live read of the schema.
- **EasyMesh** is intentionally NOT wrapped — `easymesh_enable=false` and `change_satellite` can drop satellite nodes from the network. Use `raw 'admin/easymesh*'` if you maintain a mesh.
- **Local password is 1-32 chars** per web UI validator. A longer string (e.g. TP-Link Cloud account password) won't authenticate.
- The TP-Link SSH on `:20001` accepts the password but disables `exec`, PTY, and SFTP — useless as a real shell.

## Files

- `SKILL.md` — short skill front-matter for Claude Code.
- `scripts/ge550.py` — the CLI.
- `references/routes.json` — 211 admin endpoints discovered in firmware 1.1.2 (2025-08-28).
- `references/protocol.md` — login + multipart backup flow + endpoint mining notes.

## Cross-platform

Symlinked at:
- `~/.codex/skills/ge550` (Codex)
- `~/.agents/skills/ge550` (generic agent runners)
