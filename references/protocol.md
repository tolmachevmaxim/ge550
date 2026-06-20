# GE550 API protocol notes

Reverse-engineered from the GE550 web UI (firmware `1.1.2 Build 20250828`) plus the [`tplinkrouterc6u`](https://github.com/AlexandrErohin/TP-Link-Archer-C6U) library, which already implements the encrypted handshake for this model family.

## Authentication

The router exposes a single web UI / API surface at `https://<router>/`. There is no separate username — the login page asks only for a "Local Password" (1–32 characters; longer values are rejected by the form validator). Internally the account is `admin`.

Three-step encrypted login (`tplinkrouterc6u` handles it automatically):

1. `POST /cgi-bin/luci/;stok=/login?form=auth` `operation=read` → returns RSA public key + modulus for password encryption + `mode` + `username`.
2. `POST /cgi-bin/luci/;stok=/login?form=keys` `operation=read` → returns RSA public key for AES key wrapping + a numeric `seq` (nonce/sequence counter).
3. `POST /cgi-bin/luci/;stok=/login?form=login` with: RSA-encrypted password, RSA-wrapped client-generated AES key, AES-encrypted login payload, and an MD5 signature over `data || seq+length`. Server returns `stok` (session token) and sets `sysauth` cookie.

After login, all admin requests go to `/cgi-bin/luci/;stok=<stok>/admin/...`, body is `operation=...&...`. Response payloads are AES-encrypted (`{"data": "base64..."}`) and the library handles encrypt + decrypt + seq increment transparently.

## SSH (`:20001`)

Open `dropbear_2019.78` SSH endpoint accepts `admin` + the same local password, but the device rejects `exec`, PTY allocation and SFTP — so the SSH endpoint is not a real CLI. Use the HTTPS API instead.

## Multipart endpoints (binary I/O)

The encrypted-JSON channel doesn't carry binary blobs. Backup/restore/firmware-upload use a separate **multipart/form-data** endpoint with the same authenticated session (cookie + stok).

### Backup config

Two-step:

1. `POST /cgi-bin/luci/;stok=<stok>/admin/firmware?form=config` (encrypted JSON) `operation=check` → validation.
2. `POST /cgi-bin/luci/;stok=<stok>/admin/firmware?form=config_multipart`, multipart with `operation=backup` → server replies `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="backup-Archer GE550-YYYY-MM-DD.bin"`. Body is the binary config (~44 KB on a lightly-used unit).

### Restore config

`POST /cgi-bin/luci/;stok=<stok>/admin/firmware?form=config_multipart`, multipart with `operation=restore` and `file=<bin>`. Server applies the config and reboots (~120s downtime). Web UI uses a 720s timeout.

### Firmware upgrade

`POST /cgi-bin/luci/;stok=<stok>/admin/firmware?form=save_upgrade`, multipart with `operation=firmware`, `keep=on`, `image=<bin>`. 720s timeout.

### Factory reset

`POST /cgi-bin/luci/;stok=<stok>/admin/firmware?form=config` (encrypted JSON, not multipart) with `operation=factory&all=true` (wipe everything) or `all=false` (keep user account). Destructive.

## Endpoint inventory

`references/routes.json` lists the 211 `/admin/...?form=...` routes discovered by scanning the 340 Vite-built JS chunks under `/webpages/js/`. Every entry there can be hit via the `raw` subcommand — `operation=read` is the safe default; mutating operations vary per form (`write`, `set`, `add`, `delete`, `load`, `scan`, `remove`, etc.) — inspect the corresponding `update-store-*.js` chunk to find them.

## Endpoint mining notes (mined from `/tmp/ge550-explore/js/`)

### Wireless

- `admin/wireless?form=smart_connect` — `read` returns `{smart_enable: on|off}`. `write` sets `smart_enable`. Band steering master switch. Used by `cmd_smart_connect`.
- `admin/wireless?form=mlo_host` — read works. Write fields include `ssid`, `encryption` (see WPA modes list below), `psk_key`, `psk_version`, `hidden`, `band_select`, `selected_bands`. Library has no high-level wrapper; use `raw` until a live read of a configured payload pins down all field names.
- Supported WPA modes (mined from `wirelessService-D9iRA_Tk.js`): `None`, `EnhancedOpen` (OWE), `Wpa2Aes`, `Wpa2AesTkip`, `Wpa3Personal`, `Wpa3PersonalAes` (WPA3 + WPA2 transition), `WpaEnterprise`, `WpaEnterpriseTkip`. 6 GHz only supports `EnhancedOpen` and `Wpa3Personal`.
- `admin/wireless?form=twt` / `form=ofdma_mimo` — single field each (`enable: on|off` and `setting: all|ofdma|mu_mimo|off`).

### Reboot

- `admin/system?form=reboot` — `request({operation: "reboot"})` triggers immediate reboot; `write(payload)` modifies a small immediate-reboot config (cooldown timer).
- `admin/reboot?form=set` — `read` returns the user-configured cron-like reboot schedule; `write(payload)` sets it. Field names not in JS string constants (Vue binds them dynamically) — need a live read of a configured schedule to pin down. CLI exposes only the read path for now (`cmd_reboot_schedule`).

### EasyMesh (intentionally NOT wrapped)

Endpoints exist (mined from `easymesh-BDYrYNmG.js`): `/admin/easymesh?form=easymesh_enable` (enable on/off), `/admin/easymesh?form=search_slave` (start/stop/check satellite onboarding), `/admin/easymesh_network?form=available_mesh_device_manage` (link/unlink/reboot/add_onboarding by MAC), `/admin/easymesh_network?form=mesh_sclient_detail` (per-client read/write), `/admin/easymesh_network?form=get_mesh_device_list_all`, `/admin/easymesh_network?form=change_satellite` (rename/swap a node — high risk).

Skipped per user choice: no mesh deployment here. Use `raw` if needed.

### USB / SMB / Time Machine (mined from `index-B8Qj2QJp.js`, `index-Bjl7iYZM.js`)

| Endpoint | Operations / Notes |
|---|---|
| `admin/disk_setting?form=scan` | `read`, `request{operation:"scan"}` to rescan |
| `admin/disk_setting?form=metadata` | `read` (size, filesystem, mountpoint), `request{operation:"scan"}` to refresh |
| `admin/disk_setting?form=remove` | `request{operation:"remove", serial:<X>}` — safely eject |
| `admin/folder_sharing?form=settings` | `read` settings + `request{operation:"save", ...}` to write |
| `admin/folder_sharing?form=mode` | `read` (workgroup mode etc.) |
| `admin/folder_sharing?form=server` | `read` (SMB/FTP server enable + names) |
| `admin/folder_sharing?form=auth` | `read` (users + access rules) |
| `admin/folder_sharing?form=media` | `read` (DLNA media server config) |
| `admin/folder_sharing?form=partial` | `read` (per-folder share definitions) |
| `admin/folder_sharing?form=tree` | `request{operation:"load", uuid:<disk>, path:<dir>}` — directory listing |
| `admin/time_machine?form=settings` | `read` Time Machine target settings |
| `admin/time_machine?form=contents` | `read` existing backups under the share |

### Traffic & game stats

- `admin/traffic?form=traffic_enable` — enable/disable per-client traffic monitor
- `admin/traffic?form=list` / `form=top_list` / `form=traffic_data` — read per-client + top talkers + aggregated stats
- `admin/smart_network?form=game_statistic` — `request{operation:"get_game_list"}` returns active games; `request{operation:"get_game_record", appid:N}` returns per-device records. Known bug: `smart_network` group silently disables after first error in a session ([tplinkrouterc6u#119](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/issues/119)).

### LED / Eco / Auto-upgrade

- `admin/ledgeneral?form=setting` — master LED on/off
- `admin/ledpm?form=setting` — LED night-mode schedule
- `admin/eco_mode?form=settings` — energy-saving schedule (write schema needs live read)
- `admin/firmware?form=auto_upgrade` — auto firmware upgrade schedule (read works; write schema needs live read)
- `admin/firmware?form=upgrade` — read returns firmware metadata
- `admin/firmware?form=save_upgrade` — multipart upload with `operation=firmware, keep=on, image=<bin>`, 720 s timeout

### Intentionally NOT wrapped

- **AFC** (`admin/afc?form=settings`) — 6 GHz standard-power, regulatory; wrong lat/lon/power-class can disable 6 GHz silently.
- **WTFast** (12 forms under `admin/wtfast?form=*`) — requires paid WTFast subscription. Skipped per user.
- **Avira Parental Controls** (`admin/avira_parental_control?form=avira_pactrl`, 11 operations) — Skipped per user.

For all of these, `raw` works as the escape hatch.
