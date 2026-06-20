#!/usr/bin/env python3
"""GE550 CLI — tplinkrouterc6u wrapper for the TP-Link Archer GE550.

Subcommands grouped by purpose:

  Inspect:     status, clients, net, dhcp-leases, dhcp-reservations,
               traffic, game-stats, vpn-status
  Wi-Fi:       wifi <band> on|off, twt, ofdma, mlo, smart-connect
  System:      backup, restore, reboot, reboot-schedule,
               auto-upgrade, led-schedule
  USB / SMB:   disk-list, disk-scan, disk-eject, share-config, share-tree,
               time-machine
  VPN:         vpn-server, vpn-client, vpn-client-server, vpn-client-allow
  Escape:      raw <path> [--data ...]

Secrets pulled from macOS Keychain by default (service:
`tplink-ge550-<host>`, account: admin). Write commands are dry-run unless
`--yes` is passed. `--json` is supported on every command and works in
any position.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import urllib3
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------- config ---------------------------------------------------------

DEFAULT_HOST = "https://192.168.0.1"
DEFAULT_USER = "admin"
DEFAULT_BACKUP_DIR = Path.home() / "Library/Mobile Documents/com~apple~CloudDocs/GE550 router backup"

SECRET_KEY_NAMES = {
    "password", "psk", "psk_key", "pwd", "secret", "stok", "sysauth", "key",
    "wpa_key", "sae_key", "pre_shared_key", "passphrase", "auth_token",
}

# Substring patterns that also trigger masking — catches compound names like
# `wireless_2g_psk_key`, `mlo_host_6g_psk_key`, `guest_2g_portal_password`.
SECRET_SUBSTRINGS = (
    "psk_key", "psk_cipher", "psk_pass",
    "wpa_key", "wpa_pass",
    "wep_key", "sae_key",
    "_password", "passphrase", "auth_token",
    "_pwd", "_secret",
)


def _is_secret_key(name: str) -> bool:
    lname = name.lower()
    if lname in SECRET_KEY_NAMES:
        return True
    return any(s in lname for s in SECRET_SUBSTRINGS)


def keychain_password(host: str, user: str = DEFAULT_USER) -> str:
    netloc = urlparse(host).hostname or host
    service = f"tplink-ge550-{netloc}"
    try:
        out = subprocess.check_output(
            ["security", "find-generic-password", "-a", user, "-s", service, "-w"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.rstrip("\n")
    except subprocess.CalledProcessError:
        raise SystemExit(
            f"keychain: no entry for service={service} account={user}\n"
            f"Save it once with:\n"
            f"  read -rs 'TP_PASS?GE550 local password: '; echo\n"
            f"  security add-generic-password -a {user} -s {service} -w \"$TP_PASS\" -U; unset TP_PASS"
        )


def mask(obj):
    """Recursively redact secret-looking values for logging."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return mask(asdict(obj))
    if isinstance(obj, dict):
        return {
            k: (f"<redacted len={len(v)}>"
                if isinstance(v, str) and v and _is_secret_key(k)
                else mask(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [mask(x) for x in obj]
    return obj


# ---------- router wrapper -------------------------------------------------

class Router:
    """Lazy-init authenticated wrapper around tplinkrouterc6u."""
    def __init__(self, host, user, password, verify_ssl=False, timeout=20):
        from tplinkrouterc6u import TplinkRouterProvider  # local import for --help
        self._client = TplinkRouterProvider.get_client(
            host=host, password=password, username=user,
            verify_ssl=verify_ssl, timeout=timeout,
        )
        self._client.authorize()
        self.verify_ssl = verify_ssl

    @property
    def underlying(self):
        return self._client

    def request(self, path, data, ignore_errors=True):
        return self._client.request(path, data, ignore_errors=ignore_errors)

    def read(self, path):
        return self.request(path, "operation=read")

    def write(self, path, **kw):
        body = "operation=write&" + "&".join(f"{k}={v}" for k, v in kw.items())
        return self.request(path, body)

    def op(self, path, operation, **kw):
        body = f"operation={operation}"
        if kw:
            body += "&" + "&".join(f"{k}={v}" for k, v in kw.items())
        return self.request(path, body)

    def get_status(self):
        return self._client.get_status()

    def get_firmware(self):
        return self._client.get_firmware()

    def get_ipv4_status(self):
        return self._client.get_ipv4_status()

    def get_ipv4_dhcp_leases(self):
        return self._client.get_ipv4_dhcp_leases()

    def get_ipv4_reservations(self):
        return self._client.get_ipv4_reservations()

    def get_vpn_status(self):
        return self._client.get_vpn_status()

    def get_vpn_client_status(self):
        return self._client.get_vpn_client_status()

    def set_wifi(self, conn, enable):
        return self._client.set_wifi(conn, enable)

    def set_vpn(self, vpn, enable):
        return self._client.set_vpn(vpn, enable)

    def set_vpn_client(self, enable):
        return self._client.set_vpn_client(enable)

    def set_vpn_client_server(self, server_id, enable):
        return self._client.set_vpn_client_server(server_id, enable)

    def set_vpn_client_device(self, mac, enable):
        return self._client.set_vpn_client_device(mac, enable)

    def reboot(self):
        self._client.reboot()

    def multipart_post(self, path, files, *, timeout=120, stream=False):
        """Raw multipart POST against the live authenticated session."""
        url = f"{self._client.host}/cgi-bin/luci/;stok={self._client._stok}/{path}"
        cookies = {"sysauth": self._client._sysauth}
        headers = {"Referer": f"{self._client.host}/webpages/index.html"}
        return requests.post(
            url, files=files, headers=headers, cookies=cookies,
            timeout=timeout, verify=self.verify_ssl, stream=stream,
        )

    def logout(self):
        try:
            self._client.logout()
        except Exception:
            pass


def open_router(args) -> Router:
    password = os.environ.get("TP_PASS") or keychain_password(args.host, args.user)
    return Router(host=args.host, user=args.user, password=password,
                  verify_ssl=args.verify_ssl, timeout=args.timeout)


# ---------- output helpers -------------------------------------------------

def emit(data, args, *, masked=True):
    out = mask(data) if masked else data
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))


def confirm(args, action_desc):
    if args.yes:
        return True
    print(f"[DRY-RUN] would: {action_desc}\nPass --yes to apply.", file=sys.stderr)
    return False


def run_with_router(args, fn):
    r = open_router(args)
    try:
        return fn(r)
    finally:
        r.logout()


# ---------- inspect commands ----------------------------------------------

def cmd_status(args):
    def do(r: Router):
        fw = r.get_firmware()
        st = r.get_status()
        data = {
            "host": args.host,
            "firmware": {
                "model": fw.model,
                "hardware": fw.hardware_version,
                "firmware": fw.firmware_version,
            },
            "wifi": {"2.4g": st.wifi_2g_enable, "5g": st.wifi_5g_enable, "6g": st.wifi_6g_enable},
            "guest": {"2.4g": st.guest_2g_enable, "5g": st.guest_5g_enable, "6g": st.guest_6g_enable},
            "iot": {"2.4g": st.iot_2g_enable, "5g": st.iot_5g_enable, "6g": st.iot_6g_enable},
            "lan": {"ip": st.lan_ipv4_addr, "mac": st.lan_macaddr},
            "wan": {
                "ip": st.wan_ipv4_addr,
                "gateway": st.wan_ipv4_gateway,
                "mac": st.wan_macaddr,
                "uptime": st.wan_ipv4_uptime,
                "conn_type": getattr(st, "conn_type", None),
            },
            "load": {"cpu": st.cpu_usage, "mem": st.mem_usage},
            "clients": {
                "wifi": st.wifi_clients_total,
                "wired": st.wired_total,
                "guest": st.guest_clients_total,
                "iot": st.iot_clients_total,
                "total": st.clients_total,
            },
        }
        emit(data, args)
    run_with_router(args, do)


def cmd_clients(args):
    def do(r: Router):
        st = r.get_status()
        devices = []
        for d in getattr(st, "devices", []) or []:
            entry = mask(asdict(d) if is_dataclass(d) else d)
            devices.append(entry)
        emit({"count": len(devices), "devices": devices}, args, masked=False)
    run_with_router(args, do)


def cmd_net(args):
    def do(r: Router):
        s = r.get_ipv4_status()
        emit(s, args)
    run_with_router(args, do)


def cmd_dhcp_leases(args):
    def do(r: Router):
        leases = r.get_ipv4_dhcp_leases()
        emit({"count": len(leases), "leases": leases}, args)
    run_with_router(args, do)


def cmd_dhcp_reservations(args):
    def do(r: Router):
        res = r.get_ipv4_reservations()
        emit({"count": len(res), "reservations": res}, args)
    run_with_router(args, do)


def cmd_raw(args):
    def do(r: Router):
        data = args.data or "operation=read"
        emit(r.request(args.path, data, ignore_errors=True), args)
    run_with_router(args, do)


# ---------- Wi-Fi commands ------------------------------------------------

_BAND_TO_CONNECTION = {
    # host bands
    "2g":       "HOST_2G",   "2.4g":     "HOST_2G",
    "5g":       "HOST_5G",   "6g":       "HOST_6G",
    # guest network bands
    "guest-2g": "GUEST_2G",  "guest-2.4g": "GUEST_2G",
    "guest-5g": "GUEST_5G",  "guest-6g":   "GUEST_6G",
    # iot (only 2g/5g — library has no IOT_6G)
    "iot-2g":   "IOT_2G",    "iot-2.4g":   "IOT_2G",
    "iot-5g":   "IOT_5G",
}


def cmd_wifi(args):
    from tplinkrouterc6u import Connection
    conn_name = _BAND_TO_CONNECTION[args.band.lower()]
    enable = args.state.lower() == "on"
    if not confirm(args, f"set Wi-Fi {args.band.upper()} -> {'ON' if enable else 'OFF'}"):
        return
    def do(r: Router):
        r.set_wifi(getattr(Connection, conn_name), enable)
        emit({"ok": True, "band": args.band, "enable": enable}, args)
    run_with_router(args, do)


def _read_write_toggle(args, *, path, field, valid_values=None):
    """Generic: subcommand that reads on no-arg, writes on with-arg."""
    def do(r: Router):
        cur = r.read(path)
        new = args.state.lower() if args.state else None
        if new is None:
            emit(cur, args); return
        if valid_values and new not in valid_values:
            raise SystemExit(f"value must be one of {sorted(valid_values)}")
        if cur.get(field) == new:
            emit({"ok": True, "noop": True, field: new}, args); return
        if not confirm(args, f"set {path} {field}: {cur.get(field)} -> {new}"):
            return
        emit({"before": cur, "after": r.write(path, **{field: new})}, args)
    run_with_router(args, do)


def cmd_twt(args):
    _read_write_toggle(args, path="admin/wireless?form=twt", field="enable",
                       valid_values={"on", "off"})


def cmd_ofdma(args):
    # `state` here is repurposed to carry the value
    args.state = args.value
    _read_write_toggle(args, path="admin/wireless?form=ofdma_mimo", field="setting",
                       valid_values={"all", "ofdma", "mu_mimo", "off"})


def cmd_mlo(args):
    _read_write_toggle(args, path="admin/wireless?form=mlo_host", field="enable",
                       valid_values={"on", "off"})


def _is_randomized_mac(mac: str) -> bool:
    """Locally-administered bit set on the first octet => randomized MAC.
    Android, iOS, Windows all randomize by default when joining new SSIDs.
    """
    try:
        first = int(mac.replace(":", "-").split("-")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b10)


def cmd_mlo_clients(args):
    """Cross-reference wireless STAs to find MLO clients including those
    hidden from the GUI.

    The router has two relevant client sources:

      A) `wireless?form=statistics` — ALL associated STAs (MAC + per-band
         `type` field; type is empty for STAs connected to the MLO SSID).
      B) `smart_network?form=game_accelerator` (loadDevice) — classified
         clients with `deviceTag` ("mlo", "5G", "2.4G", "6G", "iot_*").
         The GUI uses this; it silently OMITS clients connected to the
         MLO SSID that don't actually use multi-link (e.g. Wi-Fi 6E
         single-band radios that joined the MLO SSID).

    Classification:
      - In B with deviceTag=mlo                       -> "real MLO"
      - In A with empty type, NOT in B                -> "on MLO SSID,
                                                         single-link
                                                         (hidden from UI)"
      - In B with any other tag                        -> regular band client
      - In A only (not in B), with type set            -> raw STA, unusual
    """
    def do(r: Router):
        stats = r.request("admin/wireless?form=statistics", "operation=load",
                          ignore_errors=True)
        smart = r.op("admin/smart_network?form=game_accelerator", "loadDevice")

        stats_by_mac = {d["mac"].upper(): d for d in (stats or [])
                        if isinstance(d, dict) and d.get("mac")}
        smart_by_mac = {d["mac"].upper(): d for d in (smart or [])
                        if isinstance(d, dict) and d.get("mac")}

        def enrich(mac: str) -> dict:
            s = stats_by_mac.get(mac, {}) or {}
            sm = smart_by_mac.get(mac, {}) or {}
            return {
                "mac": mac,
                "name": sm.get("deviceName"),
                "ip":   sm.get("ip"),
                "host": sm.get("host"),
                "signal": sm.get("signal"),
                "tx_rate": sm.get("txrate"),
                "rx_rate": sm.get("rxrate"),
                "online_time_s": sm.get("onlineTime"),
                "device_tag": sm.get("deviceTag"),
                "stats_type": s.get("type"),
                "randomized_mac": _is_randomized_mac(mac),
            }

        # Map raw type strings from wireless statistics to canonical band tags
        TYPE_TO_TAG = {
            "2.4GHz":  "2.4g",
            "5GHz":    "5g",
            "5GHz-1":  "5g",
            "5GHz-2":  "5g2",
            "6GHz":    "6g",
        }

        real_mlo, hidden_mlo, by_tag, raw_unclassified = [], [], {}, []

        for mac in sorted(set(stats_by_mac) | set(smart_by_mac)):
            s = stats_by_mac.get(mac, {})
            sm = smart_by_mac.get(mac, {})
            tag = (sm.get("deviceTag") or "").lower()
            stype = s.get("type")  # empty/missing => connected to MLO SSID
            entry = enrich(mac)

            if tag == "mlo":
                real_mlo.append(entry)
            elif not stype and mac in stats_by_mac and mac not in smart_by_mac:
                # On MLO SSID but smart_network dropped it => single-link only
                hidden_mlo.append(entry)
            elif tag:
                by_tag.setdefault(tag, []).append(entry)
            elif stype:
                # smart_network didn't return this MAC (known bug #119), but
                # statistics gave us a band; classify by band as fallback.
                fallback_tag = TYPE_TO_TAG.get(stype, stype.lower())
                by_tag.setdefault(fallback_tag, []).append(entry)
            else:
                raw_unclassified.append(entry)

        result = {
            "totals": {
                "associated_stas":     len(stats_by_mac),
                "classified_by_smart": len(smart_by_mac),
                "real_mlo":            len(real_mlo),
                "hidden_on_mlo_ssid":  len(hidden_mlo),
                "regular":             sum(len(v) for v in by_tag.values()),
                "unclassified":        len(raw_unclassified),
            },
            "real_mlo": real_mlo,
            "hidden_on_mlo_ssid": hidden_mlo,
            "by_tag": dict(sorted(by_tag.items())),
            "raw_unclassified": raw_unclassified,
            "notes": [
                "real_mlo: deviceTag='mlo' in smart_network — multi-link active.",
                "hidden_on_mlo_ssid: connected to MLO SSID but single-link only "
                "(Wi-Fi 6E radios, Pixel 6/8 Pro etc.). Router shows them in raw "
                "associated-STA list but the GUI hides them.",
                "randomized_mac=true is normal for modern phones (Android/iOS/Win).",
            ],
        }
        emit(result, args)
    run_with_router(args, do)


def cmd_smart_connect(args):
    """Band steering. JS: /admin/wireless?form=smart_connect, write {smart_enable: on|off}"""
    path = "admin/wireless?form=smart_connect"
    def do(r: Router):
        cur = r.read(path)
        if not args.state:
            emit(cur, args); return
        new = args.state.lower()
        if cur.get("smart_enable") == new:
            emit({"ok": True, "noop": True, "smart_connect": new}, args); return
        if not confirm(args, f"set Smart Connect {cur.get('smart_enable')} -> {new}"):
            return
        emit({"before": cur, "after": r.write(path, smart_enable=new)}, args)
    run_with_router(args, do)


# ---------- backup / restore / reboot -------------------------------------

def _default_backup_path() -> Path:
    today = datetime.now().strftime("%Y-%m-%d")
    base = DEFAULT_BACKUP_DIR / f"backup-Archer GE550-{today}.bin"
    if not base.exists():
        return base
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    return base.with_name(f"backup-Archer GE550-{stamp}.bin")


def cmd_backup(args):
    out_path = Path(args.out) if args.out else _default_backup_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and not args.overwrite:
        raise SystemExit(f"refusing to overwrite {out_path}. Pass --overwrite or --out.")
    def do(r: Router):
        check = r.request("admin/firmware?form=config", "operation=check")
        resp = r.multipart_post("admin/firmware?form=config_multipart",
                                files={"operation": (None, "backup")},
                                timeout=300, stream=True)
        ctype = resp.headers.get("Content-Type", "")
        if not ctype.startswith("application/octet-stream"):
            raise SystemExit(f"unexpected Content-Type: {ctype!r}\n{resp.text[:200]}")
        size = 0
        with out_path.open("wb") as f:
            for chunk in resp.iter_content(64 * 1024):
                f.write(chunk); size += len(chunk)
        emit({
            "ok": True, "path": str(out_path), "bytes": size,
            "filename_from_server": resp.headers.get("Content-Disposition", ""),
            "check": check,
        }, args)
    run_with_router(args, do)


def cmd_restore(args):
    path = Path(args.file).expanduser()
    if not path.is_file():
        raise SystemExit(f"file not found: {path}")
    if not confirm(args, f"restore router config from {path} (router will reboot, ~120s downtime)"):
        return
    def do(r: Router):
        resp = r.multipart_post(
            "admin/firmware?form=config_multipart",
            files={
                "operation": (None, "restore"),
                "file": (path.name, path.read_bytes(), "application/octet-stream"),
            },
            timeout=720,
        )
        try:
            j = resp.json()
        except Exception:
            j = {"status": resp.status_code, "body_head": resp.text[:200]}
        emit({"ok": resp.status_code == 200, "response": j}, args)
    run_with_router(args, do)


def cmd_reboot(args):
    if not confirm(args, "reboot router (~120s downtime)"): return
    def do(r: Router):
        r.reboot()
        emit({"ok": True, "rebooting": True}, args)
    run_with_router(args, do)


def cmd_reboot_schedule(args):
    """Read current reboot schedule. Write NOT yet implemented — payload
    schema (cron-like fields: weekday/hour/minute/mode) needs a live sample.
    Use `raw 'admin/reboot?form=set' --data 'operation=write&...'` for now.
    """
    def do(r: Router):
        emit(r.read("admin/reboot?form=set"), args)
    run_with_router(args, do)


def cmd_auto_upgrade(args):
    def do(r: Router):
        emit(r.read("admin/firmware?form=auto_upgrade"), args)
    run_with_router(args, do)


def cmd_led_schedule(args):
    def do(r: Router):
        general = r.read("admin/ledgeneral?form=setting")
        pm      = r.read("admin/ledpm?form=setting")
        emit({"general": general, "schedule": pm}, args)
    run_with_router(args, do)


def cmd_traffic(args):
    def do(r: Router):
        out = {
            "enable":    r.read("admin/traffic?form=traffic_enable"),
            "list":      r.read("admin/traffic?form=list"),
            "top_list":  r.read("admin/traffic?form=top_list"),
            "stats":     r.read("admin/traffic?form=traffic_data"),
        }
        emit(out, args)
    run_with_router(args, do)


def cmd_game_stats(args):
    """Read game statistics. NOTE: smart_network endpoints have known
    silent-disable behavior (tplinkrouterc6u issue #119)."""
    def do(r: Router):
        try:
            games = r.op("admin/smart_network?form=game_statistic", "get_game_list")
        except Exception as e:  # pragma: no cover
            emit({"error": f"{type(e).__name__}: {e}", "endpoint": "game_statistic"}, args)
            return
        result = {"games": games}
        if args.appid is not None:
            try:
                result["records"] = r.op("admin/smart_network?form=game_statistic",
                                          "get_game_record", appid=args.appid)
            except Exception as e:
                result["records_error"] = f"{type(e).__name__}: {e}"
        emit(result, args)
    run_with_router(args, do)


# ---------- USB / SMB / Time Machine --------------------------------------

def cmd_disk_list(args):
    def do(r: Router):
        out = {
            "scan":     r.read("admin/disk_setting?form=scan"),
            "metadata": r.read("admin/disk_setting?form=metadata"),
        }
        emit(out, args)
    run_with_router(args, do)


def cmd_disk_scan(args):
    if not confirm(args, "trigger USB disk rescan (no data risk)"): return
    def do(r: Router):
        emit({"scan": r.op("admin/disk_setting?form=scan", "scan")}, args)
    run_with_router(args, do)


def cmd_disk_eject(args):
    if not confirm(args, f"safely eject disk serial={args.serial}"): return
    def do(r: Router):
        emit({"eject": r.op("admin/disk_setting?form=remove",
                            "remove", serial=args.serial)}, args)
    run_with_router(args, do)


def cmd_share_config(args):
    def do(r: Router):
        out = {
            "settings": r.read("admin/folder_sharing?form=settings"),
            "mode":     r.read("admin/folder_sharing?form=mode"),
            "server":   r.read("admin/folder_sharing?form=server"),
            "auth":     r.read("admin/folder_sharing?form=auth"),
            "media":    r.read("admin/folder_sharing?form=media"),
            "partial":  r.read("admin/folder_sharing?form=partial"),
        }
        emit(out, args)
    run_with_router(args, do)


def cmd_share_tree(args):
    def do(r: Router):
        emit(r.op("admin/folder_sharing?form=tree",
                  "load", uuid=args.uuid, path=args.path), args)
    run_with_router(args, do)


def cmd_time_machine(args):
    def do(r: Router):
        out = {
            "settings": r.read("admin/time_machine?form=settings"),
            "contents": r.read("admin/time_machine?form=contents"),
        }
        emit(out, args)
    run_with_router(args, do)


# ---------- VPN -----------------------------------------------------------

def cmd_vpn_status(args):
    def do(r: Router):
        emit({
            "server": r.get_vpn_status(),
            "client": r.get_vpn_client_status(),
        }, args)
    run_with_router(args, do)


def cmd_vpn_server(args):
    from tplinkrouterc6u import VPN
    server_map = {"openvpn": VPN.OPEN_VPN, "pptp": VPN.PPTP}
    # Note: VPN.IPSEC enum exists in lib but set_vpn falls back to PPTP path for
    # anything that isn't OPEN_VPN, so we expose only the two it actually handles.
    kind = args.kind.lower()
    enable = args.state.lower() == "on"
    if not confirm(args, f"set VPN server {kind} -> {'ON' if enable else 'OFF'}"):
        return
    def do(r: Router):
        r.set_vpn(server_map[kind], enable)
        emit({"ok": True, "vpn": kind, "enable": enable}, args)
    run_with_router(args, do)


def cmd_vpn_client(args):
    enable = args.state.lower() == "on"
    if not confirm(args, f"set VPN client master switch -> {'ON' if enable else 'OFF'}"):
        return
    def do(r: Router):
        r.set_vpn_client(enable)
        emit({"ok": True, "vpn_client": enable}, args)
    run_with_router(args, do)


def cmd_vpn_client_server(args):
    enable = args.state.lower() == "on"
    if not confirm(args, f"activate VPN client server_id={args.server_id} -> {'ON' if enable else 'OFF'}"):
        return
    def do(r: Router):
        r.set_vpn_client_server(args.server_id, enable)
        emit({"ok": True, "server_id": args.server_id, "enable": enable}, args)
    run_with_router(args, do)


def cmd_vpn_client_allow(args):
    enable = args.state.lower() == "on"
    if not confirm(args, f"whitelist mac={args.mac} for VPN client -> {'ON' if enable else 'OFF'}"):
        return
    def do(r: Router):
        r.set_vpn_client_device(args.mac, enable)
        emit({"ok": True, "mac": args.mac, "enable": enable}, args)
    run_with_router(args, do)


# ---------- argparse ------------------------------------------------------

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default=DEFAULT_HOST,
                        help=f"Router URL (default {DEFAULT_HOST})")
    common.add_argument("--user", default=DEFAULT_USER,
                        help="Admin user (default admin)")
    common.add_argument("--verify-ssl", action="store_true",
                        help="Verify TLS (router uses self-signed cert; off by default)")
    common.add_argument("--timeout", type=int, default=20)
    common.add_argument("--json", action="store_true",
                        help="JSON output (also the default for structured commands)")
    common.add_argument("--yes", action="store_true",
                        help="Confirm mutating actions; without --yes write commands dry-run")
    common.add_argument("-v", "--verbose", action="store_true")

    p = argparse.ArgumentParser(prog="ge550", parents=[common],
        description="TP-Link Archer GE550 CLI (encrypted API via tplinkrouterc6u).")
    sub = p.add_subparsers(dest="cmd", required=True)

    # --- inspect ---
    sub.add_parser("status",  parents=[common],
                   help="Firmware + Wi-Fi + LAN/WAN + clients counts"
                   ).set_defaults(func=cmd_status)
    sub.add_parser("clients", parents=[common],
                   help="Per-device list with signal/speeds/traffic"
                   ).set_defaults(func=cmd_clients)
    sub.add_parser("net",     parents=[common],
                   help="WAN/LAN IPv4 status: conn-type, DNS, netmask"
                   ).set_defaults(func=cmd_net)
    sub.add_parser("dhcp-leases", parents=[common],
                   help="Active DHCP leases"
                   ).set_defaults(func=cmd_dhcp_leases)
    sub.add_parser("dhcp-reservations", parents=[common],
                   help="Configured static DHCP reservations"
                   ).set_defaults(func=cmd_dhcp_reservations)
    sub.add_parser("traffic", parents=[common],
                   help="Per-client traffic + top talkers"
                   ).set_defaults(func=cmd_traffic)
    sub.add_parser("mlo-clients", parents=[common],
                   help="Per-band tagged client list (incl. deviceTag='mlo')"
                   ).set_defaults(func=cmd_mlo_clients)

    s_gs = sub.add_parser("game-stats", parents=[common],
                          help="Active games and per-device records (read-only)")
    s_gs.add_argument("--appid", type=int, default=None,
                      help="Drill into records for one game id")
    s_gs.set_defaults(func=cmd_game_stats)

    # --- escape hatch ---
    s_raw = sub.add_parser("raw", parents=[common],
                           help="Hit any admin endpoint directly")
    s_raw.add_argument("path", help="e.g. admin/wireless?form=twt")
    s_raw.add_argument("--data", default=None,
                       help="urlencoded body (default: operation=read)")
    s_raw.set_defaults(func=cmd_raw)

    # --- Wi-Fi ---
    s_wifi = sub.add_parser("wifi", parents=[common],
                            help="Toggle a Wi-Fi band on/off")
    s_wifi.add_argument("band", choices=sorted(_BAND_TO_CONNECTION.keys()))
    s_wifi.add_argument("state", choices=["on", "off"])
    s_wifi.set_defaults(func=cmd_wifi)

    s_twt = sub.add_parser("twt", parents=[common], help="Target Wake Time")
    s_twt.add_argument("state", nargs="?", choices=["on", "off"], default=None,
                       help="omit to read")
    s_twt.set_defaults(func=cmd_twt)

    s_ofdma = sub.add_parser("ofdma", parents=[common],
                             help="OFDMA / MU-MIMO setting")
    s_ofdma.add_argument("value", nargs="?",
                         choices=["all", "ofdma", "mu_mimo", "off"], default=None)
    s_ofdma.set_defaults(func=cmd_ofdma)

    s_mlo = sub.add_parser("mlo", parents=[common],
                           help="Multi-Link Operation host SSID")
    s_mlo.add_argument("state", nargs="?", choices=["on", "off"], default=None)
    s_mlo.set_defaults(func=cmd_mlo)

    s_sc = sub.add_parser("smart-connect", parents=[common],
                          help="Smart Connect (band steering)")
    s_sc.add_argument("state", nargs="?", choices=["on", "off"], default=None)
    s_sc.set_defaults(func=cmd_smart_connect)

    # --- backup / restore / reboot ---
    s_bk = sub.add_parser("backup", parents=[common],
                          help="Download full router config to .bin")
    s_bk.add_argument("--out", default=None,
                      help=f"output path (default {DEFAULT_BACKUP_DIR}/backup-Archer GE550-YYYY-MM-DD.bin)")
    s_bk.add_argument("--overwrite", action="store_true")
    s_bk.set_defaults(func=cmd_backup)

    s_rs = sub.add_parser("restore", parents=[common],
                          help="Upload backup .bin and reboot")
    s_rs.add_argument("file")
    s_rs.set_defaults(func=cmd_restore)

    sub.add_parser("reboot", parents=[common],
                   help="Reboot the router"
                   ).set_defaults(func=cmd_reboot)
    sub.add_parser("reboot-schedule", parents=[common],
                   help="Read current reboot schedule (write via `raw` for now)"
                   ).set_defaults(func=cmd_reboot_schedule)
    sub.add_parser("auto-upgrade", parents=[common],
                   help="Read auto-firmware-upgrade schedule"
                   ).set_defaults(func=cmd_auto_upgrade)
    sub.add_parser("led-schedule", parents=[common],
                   help="Read LED + LED night-mode schedule"
                   ).set_defaults(func=cmd_led_schedule)

    # --- USB / SMB / TM ---
    sub.add_parser("disk-list", parents=[common],
                   help="List USB disks + metadata"
                   ).set_defaults(func=cmd_disk_list)
    sub.add_parser("disk-scan", parents=[common],
                   help="Trigger USB disk rescan"
                   ).set_defaults(func=cmd_disk_scan)
    s_de = sub.add_parser("disk-eject", parents=[common],
                          help="Safely eject a USB disk by serial")
    s_de.add_argument("serial")
    s_de.set_defaults(func=cmd_disk_eject)

    sub.add_parser("share-config", parents=[common],
                   help="folder_sharing settings overview (SMB/DLNA/auth/media)"
                   ).set_defaults(func=cmd_share_config)
    s_st = sub.add_parser("share-tree", parents=[common],
                          help="List folder contents for a shared mount")
    s_st.add_argument("uuid")
    s_st.add_argument("path", nargs="?", default="/")
    s_st.set_defaults(func=cmd_share_tree)

    sub.add_parser("time-machine", parents=[common],
                   help="Time Machine settings + contents listing"
                   ).set_defaults(func=cmd_time_machine)

    # --- VPN ---
    sub.add_parser("vpn-status", parents=[common],
                   help="Full VPN status: server + client"
                   ).set_defaults(func=cmd_vpn_status)
    s_vs = sub.add_parser("vpn-server", parents=[common],
                          help="Toggle OpenVPN or PPTP server")
    s_vs.add_argument("kind", choices=["openvpn", "pptp"])
    s_vs.add_argument("state", choices=["on", "off"])
    s_vs.set_defaults(func=cmd_vpn_server)
    s_vc = sub.add_parser("vpn-client", parents=[common],
                          help="VPN client master switch")
    s_vc.add_argument("state", choices=["on", "off"])
    s_vc.set_defaults(func=cmd_vpn_client)
    s_vcs = sub.add_parser("vpn-client-server", parents=[common],
                           help="Activate a configured VPN client server by id")
    s_vcs.add_argument("server_id")
    s_vcs.add_argument("state", choices=["on", "off"])
    s_vcs.set_defaults(func=cmd_vpn_client_server)
    s_vca = sub.add_parser("vpn-client-allow", parents=[common],
                           help="Whitelist a device MAC for VPN client tunnel")
    s_vca.add_argument("mac")
    s_vca.add_argument("state", choices=["on", "off"])
    s_vca.set_defaults(func=cmd_vpn_client_allow)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s | %(message)s")
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
