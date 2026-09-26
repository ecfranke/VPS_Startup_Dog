#!/usr/bin/env python3
"""
ddns-cf — Cloudflare DDNS + network watchdog for Debian / Ubuntu VPS.

Features
  1. Cloudflare DDNS: keeps A (IPv4) and AAAA (IPv6) records in sync with the public IP.
  2. All credentials / settings are read from a .env file.
  3. Watchdog: detects network loss and recovers automatically, escalating:
       L1  DHCP renew        (networkctl renew / nmcli reapply / dhclient)
       L2  restart network   (netplan apply / systemd-networkd / NetworkManager / networking)
       L3  reboot            (optional, off by default)
  4. Designed to run as a systemd service (see ddns-cf.service / install.sh).

Pure Python 3 standard library (3.8+). No pip packages needed.

Usage
  ddns_cf.py run        # daemon: watchdog + periodic DDNS (default)
  ddns_cf.py ddns       # one-shot DDNS update, then exit
  ddns_cf.py check      # print config, detected network stack, connectivity, public IPs
  ddns_cf.py recover    # run the recovery sequence once (for testing, needs root)
Options
  --env PATH            # .env location (default: .env next to this script, then /opt/ddns-cf/.env)
"""

import argparse
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"
log = logging.getLogger("ddns-cf")

# ─────────────────────────────── .env handling ────────────────────────────────

DEFAULTS = {
    "CF_API_TOKEN": "",
    "CF_ZONE_ID": "",            # optional; looked up from the record name if empty
    "CF_RECORDS": "",            # comma separated FQDNs, e.g. home.example.com,vps.example.com
    "CF_ENABLE_IPV4": "true",
    "CF_ENABLE_IPV6": "true",
    "CF_CREATE_MISSING": "true", # create the record if it does not exist
    "CF_PROXIED": "false",       # only used when creating a record
    "CF_TTL": "60",              # only used when creating a record (1 = auto)
    "CF_API_BASE": "https://api.cloudflare.com/client/v4",
    "IPV4_SOURCES": "https://api.ipify.org,https://ipv4.icanhazip.com,https://1.1.1.1/cdn-cgi/trace",
    "IPV6_SOURCES": "https://api6.ipify.org,https://ipv6.icanhazip.com,https://[2606:4700:4700::1111]/cdn-cgi/trace",
    "DDNS_INTERVAL": "300",      # seconds between DDNS checks
    "DDNS_FORCE_SYNC": "3600",   # re-verify records with Cloudflare at least this often, even if IP unchanged
    "CHECK_INTERVAL": "30",      # seconds between connectivity checks
    "CHECK_TARGETS": "1.1.1.1,8.8.8.8,9.9.9.9",
    "CHECK_METHOD": "auto",      # auto | ping | tcp
    "CHECK_TCP_PORT": "443",
    "FAIL_THRESHOLD": "3",       # consecutive failed checks before recovery starts
    "NET_IFACE": "",             # interface to recover; auto-detected from default route if empty
    "RECOVERY_WAIT": "20",       # seconds to wait after each recovery step before re-checking
    "RECOVERY_COOLDOWN": "300",  # seconds between full recovery rounds
    "REBOOT_ON_FAILURE": "false",
    "REBOOT_AFTER_ROUNDS": "3",  # failed recovery rounds before reboot (if enabled)
    "BOOT_GRACE": "60",          # don't start recovery within N seconds of service start
    "HTTP_TIMEOUT": "15",
    "LOG_LEVEL": "INFO",
}


def load_env(path: str) -> Dict[str, str]:
    cfg = dict(DEFAULTS)
    if not os.path.isfile(path):
        raise SystemExit("config not found: %s  (copy .env.example to .env and edit it)" % path)
    with open(path, "r", encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                log.warning("%s:%d ignored (no '=')", path, n)
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            elif " #" in v:
                v = v.split(" #", 1)[0].rstrip()
            cfg[k] = v
    # real environment variables override the file (handy for testing)
    for k in list(cfg):
        if k in os.environ:
            cfg[k] = os.environ[k]
    return cfg


def b(cfg, k) -> bool:
    return str(cfg.get(k, "")).strip().lower() in ("1", "true", "yes", "on")


def i(cfg, k) -> int:
    try:
        return int(str(cfg[k]).strip())
    except (KeyError, ValueError):
        return int(DEFAULTS[k])


def lst(cfg, k) -> List[str]:
    return [x.strip() for x in str(cfg.get(k, "")).split(",") if x.strip()]


# ─────────────────────────────── HTTP helpers ─────────────────────────────────

class _ForceFamily:
    """Temporarily force socket.getaddrinfo to one address family (IPv4 or IPv6)."""

    def __init__(self, family):
        self.family = family
        self._orig = socket.getaddrinfo

    def __enter__(self):
        orig, fam = self._orig, self.family

        def patched(host, port, family=0, *a, **kw):
            return orig(host, port, fam, *a, **kw)

        socket.getaddrinfo = patched
        return self

    def __exit__(self, *exc):
        socket.getaddrinfo = self._orig


def http(method: str, url: str, timeout: int, headers=None, body=None) -> Tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "ddns-cf/%s" % VERSION)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _valid_ip(ip: str, family) -> bool:
    try:
        socket.inet_pton(family, ip)
        return True
    except (OSError, ValueError):
        return False


def public_ip(cfg, v6: bool) -> Optional[str]:
    family = socket.AF_INET6 if v6 else socket.AF_INET
    sources = lst(cfg, "IPV6_SOURCES" if v6 else "IPV4_SOURCES")
    for url in sources:
        try:
            with _ForceFamily(family):
                code, text = http("GET", url, i(cfg, "HTTP_TIMEOUT"))
            if code != 200:
                continue
            ip = text.strip()
            if "ip=" in text:  # cloudflare /cdn-cgi/trace format
                for line in text.splitlines():
                    if line.startswith("ip="):
                        ip = line[3:].strip()
            if _valid_ip(ip, family):
                return ip
        except Exception as e:  # noqa: BLE001
            log.debug("IP source %s failed: %s", url, e)
    return None


# ─────────────────────────────── Cloudflare ───────────────────────────────────

class CFError(Exception):
    pass


class Cloudflare:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["CF_API_BASE"].rstrip("/")
        self.timeout = i(cfg, "HTTP_TIMEOUT")
        self.headers = {"Authorization": "Bearer %s" % cfg["CF_API_TOKEN"]}
        self._zone_cache: Dict[str, str] = {}

    def _call(self, method, path, body=None):
        code, text = http(method, self.base + path, self.timeout, self.headers, body)
        try:
            js = json.loads(text)
        except ValueError:
            raise CFError("HTTP %s, non-JSON response" % code)
        if not js.get("success"):
            errs = "; ".join("%s: %s" % (e.get("code"), e.get("message")) for e in js.get("errors", []))
            raise CFError("HTTP %s %s" % (code, errs or text[:200]))
        return js["result"]

    def verify_token(self):
        return self._call("GET", "/user/tokens/verify")

    def zone_id(self, fqdn: str) -> str:
        if self.cfg.get("CF_ZONE_ID"):
            return self.cfg["CF_ZONE_ID"]
        labels = fqdn.rstrip(".").split(".")
        for n in range(len(labels) - 1):
            cand = ".".join(labels[n:])
            if cand in self._zone_cache:
                return self._zone_cache[cand]
            res = self._call("GET", "/zones?name=%s" % cand)
            if res:
                self._zone_cache[cand] = res[0]["id"]
                return res[0]["id"]
        raise CFError("no Cloudflare zone found for %s (set CF_ZONE_ID or give the token Zone:Read)" % fqdn)

    def sync(self, fqdn: str, rtype: str, ip: str) -> str:
        zid = self.zone_id(fqdn)
        recs = self._call("GET", "/zones/%s/dns_records?type=%s&name=%s" % (zid, rtype, fqdn))
        if not recs:
            if not b(self.cfg, "CF_CREATE_MISSING"):
                return "missing (CF_CREATE_MISSING=false)"
            self._call("POST", "/zones/%s/dns_records" % zid, {
                "type": rtype, "name": fqdn, "content": ip,
                "ttl": i(self.cfg, "CF_TTL"), "proxied": b(self.cfg, "CF_PROXIED"),
            })
            return "created -> %s" % ip
        rec = recs[0]
        if len(recs) > 1:
            log.warning("%s %s has %d records; only the first is managed", rtype, fqdn, len(recs))
        if rec.get("content") == ip:
            return "unchanged (%s)" % ip
        self._call("PATCH", "/zones/%s/dns_records/%s" % (zid, rec["id"]), {"content": ip})
        return "updated %s -> %s" % (rec.get("content"), ip)


class DDNS:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cf = Cloudflare(cfg)
        self.last_ips: Dict[str, Optional[str]] = {"A": None, "AAAA": None}
        self.last_full_sync = 0.0

    def run(self, force=False) -> bool:
        records = lst(self.cfg, "CF_RECORDS")
        wanted = []
        if b(self.cfg, "CF_ENABLE_IPV4"):
            wanted.append(("A", public_ip(self.cfg, False)))
        if b(self.cfg, "CF_ENABLE_IPV6"):
            wanted.append(("AAAA", public_ip(self.cfg, True)))

        stale = time.time() - self.last_full_sync > i(self.cfg, "DDNS_FORCE_SYNC")
        ok = True
        for rtype, ip in wanted:
            if not ip:
                log.info("DDNS %s: no public %s address detected, skipped", rtype,
                         "IPv6" if rtype == "AAAA" else "IPv4")
                continue
            if not force and not stale and ip == self.last_ips[rtype]:
                log.debug("DDNS %s: IP unchanged (%s)", rtype, ip)
                continue
            type_ok = True
            for fqdn in records:
                try:
                    log.info("DDNS %s %s: %s", rtype, fqdn, self.cf.sync(fqdn, rtype, ip))
                except Exception as e:  # noqa: BLE001
                    ok = type_ok = False
                    log.error("DDNS %s %s failed: %s", rtype, fqdn, e)
            if type_ok:
                self.last_ips[rtype] = ip
        if ok and (force or stale):
            self.last_full_sync = time.time()
        return ok


# ─────────────────────────────── Network watchdog ─────────────────────────────

def sh(cmd: List[str], timeout=60) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, universal_newlines=True)
        return p.returncode, p.stdout.strip()
    except FileNotFoundError:
        return 127, "not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def unit_active(name: str) -> bool:
    return sh(["systemctl", "is-active", "--quiet", name], 10)[0] == 0


def unit_exists(name: str) -> bool:
    code, out = sh(["systemctl", "list-unit-files", name, "--no-legend"], 10)
    return code == 0 and name in out


def default_iface() -> Optional[str]:
    for fam in ("-4", "-6"):
        code, out = sh(["ip", fam, "route", "show", "default"], 5)
        if code == 0:
            parts = out.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    # no default route (typical while offline): first UP non-loopback interface
    code, out = sh(["ip", "-o", "link", "show"], 5)
    for line in out.splitlines():
        name = line.split(":")[1].strip().split("@")[0] if ":" in line else ""
        if name and name != "lo" and not name.startswith(("docker", "veth", "br-", "virbr", "tun", "wg")):
            return name
    return None


def iface_is_dhcp_ifupdown(iface: str) -> bool:
    files = ["/etc/network/interfaces"]
    d = "/etc/network/interfaces.d"
    if os.path.isdir(d):
        files += [os.path.join(d, f) for f in sorted(os.listdir(d))]
    for fp in files:
        try:
            with open(fp) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 4 and p[0] == "iface" and p[1] == iface and p[3] == "dhcp":
                        return True
        except OSError:
            pass
    return False


def detect_stack() -> Dict[str, bool]:
    return {
        "netplan": shutil.which("netplan") is not None and os.path.isdir("/etc/netplan")
                   and any(f.endswith(".yaml") for f in os.listdir("/etc/netplan")),
        "networkd": unit_active("systemd-networkd"),
        "networkmanager": unit_active("NetworkManager"),
        "ifupdown": os.path.isfile("/etc/network/interfaces") and unit_exists("networking.service"),
        "dhclient": shutil.which("dhclient") is not None,
        "dhcpcd": shutil.which("dhcpcd") is not None,
    }


class Watchdog:
    def __init__(self, cfg):
        self.cfg = cfg
        self.fails = 0
        self.failed_rounds = 0
        self.last_recovery = 0.0
        self.started = time.time()
        m = cfg.get("CHECK_METHOD", "auto").lower()
        self.method = ("ping" if shutil.which("ping") else "tcp") if m == "auto" else m

    # ---- connectivity ----
    def _probe(self, target: str) -> bool:
        if self.method == "ping":
            fam = "-6" if ":" in target else "-4"
            return sh(["ping", fam, "-c", "1", "-W", "3", target], 8)[0] == 0
        try:
            fam = socket.AF_INET6 if ":" in target else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                s.connect((target, i(self.cfg, "CHECK_TCP_PORT")))
            return True
        except OSError:
            return False

    def online(self) -> bool:
        return any(self._probe(t) for t in lst(self.cfg, "CHECK_TARGETS"))

    # ---- recovery steps ----
    def _iface(self) -> Optional[str]:
        return self.cfg.get("NET_IFACE") or default_iface()

    def step_dhcp(self, st, iface) -> bool:
        if not iface:
            log.warning("L1: no interface detected, skip DHCP renew")
            return False
        if st["networkd"]:
            log.warning("L1: networkctl renew %s", iface)
            sh(["networkctl", "renew", iface], 30)
            return True
        if st["networkmanager"] and shutil.which("nmcli"):
            log.warning("L1: nmcli device reapply %s", iface)
            code, _ = sh(["nmcli", "device", "reapply", iface], 30)
            if code != 0:
                sh(["nmcli", "device", "connect", iface], 30)
            return True
        if st["dhclient"] and (not st["ifupdown"] or iface_is_dhcp_ifupdown(iface)):
            log.warning("L1: dhclient -r %s && dhclient %s", iface, iface)
            sh(["dhclient", "-r", iface], 30)
            sh(["dhclient", "-1", iface], 60)
            return True
        if st["dhcpcd"]:
            log.warning("L1: dhcpcd -n %s", iface)
            sh(["dhcpcd", "-n", iface], 30)
            return True
        log.info("L1: interface %s is not DHCP-managed (static?), skip", iface)
        return False

    def step_restart(self, st, iface) -> bool:
        did = False
        if st["netplan"]:
            log.warning("L2: netplan apply")
            sh(["netplan", "apply"], 90)
            did = True
        elif st["networkd"]:
            log.warning("L2: systemctl restart systemd-networkd")
            sh(["systemctl", "restart", "systemd-networkd"], 90)
            did = True
        if st["networkmanager"]:
            log.warning("L2: systemctl restart NetworkManager")
            sh(["systemctl", "restart", "NetworkManager"], 90)
            did = True
        if st["ifupdown"]:
            log.warning("L2: systemctl restart networking")
            code, out = sh(["systemctl", "restart", "networking"], 120)
            if code != 0 and iface:
                log.warning("L2: restart networking failed (%s); ifdown/ifup %s", out[-200:], iface)
                sh(["ifdown", "--force", iface], 60)
                sh(["ifup", iface], 90)
            did = True
        if not did and iface:
            log.warning("L2: no known network manager; ip link down/up %s", iface)
            sh(["ip", "link", "set", iface, "down"], 10)
            time.sleep(2)
            sh(["ip", "link", "set", iface, "up"], 10)
            did = True
        return did

    def recover(self) -> bool:
        st = detect_stack()
        iface = self._iface()
        log.warning("network DOWN — starting recovery (iface=%s, stack=%s)",
                    iface, ",".join(k for k, v in st.items() if v) or "unknown")
        wait = i(self.cfg, "RECOVERY_WAIT")
        for name, step in (("DHCP renew", self.step_dhcp), ("network restart", self.step_restart)):
            if step(st, iface):
                time.sleep(wait)
                if self.online():
                    log.warning("network RESTORED after %s", name)
                    return True
        self.failed_rounds += 1
        log.error("recovery round failed (%d consecutive)", self.failed_rounds)
        if b(self.cfg, "REBOOT_ON_FAILURE") and self.failed_rounds >= i(self.cfg, "REBOOT_AFTER_ROUNDS"):
            log.critical("L3: rebooting after %d failed recovery rounds", self.failed_rounds)
            sh(["systemctl", "reboot"], 30)
        return False

    def tick(self) -> Optional[bool]:
        """Returns True if the network was just restored, else None."""
        if self.online():
            if self.fails:
                log.info("network OK again after %d failed checks", self.fails)
            self.fails = 0
            self.failed_rounds = 0
            return None
        self.fails += 1
        log.warning("connectivity check failed (%d/%d)", self.fails, i(self.cfg, "FAIL_THRESHOLD"))
        if self.fails < i(self.cfg, "FAIL_THRESHOLD"):
            return None
        now = time.time()
        if now - self.started < i(self.cfg, "BOOT_GRACE"):
            log.info("within boot grace period, not recovering yet")
            return None
        if now - self.last_recovery < i(self.cfg, "RECOVERY_COOLDOWN"):
            return None
        self.last_recovery = now
        if self.recover():
            self.fails = 0
            self.failed_rounds = 0
            return True
        return None


# ─────────────────────────────── main ─────────────────────────────────────────

_stop = False


def _on_signal(signum, _frame):
    global _stop
    log.info("signal %d received, stopping", signum)
    _stop = True


def validate(cfg, need_cf=True):
    errs = []
    if need_cf:
        if not cfg.get("CF_API_TOKEN") or cfg["CF_API_TOKEN"].startswith("your_"):
            errs.append("CF_API_TOKEN is not set")
        if not lst(cfg, "CF_RECORDS") or any("example.com" in r for r in lst(cfg, "CF_RECORDS")):
            errs.append("CF_RECORDS is not set")
    if errs:
        raise SystemExit("config error: " + "; ".join(errs))


def cmd_run(cfg):
    validate(cfg)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    ddns, wd = DDNS(cfg), Watchdog(cfg)
    log.info("ddns-cf %s started: records=%s, check every %ss (%s), DDNS every %ss",
             VERSION, ",".join(lst(cfg, "CF_RECORDS")), cfg["CHECK_INTERVAL"], wd.method, cfg["DDNS_INTERVAL"])
    next_ddns = 0.0
    while not _stop:
        restored = wd.tick()
        now = time.time()
        if restored or (now >= next_ddns and wd.fails == 0):
            try:
                ddns.run(force=bool(restored) or next_ddns == 0.0)
            except Exception as e:  # noqa: BLE001
                log.error("DDNS error: %s", e)
            next_ddns = now + i(cfg, "DDNS_INTERVAL")
        for _ in range(i(cfg, "CHECK_INTERVAL")):
            if _stop:
                break
            time.sleep(1)
    log.info("stopped")


def cmd_ddns(cfg):
    validate(cfg)
    sys.exit(0 if DDNS(cfg).run(force=True) else 1)


def cmd_check(cfg):
    print("ddns-cf", VERSION)
    print("records     :", ", ".join(lst(cfg, "CF_RECORDS")) or "(none)")
    print("token       :", ("set (%d chars)" % len(cfg["CF_API_TOKEN"])) if cfg.get("CF_API_TOKEN") else "NOT SET")
    if cfg.get("CF_API_TOKEN"):
        try:
            r = Cloudflare(cfg).verify_token()
            print("token check :", r.get("status"))
        except Exception as e:  # noqa: BLE001
            print("token check : FAILED -", e)
    st = detect_stack()
    print("interface   :", cfg.get("NET_IFACE") or default_iface(), "(configured)" if cfg.get("NET_IFACE") else "(auto)")
    print("net stack   :", ", ".join(k for k, v in st.items() if v) or "unknown")
    wd = Watchdog(cfg)
    print("check method:", wd.method)
    print("online      :", wd.online())
    print("public IPv4 :", public_ip(cfg, False) if b(cfg, "CF_ENABLE_IPV4") else "(disabled)")
    print("public IPv6 :", public_ip(cfg, True) if b(cfg, "CF_ENABLE_IPV6") else "(disabled)")


def cmd_recover(cfg):
    if os.geteuid() != 0:
        raise SystemExit("recover needs root")
    wd = Watchdog(cfg)
    sys.exit(0 if wd.recover() else 1)


def main():
    ap = argparse.ArgumentParser(description="Cloudflare DDNS + network watchdog")
    ap.add_argument("command", nargs="?", default="run", choices=["run", "ddns", "check", "recover"])
    ap.add_argument("--env", help="path to .env")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    here = os.path.dirname(os.path.realpath(__file__))
    env_path = a.env or next((p for p in (os.path.join(here, ".env"), "/opt/ddns-cf/.env") if os.path.isfile(p)),
                             os.path.join(here, ".env"))
    logging.basicConfig(format="%(levelname)s %(message)s" if os.environ.get("INVOCATION_ID")
                        else "%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    cfg = load_env(env_path)
    log.setLevel("DEBUG" if a.verbose else cfg.get("LOG_LEVEL", "INFO").upper())
    {"run": cmd_run, "ddns": cmd_ddns, "check": cmd_check, "recover": cmd_recover}[a.command](cfg)


if __name__ == "__main__":
    main()
