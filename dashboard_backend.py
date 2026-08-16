#!/usr/bin/env python3
"""
Dashboard backend for the SDN DDoS project (multi-host edition).

Builds a Mininet star topology of up to SDN_MAX_HOSTS hosts (1 victim +
the rest usable as attackers / normal users), serves the web dashboard,
and generates REAL traffic:

  * Normal users continuously ping the victim at a low rate.
  * Attackers flood the victim on demand (DoS = 1 source, DDoS = many),
    on TOP of the normal traffic (they run simultaneously).
  * When the Ryu controller detects + blocks attackers, the switch drops
    their traffic while normal-user traffic keeps reaching the victim.

Detection/mitigation is NOT reimplemented here. All statistics come from
ryu_controller.py's own dashboard_state.json. This process only:
  * generates traffic from the real Mininet hosts,
  * tags each real per-source stat with the role it assigned (attacker /
    normal / victim) so the UI can separate them, and
  * serves the dashboard + a small JSON API.

Run (root, AFTER Ryu is up):  sudo python3 dashboard_backend.py
Optional:  SDN_MAX_HOSTS=30 sudo -E python3 dashboard_backend.py
"""

import json
import os
import shlex
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(BASE_DIR, "index.html")
STATE_FILE = os.path.join(BASE_DIR, "dashboard_state.json")
CONTROL_FILE = os.path.join(BASE_DIR, "dashboard_control.json")

HTTP_PORT = 8081

# Physical host pool cap. The UI accepts up to 100 hosts, but we only
# build this many real Mininet hosts so the machine stays responsive.
# Override with SDN_MAX_HOSTS (hard-clamped to [4, 100]).
HARD_MAX = 100
DEFAULT_MAX = 20
try:
    MAX_HOSTS = int(os.environ.get("SDN_MAX_HOSTS", DEFAULT_MAX))
except ValueError:
    MAX_HOSTS = DEFAULT_MAX
MAX_HOSTS = max(4, min(HARD_MAX, MAX_HOSTS))

SUBNET = "10.0.0"          # host i -> 10.0.0.i
NORMAL_INTERVAL = "1"      # ping -i 1  => ~1 pkt/s per normal user
DEFAULT_VICTIM = "h2"      # matches controller's default VICTIM_IP

# ---- runtime state (guarded by LOCK) ----
NET = None
HOSTS = {}                 # name -> Mininet host
IP_OF = {}                 # name -> ip
MAC_OF = {}                # name -> mac
POOL = []                  # ordered host names
NORMAL_PROCS = {}          # name -> Popen
ATTACK_PROCS = {}          # name -> Popen
ROLE_MAP = {}              # mac -> "attacker"|"normal"|"victim"|"idle"
ROLE_TOTALS = {"attacker": {"packets": 0, "bytes": 0},
               "normal":   {"packets": 0, "bytes": 0}}
LAST_TS = 0.0
LOCK = threading.Lock()

CONFIG = {
    "num_attackers": 3,
    "num_normal": 3,
    "victim": DEFAULT_VICTIM,
    "attack_type": "ddos",       # dos | ddos
    "pkt_rate_limit": 300.0,
    "byte_rate_limit": 300000.0,
    "attack_running": False,
    "normal_running": False,
    "max_hosts": MAX_HOSTS,
}


def ip_of_name(name):
    return IP_OF.get(name, "")


def victim_ip():
    return ip_of_name(CONFIG["victim"])


# ======================================================================
# ROLE ASSIGNMENT
# ======================================================================
def assign_roles():
    """Map hosts to roles from the current counts + victim. Caller holds LOCK."""
    victim = CONFIG["victim"] if CONFIG["victim"] in POOL else POOL[1]
    CONFIG["victim"] = victim
    others = [n for n in POOL if n != victim]

    na = max(0, min(CONFIG["num_attackers"], len(others)))
    nn = max(0, min(CONFIG["num_normal"], len(others) - na))

    attackers = others[:na]
    normals = others[na:na + nn]

    roles = {victim: "victim"}
    for n in attackers:
        roles[n] = "attacker"
    for n in normals:
        roles[n] = "normal"
    for n in POOL:
        roles.setdefault(n, "idle")

    ROLE_MAP.clear()
    for name, role in roles.items():
        ROLE_MAP[MAC_OF[name]] = role

    # Report the effective (possibly capped) counts back to the UI.
    CONFIG["num_attackers"] = na
    CONFIG["num_normal"] = nn
    return attackers, normals, victim


def roles_list(blocked_ips):
    """List of every pool host with role + blocked flag (for the UI/viz)."""
    out = []
    for name in POOL:
        mac = MAC_OF[name]
        out.append({
            "name": name,
            "ip": IP_OF[name],
            "role": ROLE_MAP.get(mac, "idle"),
            "blocked": IP_OF[name] in blocked_ips,
        })
    return out


# ======================================================================
# TRAFFIC CONTROL
# ======================================================================
def _write_control_file():
    try:
        with open(CONTROL_FILE, "w") as f:
            json.dump({
                "pkt_rate_limit": CONFIG["pkt_rate_limit"],
                "byte_rate_limit": CONFIG["byte_rate_limit"],
                "victim_ip": victim_ip(),
            }, f)
    except Exception as e:
        print("[backend] control write error:", e)


def _launch(name, cmd):
    h = HOSTS.get(name)
    if h is None:
        return None
    return h.popen(shlex.split(cmd),
                   stdout=open(os.devnull, "w"),
                   stderr=open(os.devnull, "w"))


def _kill(procs):
    for name, proc in list(procs.items()):
        try:
            proc.terminate()
        except Exception:
            pass
    procs.clear()


def start_normal_locked(normals):
    # Stop normal traffic from hosts that are no longer normal users.
    for name in list(NORMAL_PROCS):
        if name not in normals:
            try:
                NORMAL_PROCS[name].terminate()
            except Exception:
                pass
            del NORMAL_PROCS[name]
    vip = victim_ip()
    for name in normals:
        if name in NORMAL_PROCS:
            continue
        p = _launch(name, "ping -i %s %s" % (NORMAL_INTERVAL, vip))
        if p:
            NORMAL_PROCS[name] = p
    CONFIG["normal_running"] = len(NORMAL_PROCS) > 0


def stop_normal_locked():
    _kill(NORMAL_PROCS)
    for name in POOL:
        h = HOSTS.get(name)
        if h:
            try:
                h.cmd("pkill -f 'ping -i' 2>/dev/null")
            except Exception:
                pass
    CONFIG["normal_running"] = False


def start_attack_locked(attackers):
    _kill(ATTACK_PROCS)
    if CONFIG["attack_type"] == "dos":
        flood_hosts = attackers[:1]
    else:  # ddos
        flood_hosts = attackers
    vip = victim_ip()
    launched = []
    for name in flood_hosts:
        p = _launch(name, "ping -f %s" % vip)
        if p:
            ATTACK_PROCS[name] = p
            launched.append(name)
    CONFIG["attack_running"] = len(ATTACK_PROCS) > 0
    return launched


def stop_attack_locked():
    _kill(ATTACK_PROCS)
    for name in POOL:
        h = HOSTS.get(name)
        if h:
            try:
                h.cmd("pkill -f 'ping -f' 2>/dev/null")
            except Exception:
                pass
    CONFIG["attack_running"] = False


# ======================================================================
# BACKGROUND READER  (accumulate per-role totals from REAL controller data)
# ======================================================================
def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def role_reader():
    global LAST_TS
    while True:
        st = _load_state()
        if st:
            ts = st.get("timestamp", 0.0)
            if ts > LAST_TS:
                with LOCK:
                    for s in st.get("sources", []):
                        role = ROLE_MAP.get(s.get("mac"), "idle")
                        if role in ROLE_TOTALS:
                            ROLE_TOTALS[role]["packets"] += s.get("packets", 0)
                            ROLE_TOTALS[role]["bytes"] += s.get("bytes", 0)
                    LAST_TS = ts
        time.sleep(1.0)


def build_role_summary(state):
    """Group the controller's real per-source rates by assigned role."""
    cur = {
        "attacker": {"pkt_rate": 0.0, "byte_rate": 0.0, "count": 0, "blocked": 0},
        "normal":   {"pkt_rate": 0.0, "byte_rate": 0.0, "count": 0, "blocked": 0},
    }
    for s in state.get("sources", []):
        role = ROLE_MAP.get(s.get("mac"), "idle")
        if role in cur:
            cur[role]["pkt_rate"] += s.get("pkt_rate", 0.0)
            cur[role]["byte_rate"] += s.get("byte_rate", 0.0)
            cur[role]["count"] += 1
            if s.get("blocked"):
                cur[role]["blocked"] += 1
    with LOCK:
        cur["attacker"]["total_packets"] = ROLE_TOTALS["attacker"]["packets"]
        cur["attacker"]["total_bytes"] = ROLE_TOTALS["attacker"]["bytes"]
        cur["normal"]["total_packets"] = ROLE_TOTALS["normal"]["packets"]
        cur["normal"]["total_bytes"] = ROLE_TOTALS["normal"]["bytes"]
    cur["total"] = {
        "pkt_rate": round(cur["attacker"]["pkt_rate"] + cur["normal"]["pkt_rate"], 2),
        "byte_rate": round(cur["attacker"]["byte_rate"] + cur["normal"]["byte_rate"], 2),
    }
    for k in ("attacker", "normal"):
        cur[k]["pkt_rate"] = round(cur[k]["pkt_rate"], 2)
        cur[k]["byte_rate"] = round(cur[k]["byte_rate"], 2)
    return cur


# ======================================================================
# HTTP API
# ======================================================================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n).decode()) if n > 0 else {}
        except Exception:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_index()
            return
        if self.path.startswith("/api/stats"):
            state = _load_state() or {}
            blocked_ips = {b.get("ip") for b in state.get("blocked", [])}
            self._json({
                "connected": bool(state),
                "config": CONFIG,
                "hosts": roles_list(blocked_ips),
                "roles": build_role_summary(state),
                "state": state,
            })
            return
        if self.path.startswith("/api/config"):
            self._json({"config": CONFIG, "pool": POOL,
                        "max_hosts": MAX_HOSTS,
                        "ips": IP_OF})
            return
        self.send_error(404)

    def do_POST(self):
        if self.path.startswith("/api/config"):
            b = self._body()
            with LOCK:
                for k in ("num_attackers", "num_normal"):
                    if isinstance(b.get(k), (int, float)):
                        CONFIG[k] = max(0, int(b[k]))
                if b.get("victim") in POOL:
                    CONFIG["victim"] = b["victim"]
                if b.get("attack_type") in ("dos", "ddos"):
                    CONFIG["attack_type"] = b["attack_type"]
                for k in ("pkt_rate_limit", "byte_rate_limit"):
                    v = b.get(k)
                    if isinstance(v, (int, float)) and v > 0:
                        CONFIG[k] = float(v)
                attackers, normals, victim = assign_roles()
                _write_control_file()
                # Applying config re-scopes normal traffic to the new set.
                start_normal_locked(normals)
                # An in-flight attack is stopped when roles change.
                stop_attack_locked()
            self._json({"ok": True, "config": CONFIG})
            return

        if self.path.startswith("/api/normal/start"):
            with LOCK:
                attackers, normals, _ = assign_roles()
                start_normal_locked(normals)
            self._json({"ok": True, "config": CONFIG})
            return
        if self.path.startswith("/api/normal/stop"):
            with LOCK:
                stop_normal_locked()
            self._json({"ok": True, "config": CONFIG})
            return

        if self.path.startswith("/api/attack/start"):
            with LOCK:
                attackers, normals, _ = assign_roles()
                if CONFIG["attack_type"] == "ddos" and len(attackers) < 2:
                    self._json({"ok": False,
                                "message": "DDoS needs >= 2 attackers.",
                                "config": CONFIG})
                    return
                if not attackers:
                    self._json({"ok": False,
                                "message": "No attackers selected.",
                                "config": CONFIG})
                    return
                launched = start_attack_locked(attackers)
            self._json({"ok": True,
                        "message": "%s started from %s" % (
                            CONFIG["attack_type"].upper(), ", ".join(launched)),
                        "config": CONFIG})
            return
        if self.path.startswith("/api/attack/stop"):
            with LOCK:
                stop_attack_locked()
            self._json({"ok": True, "message": "Attack stopped.",
                        "config": CONFIG})
            return
        if self.path.startswith("/api/stop_all"):
            with LOCK:
                stop_attack_locked()
                stop_normal_locked()
            self._json({"ok": True, "message": "All traffic stopped.",
                        "config": CONFIG})
            return
        self.send_error(404)

    def _serve_index(self):
        try:
            with open(INDEX_FILE, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_error(404, "index.html not found in %s" % BASE_DIR)


def start_http_server():
    srv = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    print("[backend] Dashboard on http://localhost:%d" % HTTP_PORT)
    srv.serve_forever()


# ======================================================================
# MININET
# ======================================================================
def build_network():
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=RemoteController)
    net.addController("c0", controller=RemoteController,
                      ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    print("[backend] Building %d hosts (cap SDN_MAX_HOSTS=%d)..."
          % (MAX_HOSTS, MAX_HOSTS))
    for i in range(1, MAX_HOSTS + 1):
        name = "h%d" % i
        ip = "%s.%d" % (SUBNET, i)
        mac = "00:00:00:00:00:%02x" % i
        host = net.addHost(name, ip="%s/24" % ip, mac=mac)
        net.addLink(host, s1)
        HOSTS[name] = host
        IP_OF[name] = ip
        MAC_OF[name] = mac
        POOL.append(name)

    net.start()

    print("[backend] Waiting for Ryu controller...")
    if not net.waitConnected(timeout=15):
        print("[backend] WARNING: controller not connected. Start Ryu first:")
        print("          SDN_MODE=detect ryu-manager --ofp-tcp-listen-port "
              "6633 ryu_controller.py")

    # Cheap O(n) warm-up: every host pings the victim once so the
    # controller learns all MAC->IP mappings and installs victim-bound
    # flows (full pingAll would be O(n^2) and slow for many hosts).
    vic = CONFIG["victim"] if CONFIG["victim"] in POOL else "h2"
    vip = IP_OF.get(vic, "%s.2" % SUBNET)
    print("[backend] Warming up ARP/flows toward victim %s..." % vip)
    for name in POOL:
        if name == vic:
            continue
        HOSTS[name].cmd("ping -c 1 -W 1 %s >/dev/null 2>&1" % vip)
    print("[backend] Warm-up done.")
    return net


def main():
    global NET
    setLogLevel("info")

    NET = build_network()
    with LOCK:
        assign_roles()
        _write_control_file()

    threading.Thread(target=role_reader, daemon=True).start()
    threading.Thread(target=start_http_server, daemon=True).start()

    print("[backend] Ready with %d hosts. Open http://localhost:%d"
          % (MAX_HOSTS, HTTP_PORT))
    print("[backend] Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[backend] Shutting down...")
    finally:
        try:
            with LOCK:
                stop_attack_locked()
                stop_normal_locked()
        except Exception:
            pass
        if NET is not None:
            NET.stop()


if __name__ == "__main__":
    main()