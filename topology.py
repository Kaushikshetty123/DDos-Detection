#!/usr/bin/env python3
"""
SDN DDoS test topology - THE canonical 4-host topology.

    h1 = attacker   10.0.0.1
    h2 = VICTIM     10.0.0.2
    h3 = attacker   10.0.0.3
    h4 = attacker   10.0.0.4

All four hosts connect to a single OpenFlow 1.3 switch (s1).

If you have older topology files lying around (2-host or 3-host
versions), the distributed test fails because h4 is missing or not
reachable. RUN ONLY THIS FILE. The startup self-check below pings each
attacker -> victim and prints PASS/FAIL so a missing/unreachable h4 is
obvious instead of silently producing "almost no traffic".
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_network():

    net = Mininet(
        switch=OVSSwitch,
        link=TCLink,
        controller=RemoteController,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633,
    )

    print("\n========================================")
    print("   SDN DISTRIBUTED DDoS TOPOLOGY (4 hosts)")
    print("========================================\n")

    # Hosts. Fixed MACs make controller logs readable and MAC learning
    # deterministic (h1=..:01, h2=..:02, h3=..:03, h4=..:04).
    attacker1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    victim    = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    attacker2 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    attacker3 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

    # OVS switch on OpenFlow 1.3.
    switch = net.addSwitch("s1", protocols="OpenFlow13")

    # One link per host -> switch. h4's link is right here; if this file
    # is the one running, h4 is guaranteed connected.
    net.addLink(attacker1, switch)
    net.addLink(victim, switch)
    net.addLink(attacker2, switch)
    net.addLink(attacker3, switch)

    net.start()

    # --------------------------------------------------------------
    # CONTROLLER MUST BE RUNNING FIRST.
    # The Ryu controller installs every forwarding flow AND is the
    # detector. If it is not connected, nothing forwards reliably and
    # nothing is detected. Wait for s1 to connect before doing anything.
    # --------------------------------------------------------------
    print("\n--- Waiting for Ryu controller to connect ---")
    connected = net.waitConnected(timeout=10)

    if not connected:
        print("\n[ERROR] s1 did NOT connect to a controller at 127.0.0.1:6633.")
        print("        The Ryu controller is not running - that is why you saw")
        print("        'Unable to contact the remote controller' above, and why")
        print("        pingAll drops packets.")
        print()
        print("        Start the controller FIRST, in a separate terminal:")
        print("          source venv/bin/activate")
        print("          SDN_MODE=detect ryu-manager --ofp-tcp-listen-port 6633 "
              "ryu_controller.py")
        print("        Wait until it logs 'DETECTION MODE' and")
        print("        'Switch connected: DPID=...', THEN run this topology.")
        print()
        print("        Dropping into the CLI for inspection - forwarding and")
        print("        detection will NOT work until the controller is up.")
        CLI(net)
        net.stop()
        return

    print("[OK] Controller connected.")

    # --------------------------------------------------------------
    # WARM-UP + SELF-CHECK
    # pingAll converges ARP, installs forwarding flows, and teaches the
    # controller every host's MAC->IP (so the aggregate direction guard
    # recognises victim-bound traffic from ALL attackers, h4 included).
    # --------------------------------------------------------------
    print("\n--- Warming up (pingAll) ---")
    drop = net.pingAll()
    if drop != 0.0:
        # First pass can lose the very first packet of a pair while the
        # flow is being installed; a second pass should be clean.
        print("--- Re-checking (pingAll) ---")
        drop = net.pingAll()

    print("\n--- Attacker -> victim reachability self-check ---")
    all_ok = True
    for host in (attacker1, attacker2, attacker3):
        result = host.cmd("ping -c 1 -W 1 10.0.0.2")
        ok = "1 received" in result
        all_ok = all_ok and ok
        print("  {:>3} ({}) -> h2 : {}".format(
            host.name, host.IP(), "PASS" if ok else "FAIL - cannot reach victim!"
        ))

    print("\n========================================")
    print("Attacker : h1 - 10.0.0.1  (00:00:00:00:00:01)")
    print("VICTIM   : h2 - 10.0.0.2  (00:00:00:00:00:02)")
    print("Attacker : h3 - 10.0.0.3  (00:00:00:00:00:03)")
    print("Attacker : h4 - 10.0.0.4  (00:00:00:00:00:04)")
    print("Switch   : s1  (OpenFlow13)")
    print("========================================")

    if all_ok and drop == 0.0:
        print("\n[OK] All 4 hosts up and every attacker can reach h2.")
    else:
        print("\n[WARNING] Connectivity check did not fully pass.")
        print("          Fix reachability before running the DDoS test,")
        print("          otherwise an attacker will appear as ~0 traffic.")

    print("\nReady. Suggested tests (run from this mininet> prompt):")
    print("  NORMAL       : h1 ping -c 10 10.0.0.2")
    print("  SINGLE DoS   : h1 ping -f 10.0.0.2")
    print("  DISTRIBUTED  : h1 ping -f 10.0.0.2 > /dev/null 2>&1 &")
    print("                 h3 ping -f 10.0.0.2 > /dev/null 2>&1 &")
    print("                 h4 ping -f 10.0.0.2 > /dev/null 2>&1 &")
    print("                 (launch all three, then let them run ~20s)")
    print("  Stop floods  : sh pkill -f 'ping -f'")
    print()
    print()

    CLI(net)

    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_network()