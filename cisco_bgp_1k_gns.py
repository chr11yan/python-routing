#!/usr/bin/env python3
"""
bgp_1000_routes.py
════════════════════════════════════════════════════════════════════
Generates 1000 BGP routes between two Cisco IOS routers.

Topology:
                      eBGP Session
  ┌──────────────┐   192.168.100.0/30   ┌──────────────┐
  │   Router 1   │◄───────────────────►│   Router 2   │
  │   AS 65001   │  .1            .2   │   AS 65002   │
  │              │                     │              │
  │ 1000 static  │                     │ receives all │
  │ routes       │                     │ 1000 routes  │
  │ redistributed│                     │ via BGP      │
  │ into BGP     │                     │              │
  └──────────────┘                     └──────────────┘

Router 1:
  - BGP AS:          65001
  - BGP peer IP:     192.168.100.2 (Router 2)
  - Loopback0:       1.1.1.1/32
  - 1000 static routes: 10.0.0.0/24 → 10.3.231.255/24
  - Redistributes static routes into BGP

Router 2:
  - BGP AS:          65002
  - BGP peer IP:     192.168.100.1 (Router 1)
  - Loopback0:       2.2.2.2/32
  - Receives all 1000 routes via eBGP

Requirements:
  pip install netmiko

Usage:
  1. Edit ROUTER1 and ROUTER2 device dictionaries below
  2. Run: python bgp_1000_routes.py
  3. Script configures both routers automatically
  4. Verification output shown at end

════════════════════════════════════════════════════════════════════
"""

import sys
import time
import ipaddress
import logging
from datetime import datetime
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)

# ─────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            f"bgp_routes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        ),
    ],
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# DEVICE CONFIGURATION — Edit these for your environment
# ─────────────────────────────────────────────────────────────────
ROUTER1 = {
    # Connection settings
    "host":         "192.168.1.2",   # Router 1 management IP
    "port":         22,                  # 22=SSH, 23=Telnet
    "device_type":  "cisco_ios",         # cisco_ios or cisco_ios_telnet
    "username":     "admin",
    "password":     "cisco",
    "secret":       "lab",          # Enable secret
    "timeout":      160,
    "auth_timeout": 30,
    # BGP settings
    "bgp_as":       65001,
    "bgp_peer_ip":  "192.168.100.2",
    "bgp_peer_as":  65002,
    "loopback_ip":  "1.1.1.1",
    "link_ip":      "192.168.100.1",
    "link_mask":    "255.255.255.252",
    "hostname":     "R1",
}

ROUTER2 = {
    # Connection settings
    "host":         "192.168.18.2",   # Router 2 management IP
    "port":         22,
    "device_type":  "cisco_ios",
    "username":     "admin",
    "password":     "cisco",
    "secret":       "lab",
    "timeout":      160,
    "auth_timeout": 30,
    # BGP settings
    "bgp_as":       65002,
    "bgp_peer_ip":  "192.168.100.1",
    "bgp_peer_as":  65001,
    "loopback_ip":  "2.2.2.2",
    "link_ip":      "192.168.100.2",
    "link_mask":    "255.255.255.252",
    "hostname":     "R2",
}

# ─────────────────────────────────────────────────────────────────
# ROUTE GENERATION SETTINGS
# ─────────────────────────────────────────────────────────────────
ROUTE_CONFIG = {
    "count":        1000,          # Number of routes to generate
    "start_network":"10.0.0.0",    # Starting network address
    "prefix_len":   24,            # Prefix length for each route
    "next_hop":     "Null0",       # Next hop for static routes
    "batch_size":   50,            # Routes per config batch (avoid timeout)
}


# ─────────────────────────────────────────────────────────────────
# ROUTE GENERATOR
# ─────────────────────────────────────────────────────────────────
def generate_routes(start_network, prefix_len, count):
    """
    Generate a list of sequential network prefixes.

    Starting from start_network, increments the network
    address to generate 'count' unique /prefix_len networks.

    Example:
        10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24 ... 10.3.231.255/24
    """
    routes = []
    network = ipaddress.IPv4Network(f"{start_network}/{prefix_len}", strict=False)

    for i in range(count):
        routes.append(str(network.network_address))
        # Increment to next network
        next_addr = int(network.network_address) + (2 ** (32 - prefix_len))
        network = ipaddress.IPv4Network(
            f"{ipaddress.IPv4Address(next_addr)}/{prefix_len}",
            strict=False,
        )

    log.info("Generated %d routes from %s/%d to %s/%d",
             count,
             routes[0], prefix_len,
             routes[-1], prefix_len)
    return routes


# ─────────────────────────────────────────────────────────────────
# CONNECTION HELPERS
# ─────────────────────────────────────────────────────────────────
def connect_router(device, label):
    """Connect to router and enter privileged mode."""
    log.info("Connecting to %s (%s)...", label, device["host"])
    try:
        conn = ConnectHandler(**{
            k: v for k, v in device.items()
            if k not in ("bgp_as", "bgp_peer_ip", "bgp_peer_as",
                         "loopback_ip", "link_ip", "link_mask",
                         "hostname", "bgp_peer_as")
        })
        conn.enable()
        log.info("   Connected to %s", label)
        return conn
    except NetmikoTimeoutException:
        log.error("    Timeout connecting to %s — check IP/port", label)
        sys.exit(1)
    except NetmikoAuthenticationException:
        log.error("    Auth failed on %s — check credentials", label)
        sys.exit(1)
    except Exception as e:
        log.error("    Failed to connect to %s: %s", label, str(e))
        sys.exit(1)


def send_config_batch(conn, commands, label, batch_desc):
    """Send a batch of config commands with error handling."""
    try:
        output = conn.send_config_set(
            commands,
            read_timeout=280,
            cmd_verify=False,
        )
        # Check for common errors
        if "invalid input" in output.lower():
            log.warning("  Invalid input detected in %s — %s",
                        label, batch_desc)
            log.warning("  Output: %s", output[:200])
        return output
    except Exception as e:
        log.error("  ❌  Config error on %s (%s): %s", label, batch_desc, str(e))
        return ""


def send_command(conn, command, read_timeout=30):
    """Send show command and return output."""
    try:
        return conn.send_command(command, read_timeout=read_timeout)
    except Exception as e:
        log.error("   Command error: %s", str(e))
        return ""


# ─────────────────────────────────────────────────────────────────
# ROUTER 1 CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def configure_router1_base(conn, device):
    """Configure Router 1 base settings — hostname, interfaces, BGP."""
    log.info("\n" + "-" * 50)
    log.info("Configuring Router 1 base settings...")
    log.info("-" * 50)

    commands = [
        # Hostname
        f"hostname {device['hostname']}",

        # Loopback interface
        "interface Loopback0",
        f"ip address {device['loopback_ip']} 255.255.255.255",
        "no shutdown",
        "exit",

        # BGP link interface
        "interface GigabitEthernet1/0",
        f"ip address {device['link_ip']} {device['link_mask']}",
        "no shutdown",
        "no ip redirects",
        "no ip proxy-arp",
        "exit",

        # BGP process
        f"router bgp {device['bgp_as']}",
        f"bgp router-id {device['loopback_ip']}",
        "bgp log-neighbor-changes",
        "no auto-summary",
        "no synchronization",

        # eBGP neighbor (Router 2)
        f"neighbor {device['bgp_peer_ip']} remote-as {device['bgp_peer_as']}",
        f"neighbor {device['bgp_peer_ip']} description 'eBGP-to-R2'",
        f"neighbor {device['bgp_peer_ip']} send-community",

        # Address family
        "address-family ipv4",
        f"neighbor {device['bgp_peer_ip']} activate",

        # Redistribute static routes into BGP
        "redistribute static metric 100",
        "exit-address-family",
        "exit",
    ]

    output = send_config_batch(conn, commands, "R1", "base config")
    log.info("   Router 1 base configuration complete")
    return output


def configure_router1_static_routes(conn, routes, prefix_len, next_hop):
    """
    Configure 1000 static routes on Router 1 in batches.
    Batching prevents timeout on large config pushes.
    """
    log.info("\n" + "-" * 50)
    log.info("Configuring %d static routes on Router 1...", len(routes))
    log.info("-" * 50)

    batch_size = ROUTE_CONFIG["batch_size"]
    total_batches = (len(routes) + batch_size - 1) // batch_size
    mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)

    for batch_num in range(total_batches):
        start_idx = batch_num * batch_size
        end_idx = min(start_idx + batch_size, len(routes))
        batch = routes[start_idx:end_idx]

        # Build static route commands for this batch
        commands = []
        for network in batch:
            commands.append(
                f"ip route {network} {mask} {next_hop}"
            )

        output = send_config_batch(
            conn, commands, "R1",
            f"static routes batch {batch_num + 1}/{total_batches} "
            f"(routes {start_idx + 1}-{end_idx})"
        )

        # Progress update every 5 batches
        if (batch_num + 1) % 5 == 0 or batch_num == total_batches - 1:
            log.info(
                "  Progress: %d/%d routes configured (%.1f%%)",
                end_idx, len(routes),
                (end_idx / len(routes)) * 100,
            )

    log.info("   All %d static routes configured on Router 1", len(routes))


# ─────────────────────────────────────────────────────────────────
# ROUTER 2 CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def configure_router2(conn, device):
    """Configure Router 2 — base settings and BGP peer."""
    log.info("\n" + "-" * 50)
    log.info("Configuring Router 2...")
    log.info("-" * 50)
    commands1 = [
        f"hostname {device['hostname']}",

        # Loopback interface
        "interface Loopback0",
        f"ip address {device['loopback_ip']} 255.255.255.255",
        "no shutdown",
        "exit",
    ]

    commands2 = [  # Hostname
        f"hostname {device['hostname']}",

        # Loopback interface
        "interface Loopback0",
        f"ip address {device['loopback_ip']} 255.255.255.255",
        "no shutdown",
        "exit",

        # BGP link interface
        "interface GigabitEthernet1/0",
        f"ip address {device['link_ip']} {device['link_mask']}",
        "no shutdown",
        "no ip redirects",
        "no ip proxy-arp",
        "exit",

        # BGP process
        f"router bgp {device['bgp_as']}",
        f"bgp router-id {device['loopback_ip']}",
        "bgp log-neighbor-changes",
        "no auto-summary",
        "no synchronization",
    ]

    commands = [
        # Hostname
        f"hostname {device['hostname']}",

        # Loopback interface
        "interface Loopback0",
        f"ip address {device['loopback_ip']} 255.255.255.255",
        "no shutdown",
        "exit",

        # BGP link interface
        "interface GigabitEthernet1/0",
        f"ip address {device['link_ip']} {device['link_mask']}",
        "no shutdown",
        "no ip redirects",
        "no ip proxy-arp",
        "exit",

        # BGP process
        f"router bgp {device['bgp_as']}",
        f"bgp router-id {device['loopback_ip']}",
        "bgp log-neighbor-changes",
        "no auto-summary",
        "no synchronization",

        # eBGP neighbor (Router 1)
        f"neighbor {device['bgp_peer_ip']} remote-as {device['bgp_peer_as']}",
        f"neighbor {device['bgp_peer_ip']} description 'eBGP-to-R1'",

        # Address family — receive all routes from R1
        "address-family ipv4",
        f"neighbor {device['bgp_peer_ip']} activate",

        # Allow more routes than default (default is 1000 on some IOS)
        f"neighbor {device['bgp_peer_ip']} maximum-prefix 5000 80",
        "exit-address-family",
        "exit",
    ]

    output = send_config_batch(conn, "hostname R2-test", "R2", "one cli")
    output = send_config_batch(conn, commands1, "R2-test2", "2 cli")
    output = send_config_batch(conn, commands2, "R2-test3", "3 cli")

    output = send_config_batch(conn, commands, "R2", "full config")
    log.info(" Router 2 configuration complete")
    return output


# ─────────────────────────────────────────────────────────────────
# SAVE CONFIGURATIONS
# ─────────────────────────────────────────────────────────────────
def save_config(conn, label):
    """Save running config to NVRAM."""
    log.info("Saving config on %s...", label)
    output = conn.send_command_timing(
        "write memory",
        read_timeout=30,
    )
    if "confirm" in output.lower() or "[confirm]" in output.lower():
        output += conn.send_command_timing("\n", read_timeout=30)
    time.sleep(2)
    log.info("   Config saved on %s", label)
    return output


# ─────────────────────────────────────────────────────────────────
# WAIT FOR BGP CONVERGENCE
# ─────────────────────────────────────────────────────────────────
def wait_for_bgp_convergence(conn1, conn2, expected_routes=1000, max_wait=300):
    """
    Wait for BGP session to establish and routes to converge.
    Polls every 15 seconds up to max_wait seconds.
    """
    log.info("\n" + "-" * 50)
    log.info("Waiting for BGP convergence (max %ds)...", max_wait)
    log.info("-" * 50)

    start_time = time.time()
    interval   = 15

    while time.time() - start_time < max_wait:
        elapsed = int(time.time() - start_time)

        # Check BGP neighbor state on R2
        bgp_summary = send_command(
            conn2,
            f"show bgp ipv4 unicast summary | include {ROUTER2['bgp_peer_ip']}",
            read_timeout=30,
        )

        # Check route count on R2
        route_count_output = send_command(
            conn2,
            "show bgp ipv4 unicast summary | include ^Neighbor",
            read_timeout=30,
        )

        # Parse prefixes received
        prefixes_received = 0
        for line in bgp_summary.splitlines():
            if ROUTER2["bgp_peer_ip"] in line:
                parts = line.split()
                if len(parts) >= 10:
                    try:
                        prefixes_received = int(parts[-1])
                    except ValueError:
                        pass

        log.info(
            "  [%3ds] BGP peer: %-15s | Prefixes received: %d / %d",
            elapsed,
            ROUTER2["bgp_peer_ip"],
            prefixes_received,
            expected_routes,
        )

        # Check if session is established
        if "established" in bgp_summary.lower() or prefixes_received > 0:
            if prefixes_received >= expected_routes:
                log.info(
                    "   BGP converged! %d routes received after %ds",
                    prefixes_received, elapsed,
                )
                return True
            elif prefixes_received > 0:
                log.info(
                    "   Partial convergence: %d/%d routes received...",
                    prefixes_received, expected_routes,
                )

        time.sleep(interval)

    log.warning(
        "  BGP convergence timeout after %ds — routes may still be converging",
        max_wait,
    )
    return False


# ─────────────────────────────────────────────────────────────────
# VERIFICATION — ROUTER 1
# ─────────────────────────────────────────────────────────────────
def verify_router1(conn):
    """Run verification commands on Router 1 and display results."""
    log.info("\n" + "=" * 60)
    log.info("ROUTER 1 VERIFICATION")
    log.info("=" * 60)

    # 1. BGP neighbor summary
    log.info("\n[R1] BGP Neighbor Summary:")
    output = send_command(conn, "show bgp ipv4 unicast summary", 30)
    log.info("\n%s", output)

    # 2. BGP route count
    log.info("\n[R1] Total BGP routes:")
    output = send_command(
        conn,
        "show bgp ipv4 unicast | count Network",
        30,
    )
    log.info("  %s", output.strip())

    # 3. Static route count
    log.info("\n[R1] Static route count:")
    output = send_command(
        conn,
        "show ip route static | count ^S",
        30,
    )
    log.info("  %s", output.strip())

    # 4. BGP routes redistributed — sample first 10
    log.info("\n[R1] BGP table — first 10 redistributed routes:")
    output = send_command(
        conn,
        "show bgp ipv4 unicast | begin Network",
        30,
    )
    # Print first 15 lines only
    lines = output.splitlines()[:15]
    log.info("\n%s", "\n".join(lines))
    log.info("  ... (showing first 10 of 1000 routes)")

    # 5. BGP neighbor state
    log.info("\n[R1] BGP Neighbor Details:")
    output = send_command(
        conn,
        f"show bgp ipv4 unicast neighbors {ROUTER1['bgp_peer_ip']} | include "
        f"BGP state|prefixes|messages",
        30,
    )
    log.info("\n%s", output)

    # 6. Interface status
    log.info("\n[R1] Interface Status:")
    output = send_command(conn, "show ip interface brief", 30)
    log.info("\n%s", output)


# ─────────────────────────────────────────────────────────────────
# VERIFICATION — ROUTER 2
# ─────────────────────────────────────────────────────────────────
def verify_router2(conn):
    """Run verification commands on Router 2 and display results."""
    log.info("\n" + "=" * 60)
    log.info("ROUTER 2 VERIFICATION")
    log.info("=" * 60)

    # 1. BGP neighbor summary
    log.info("\n[R2] BGP Neighbor Summary:")
    output = send_command(conn, "show bgp ipv4 unicast summary", 30)
    log.info("\n%s", output)

    # 2. Total BGP routes received
    log.info("\n[R2] Total BGP routes received:")
    output = send_command(
        conn,
        "show bgp ipv4 unicast  ",
        30,
    )
    log.info("  Routes with best path (*): %s", output.strip())

    # 3. Sample routes — first 10
    log.info("\n[R2] BGP routing table — first 10 routes received:")
    output = send_command(
        conn,
        "show bgp ipv4 unicast | begin Network",
        30,
    )
    lines = output.splitlines()[:15]
    log.info("\n%s", "\n".join(lines))
    log.info("  ... (showing first 10 of 1000 routes)")

    # 4. Sample routes — last 10
    log.info("\n[R2] BGP routing table — last 10 routes received:")
    output = send_command(
        conn,
        "show bgp ipv4 unicast 10.3.231.0",
        30,
    )
    log.info("\n%s", output)

    # 5. BGP neighbor details
    log.info("\n[R2] BGP Neighbor Details:")
    output = send_command(
        conn,
        f"show bgp ipv4 unicast neighbors {ROUTER2['bgp_peer_ip']} | include "
        f"BGP state|prefixes|Prefixes",
        30,
    )
    log.info("\n%s", output)

    # 6. Specific route lookup
    log.info("\n[R2] Route lookup for 10.0.0.0/24 (first route):")
    output = send_command(conn, "show bgp ipv4 unicast 10.0.0.0", 30)
    log.info("\n%s", output)

    # 7. Route lookup for middle route
    log.info("\n[R2] Route lookup for 10.1.244.0/24 (middle route ~500th):")
    output = send_command(conn, "show bgp ipv4 unicast 10.1.244.0", 30)
    log.info("\n%s", output)

    # 8. IP routing table count
    log.info("\n[R2] IP routing table summary:")
    output = send_command(conn, "show ip route summary", 30)
    log.info("\n%s", output)

    # 9. Interface status
    log.info("\n[R2] Interface Status:")
    output = send_command(conn, "show ip interface brief", 30)
    log.info("\n%s", output)


# ─────────────────────────────────────────────────────────────────
# SHOW COMMANDS REFERENCE
# ─────────────────────────────────────────────────────────────────
def print_useful_commands():
    """Print reference of useful show commands for manual verification."""
    log.info("\n" + "=" * 60)
    log.info("USEFUL CLI COMMANDS FOR MANUAL VERIFICATION")
    log.info("=" * 60)

    log.info("""
---------------------------------------------------------------
                    ROUTER 1 (R1) COMMANDS                   
---------------------------------------------------------------
  BGP verification:                                          
  show bgp ipv4 unicast summary                             
  show bgp ipv4 unicast                                                           │
  show bgp ipv4 unicast neighbors 192.168.100.2             
  show bgp ipv4 unicast neighbors 192.168.100.2 advertised  

  Static routes:                                             
  show ip route static                                       
  show ip route static | begin 10.0.0.0                     
    
    BGP redistribution:                                        
  show ip protocols                                          
  show bgp ipv4 unicast | include 10.0.0                                                                                │
  Specific route:                                            
    show bgp ipv4 unicast 10.0.0.0/24                        
    show ip route 10.0.0.0                                    

---------------------------------------------------------------
│                    ROUTER 2 (R2) COMMANDS                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BGP verification:                                          │
│  show bgp ipv4 unicast summary                             │
│  show bgp ipv4 unicast                                     │
│  show bgp ipv4 unicast | count ^\*>                        │
│  show bgp ipv4 unicast neighbors 192.168.100.1             │
│  show bgp ipv4 unicast neighbors 192.168.100.1 received    │
│                                                             │
│  Routing table:                                             │
│  show ip route bgp                                          │
│  show ip route bgp | count ^B                              │
│  show ip route summary                                      │
│                                                             │
│  Specific route lookup:                                     │
│  show bgp ipv4 unicast 10.0.0.0/24                        │
│  show bgp ipv4 unicast 10.3.231.0/24  (last route)        │
│  show ip route 10.0.0.0                                    │
│                                                             │
│  BGP path details:                                          │
│  show bgp ipv4 unicast 10.1.0.0 longer-prefixes           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   BOTH ROUTERS COMMANDS                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BGP session health:                                        │
│  show bgp ipv4 unicast summary                             │
│  show tcp brief                                             │
│  show ip bgp summary                                        │
│                                                             │
│  Interface check:                                           │
│  show ip interface brief                                    │
│  show interface GigabitEthernet1/0                         │
│                                                             │
│  Connectivity:                                              │
│  ping 192.168.100.1  (from R2)                            │
│  ping 192.168.100.2  (from R1)                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
""")


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    start_time = time.time()

    log.info("=" * 60)
    log.info("  BGP 1000 Routes Generator")
    log.info("  Router 1: %s (AS %d)", ROUTER1["host"], ROUTER1["bgp_as"])
    log.info("  Router 2: %s (AS %d)", ROUTER2["host"], ROUTER2["bgp_as"])
    log.info("  Routes:   %d x /%d networks",
             ROUTE_CONFIG["count"], ROUTE_CONFIG["prefix_len"])
    log.info("=" * 60)

    # ── Step 1 — Generate route list ────────────────────────────
    log.info("\n[STEP 1] Generating %d route prefixes...", ROUTE_CONFIG["count"])
    routes = generate_routes(
        ROUTE_CONFIG["start_network"],
        ROUTE_CONFIG["prefix_len"],
        ROUTE_CONFIG["count"],
    )
    log.info("  First route: %s/%d", routes[0],   ROUTE_CONFIG["prefix_len"])
    log.info("  Last route:  %s/%d", routes[-1],  ROUTE_CONFIG["prefix_len"])

    # ── Step 2 — Connect to both routers ────────────────────────
    log.info("\n[STEP 2] Connecting to routers...")
    conn1 = connect_router(ROUTER1, "Router 1")
    conn2 = connect_router(ROUTER2, "Router 2")

    try:
        # ── Step 3 — Configure Router 2 first ───────────────────
        # Configure R2 first so BGP peer is ready when R1 comes up
        log.info("\n[STEP 3] Configuring Router 2 (BGP receiver)...")
        configure_router2(conn2, ROUTER2)
        save_config(conn2, "Router 2")

        # ── Step 4 — Configure Router 1 base ────────────────────
        log.info("\n[STEP 4] Configuring Router 1 base settings...")
        configure_router1_base(conn1, ROUTER1)

        # ── Step 5 — Push 1000 static routes to Router 1 ────────
        log.info("\n[STEP 5] Pushing 1000 static routes to Router 1...")
        configure_router1_static_routes(
            conn1,
            routes,
            ROUTE_CONFIG["prefix_len"],
            ROUTE_CONFIG["next_hop"],
        )
        save_config(conn1, "Router 1")

        # ── Step 6 — Wait for BGP convergence ───────────────────
        log.info("\n[STEP 6] Waiting for BGP to converge...")
        converged = wait_for_bgp_convergence(
            conn1, conn2,
            expected_routes=ROUTE_CONFIG["count"],
            max_wait=300,
        )

        # ── Step 7 — Verify on both routers ─────────────────────
        log.info("\n[STEP 7] Running verification commands...")
        verify_router1(conn1)
        verify_router2(conn2)

        # ── Step 8 — Print useful commands reference ─────────────
        print_useful_commands()

        # ── Summary ──────────────────────────────────────────────
        elapsed = int(time.time() - start_time)
        log.info("\n" + "=" * 60)
        log.info("  SCRIPT COMPLETE")
        log.info("  Total time: %dm %ds", elapsed // 60, elapsed % 60)
        log.info("  BGP converged: %s", " YES" if converged else "⚠️  CHECK MANUALLY")
        log.info("  Routes generated: %d", ROUTE_CONFIG["count"])
        log.info("  Router 1: %s (AS %d)", ROUTER1["host"], ROUTER1["bgp_as"])
        log.info("  Router 2: %s (AS %d)", ROUTER2["host"], ROUTER2["bgp_as"])
        log.info("=" * 60)

    except Exception as e:
        log.error("    Unexpected error: %s", str(e))
        raise

    finally:
        # Always disconnect cleanly
        log.info("\nDisconnecting from routers...")
        try:
            conn1.disconnect()
            log.info("   Router 1 disconnected")
        except Exception:
            pass
        try:
            conn2.disconnect()
            log.info("    Router 2 disconnected")
        except Exception:
            pass


if __name__ == "__main__":
    main()
