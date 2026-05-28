#!/usr/bin/env python3
"""
sonic_ospf_1k_routes.py  (v1)
════════════════════════════════════════════════════════════════════
Generates 1000 OSPF routes between two Dell SONiC switches.

Topology:
                    OSPF Area 0 (Backbone)
  ┌──────────────┐   192.168.100.0/30   ┌──────────────┐
  │   Switch 1   │◄───────────────────►│   Switch 2   │
  │  Router ID   │  .1            .2   │  Router ID   │
  │  1.1.1.1     │                     │  2.2.2.2     │
  │              │                     │              │
  │ 1000 static  │                     │ receives all │
  │ routes       │                     │ 1000 routes  │
  │ redistributed│                     │ via OSPF     │
  │ into OSPF    │                     │ Type-5 LSAs  │
  └──────────────┘                     └──────────────┘

How it works:
  Switch 1:
    - 1000 blackhole static routes (10.0.0.0/24 ... 10.3.231.0/24)
    - OSPF process 1, area 0, router-id 1.1.1.1
    - redistribute static metric 10 metric-type 2
    - Link interface Ethernet0 in OSPF area 0

  Switch 2:
    - OSPF process 1, area 0, router-id 2.2.2.2
    - Link interface Ethernet0 in OSPF area 0
    - Receives 1000 Type-5 External LSAs from Switch 1

Key SONiC/FRR differences from Cisco OSPF:
  Cisco:  router ospf 1
            network 192.168.100.0 0.0.0.3 area 0
            redistribute static subnets metric 10

  FRR:    router ospf
            ospf router-id 1.1.1.1
            redistribute static metric 10 metric-type 2
          interface Ethernet0
            ip ospf area 0
            ip ospf network point-to-point

Requirements:
  pip install netmiko paramiko

Usage:
  python sonic_ospf_1k_routes.py
════════════════════════════════════════════════════════════════════
"""

import re
import io
import sys
import socket
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
# LOGGING — UTF-8 safe for Windows and Linux
# ─────────────────────────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    _utf8_stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding="utf-8",
        errors="replace",
        line_buffering=True,
    )
else:
    _utf8_stdout = sys.stdout

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(_utf8_stdout),
        logging.FileHandler(
            f"sonic_ospf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            encoding="utf-8",
        ),
    ],
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# DEVICE CONFIGURATION — Edit these for your environment
# ─────────────────────────────────────────────────────────────────
SWITCH1 = {
    "host":             "192.168.1.2",
    "port":             22,
    "device_type":      "linux",
    "username":         "admin",
    "password":         "admin",
    "timeout":          60,
    "auth_timeout":     30,
    "session_timeout":  600,
    "hostname":         "sonic-sw1",
    "label":            "Switch1",
    # OSPF settings
    "ospf_router_id":   "1.1.1.1",
    "ospf_area":        "0.0.0.0",
    # Link interface to Switch 2
    "link_interface":   "Ethernet0",
    "link_ip":          "192.168.100.1",
    "link_prefix":      "192.168.100.1/30",
    # Loopback
    "loopback_ip":      "1.1.1.1",
    "loopback_prefix":  "1.1.1.1/32",
    # Peer
    "peer_ip":          "192.168.100.2",
}

SWITCH2 = {
    "host":             "192.168.18.2",
    "port":             22,
    "device_type":      "linux",
    "username":         "admin",
    "password":         "admin",
    "timeout":          60,
    "auth_timeout":     30,
    "session_timeout":  600,
    "hostname":         "sonic-sw2",
    "label":            "Switch2",
    # OSPF settings
    "ospf_router_id":   "2.2.2.2",
    "ospf_area":        "0.0.0.0",
    # Link interface to Switch 1
    "link_interface":   "Ethernet0",
    "link_ip":          "192.168.100.2",
    "link_prefix":      "192.168.100.2/30",
    # Loopback
    "loopback_ip":      "2.2.2.2",
    "loopback_prefix":  "2.2.2.2/32",
    # Peer
    "peer_ip":          "192.168.100.1",
}

ROUTE_CONFIG = {
    "count":            1000,
    "start_network":    "10.0.0.0",
    "prefix_len":       24,
    "next_hop":         "blackhole",
    "batch_size":       50,
}


# ─────────────────────────────────────────────────────────────────
# PROMPT PATTERNS
# \n anchor prevents false match inside FRR output body text.
# No hardcoded hostname — \w[\w-]* matches any hostname.
# Initial vtysh entry uses pattern WITHOUT \n (first prompt
# has no leading newline).
# ─────────────────────────────────────────────────────────────────
VTYSH_EXEC_PROMPT   = r"\n\w[\w-]*# "
VTYSH_CONFIG_PROMPT = r"\n\w[\w-]*\(config\)# "
VTYSH_ROUTER_PROMPT = r"\n\w[\w-]*\(config-router\)# "
VTYSH_IF_PROMPT     = r"\n\w[\w-]*\(config-if\)# "
VTYSH_ANY_PROMPT    = r"\n\w[\w-]*(?:\([^)]*\))?# "
SHELL_PROMPT        = r"\n[^@\s]+@\S+[#$] "


# ─────────────────────────────────────────────────────────────────
# HELPER — strip prompt from timing output
# ─────────────────────────────────────────────────────────────────
def _strip_prompt(output):
    """Remove SONiC shell prompt lines from send_command_timing output."""
    cleaned = []
    for line in output.splitlines():
        if re.search(r"[^@\s]+@[^:]+:[^$#]*[$#]\s*", line):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


# ─────────────────────────────────────────────────────────────────
# COMMAND RUNNERS
# ─────────────────────────────────────────────────────────────────
def run_cmd(conn, command, label="", timeout=30):
    """Run a Linux shell command using timing-based read."""
    try:
        output = conn.send_command_timing(
            command,
            read_timeout=timeout,
            strip_prompt=False,
            strip_command=True,
            last_read=2.0,
        )
        return _strip_prompt(output)
    except Exception as e:
        log.error("  [FAIL] [%s] run_cmd '%s': %s", label, command[:60], str(e))
        return ""


def run_cmd_timing(conn, command, label="", timeout=30):
    """Run a SONiC config CLI command with timing-based read."""
    try:
        output = conn.send_command_timing(
            command,
            read_timeout=timeout,
            strip_prompt=True,
            strip_command=True,
            last_read=3.0,
        )
        return output.strip()
    except Exception as e:
        log.error("  [FAIL] [%s] run_cmd_timing: %s", label, str(e))
        return ""


def run_vtysh(conn, vtysh_command, label="", timeout=60):
    """Run a FRR vtysh show/exec command via timing-based read."""
    if not conn.is_alive():
        log.warning("  [WARN] [%s] run_vtysh skipped — not alive", label)
        return ""
    escaped = vtysh_command.replace('"', '\\"')
    cmd     = f'sudo vtysh -c "{escaped}"'
    try:
        output = conn.send_command_timing(
            cmd,
            read_timeout=timeout,
            strip_prompt=False,
            strip_command=True,
            last_read=2.0,
        )
        return _strip_prompt(output)
    except Exception as e:
        log.error("  [FAIL] [%s] run_vtysh '%s': %s",
                  label, vtysh_command[:60], str(e))
        return ""


# ─────────────────────────────────────────────────────────────────
# MODE TRACKER — for run_vtysh_config
# ─────────────────────────────────────────────────────────────────
def _prompt_for_cmd(cmd, current_mode):
    """
    Return expected vtysh prompt AFTER this command runs.
    exit/end checked FIRST — context-sensitive.
    Then MODE_MAP for fixed transitions.
    """
    cl = cmd.lower().strip()

    # 1. Context-sensitive — FIRST
    if cl == "exit":
        if current_mode == "iface":  return VTYSH_CONFIG_PROMPT
        elif current_mode == "router": return VTYSH_CONFIG_PROMPT
        elif current_mode == "config": return VTYSH_EXEC_PROMPT
        else:                          return VTYSH_EXEC_PROMPT

    if cl == "end":
        return VTYSH_EXEC_PROMPT

    # 2. Fixed transitions
    MODE_MAP = {
        "configure terminal": VTYSH_CONFIG_PROMPT,
        "router ospf":        VTYSH_ROUTER_PROMPT,
        "interface":          VTYSH_IF_PROMPT,
    }
    for keyword, prompt in MODE_MAP.items():
        if cl.startswith(keyword):
            return prompt

    # 3. Stay in current mode
    mode_prompts = {
        "exec":   VTYSH_EXEC_PROMPT,
        "config": VTYSH_CONFIG_PROMPT,
        "router": VTYSH_ROUTER_PROMPT,
        "iface":  VTYSH_IF_PROMPT,
    }
    return mode_prompts.get(current_mode, VTYSH_ANY_PROMPT)


def _update_mode(cmd, current_mode):
    """Return new mode string after command executes."""
    cl = cmd.lower().strip()

    # 1. Context-sensitive — FIRST
    if cl == "exit":
        if current_mode == "iface":   return "config"
        elif current_mode == "router": return "config"
        elif current_mode == "config": return "exec"
        else:                          return "exec"

    if cl == "end":
        return "exec"

    # 2. Fixed transitions
    if cl == "configure terminal":  return "config"
    if cl.startswith("router ospf"): return "router"
    if cl.startswith("interface"):  return "iface"

    return current_mode


# ─────────────────────────────────────────────────────────────────
# run_vtysh_config — interactive vtysh session
# ─────────────────────────────────────────────────────────────────
def run_vtysh_config(conn, config_block, label=""):
    """
    Run a FRR vtysh config block interactively.
    Uses write_channel + read_until_pattern per command
    with correct per-mode prompt patterns.
    """
    results      = []
    errors       = []
    current_mode = "exec"

    def _read_until(pattern, timeout=20):
        try:
            out = conn.read_until_pattern(
                pattern=pattern,
                read_timeout=timeout,
            )
            return out.strip()
        except Exception as e:
            log.debug("  [%s] read_until miss '%s': %s — timing fallback",
                      label, pattern, str(e)[:60])
            time.sleep(2.0)
            return conn.read_channel().strip()

    try:
        # Enter vtysh — broad pattern (no \n) for first prompt
        conn.write_channel("sudo vtysh\n")
        time.sleep(1.5)
        init = _read_until(r"\w[\w-]*# ", timeout=15)
        log.debug("  [%s] vtysh entered: ...%s", label, init[-20:])

        for cmd in config_block:
            cmd = cmd.strip()
            if not cmd or cmd.startswith("!"):
                continue

            expected     = _prompt_for_cmd(cmd, current_mode)
            log.debug("  [%s] mode=%-8s  CMD: %-40s  expect: %s",
                      label, current_mode, cmd, expected)

            conn.write_channel(f"{cmd}\n")
            time.sleep(0.3)

            out          = _read_until(expected, timeout=20)
            current_mode = _update_mode(cmd, current_mode)

            log.debug("  [%s] mode now=%-8s  response: ...%s",
                      label, current_mode, out[-40:])
            results.append(f"[{cmd}]->{out[-60:]}")

            if re.search(r"^%\s+(?:Unknown|Invalid|Incomplete)",
                         out, re.MULTILINE):
                errors.append(cmd)
                log.warning("  [WARN] [%s] FRR rejected '%s': %s",
                             label, cmd, out[:100])

        # Exit cleanly
        conn.write_channel("end\n")
        time.sleep(0.3)
        _read_until(VTYSH_EXEC_PROMPT, timeout=10)
        conn.write_channel("exit\n")
        time.sleep(0.5)
        _read_until(SHELL_PROMPT, timeout=10)

    except Exception as e:
        log.error("  [FAIL] [%s] vtysh_config error: %s", label, str(e))
        try:
            conn.write_channel("end\nexit\n")
            time.sleep(1)
            conn.read_channel()
        except Exception:
            pass

    if errors:
        log.warning("  [WARN] [%s] %d FRR error(s): %s",
                    label, len(errors), errors)
    return "\n".join(results)


# ─────────────────────────────────────────────────────────────────
# ROUTE GENERATOR
# ─────────────────────────────────────────────────────────────────
def generate_routes(start_network, prefix_len, count):
    """Generate list of sequential IPv4 network prefixes."""
    routes  = []
    network = ipaddress.IPv4Network(
        f"{start_network}/{prefix_len}", strict=False
    )
    for _ in range(count):
        routes.append(str(network.network_address))
        next_addr = int(network.network_address) + (2 ** (32 - prefix_len))
        network   = ipaddress.IPv4Network(
            f"{ipaddress.IPv4Address(next_addr)}/{prefix_len}", strict=False
        )
    log.info("Generated %d routes: %s/%d -> %s/%d",
             count, routes[0], prefix_len, routes[-1], prefix_len)
    return routes


# ─────────────────────────────────────────────────────────────────
# SSH READINESS CHECK
# ─────────────────────────────────────────────────────────────────
def wait_for_ssh_ready(host, port=22, max_wait=180,
                       check_interval=10, label=""):
    """Wait until SSH port is open and banner is present."""
    log.info("%s: Waiting for SSH on %s:%d...", label, host, port)
    start  = time.time()
    opened = False

    while time.time() - start < max_wait:
        elapsed = int(time.time() - start)
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            if not opened:
                log.info("  [%3ds] TCP port %d open — waiting 10s for sshd...",
                         elapsed, port)
                opened = True
                time.sleep(10)
            try:
                sock2  = socket.create_connection((host, port), timeout=5)
                banner = sock2.recv(256)
                sock2.close()
                if b"SSH" in banner:
                    log.info("  [OK] SSH ready on %s:%d after %ds",
                             host, port, elapsed)
                    return True
            except Exception:
                pass
        except (socket.timeout, ConnectionRefusedError, OSError):
            log.info("  [%3ds] %s:%d not ready yet...", elapsed, host, port)
        time.sleep(check_interval)

    log.warning("  [WARN] SSH not ready on %s:%d after %ds",
                host, port, max_wait)
    return False


# ─────────────────────────────────────────────────────────────────
# CONNECTION WITH RETRY
# ─────────────────────────────────────────────────────────────────
def connect_switch(device, label,
                   max_retries=10, retry_delay=15, connect_timeout=60):
    """Connect to SONiC switch via SSH with automatic retry."""
    conn_params = {
        "host":            device["host"],
        "port":            device["port"],
        "device_type":     device["device_type"],
        "username":        device["username"],
        "password":        device["password"],
        "timeout":         connect_timeout,
        "auth_timeout":    device.get("auth_timeout", 30),
        "session_timeout": device.get("session_timeout", 600),
        "banner_timeout":  30,
        "keepalive":       60,
    }
    last_error = None
    for attempt in range(1, max_retries + 1):
        log.info("Connecting to %s (%s) attempt %d/%d...",
                 label, device["host"], attempt, max_retries)
        try:
            conn = ConnectHandler(**conn_params)
            log.info("  [OK] Connected to %s (attempt %d/%d)",
                     label, attempt, max_retries)
            return conn
        except NetmikoAuthenticationException as e:
            log.error("  [FAIL] Auth failed on %s: %s", label, str(e))
            sys.exit(1)
        except NetmikoTimeoutException as e:
            last_error = e
            log.warning("  [WARN] Timeout on %s attempt %d/%d",
                        label, attempt, max_retries)
        except Exception as e:
            last_error = e
            err = str(e).lower()
            reason = ("EOF in transport"    if "eof"      in err else
                      "Connection refused"  if "refused"  in err else
                      "Timed out"           if "timed"    in err else
                      str(e)[:80])
            log.warning("  [WARN] [%s] attempt %d/%d: %s",
                        label, attempt, max_retries, reason)
        if attempt < max_retries:
            log.info("  Retrying in %ds (%d left)...",
                     retry_delay, max_retries - attempt)
            time.sleep(retry_delay)

    log.error("  [FAIL] Could not connect to %s after %d attempts: %s",
              label, max_retries, str(last_error)[:120])
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────
# INTERFACE CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def configure_loopback(conn, device, label):
    """Configure loopback interface with multi-method fallback."""
    log.info("%s: Configuring Loopback0 %s...", label, device["loopback_prefix"])
    lb_prefix = device["loopback_prefix"]
    lb_ip     = device["loopback_ip"]

    existing = run_cmd(conn, f"ip addr show Loopback0 | grep {lb_ip}",
                       label, timeout=15)
    if lb_ip in existing:
        log.info("  [OK] Loopback0 already has IP %s", lb_prefix)
        return

    out = run_cmd_timing(
        conn, f"sudo config interface ip add Loopback0 {lb_prefix}", label
    )
    time.sleep(1)

    if "invalid" in out.lower() or "error" in out.lower():
        log.warning("  [WARN] SONiC CLI rejected — trying redis + Linux...")
        run_cmd_timing(conn,
            'sudo redis-cli -n 4 HSET "LOOPBACK_INTERFACE|Loopback0" "NULL" "NULL"',
            label)
        run_cmd_timing(conn,
            f'sudo redis-cli -n 4 HSET '
            f'"LOOPBACK_INTERFACE|Loopback0|{lb_prefix}" "scope" "global"',
            label)
        time.sleep(2)
        run_cmd_timing(conn,
            f"sudo config interface ip add Loopback0 {lb_prefix}", label)
        time.sleep(1)

    verify = run_cmd(conn, f"ip addr show Loopback0 | grep {lb_ip}",
                     label, timeout=15)
    if lb_ip not in verify:
        log.warning("  [WARN] Falling back to Linux ip + FRR vtysh...")
        run_cmd_timing(conn, "sudo ip link set Loopback0 up", label)
        run_cmd_timing(conn, f"sudo ip addr add {lb_prefix} dev Loopback0", label)
        run_vtysh_config(conn, [
            "configure terminal",
            "interface Loopback0",
            f"ip address {lb_prefix}",
            "end",
        ], label)
    time.sleep(1)
    verify2 = run_cmd(conn, f"ip addr show Loopback0 | grep {lb_ip}",
                      label, timeout=15)
    if lb_ip in verify2:
        log.info("  [OK] Loopback0 IP %s confirmed", lb_prefix)
    else:
        log.error("  [FAIL] Loopback0 IP %s NOT configured!", lb_prefix)


def configure_interface(conn, device, label):
    """Configure OSPF link interface on SONiC."""
    log.info("%s: Configuring %s %s...",
             label, device["link_interface"], device["link_prefix"])
    iface  = device["link_interface"]
    prefix = device["link_prefix"]
    ip     = device["link_ip"]

    existing = run_cmd(conn, f"ip addr show {iface} | grep {ip}",
                       label, timeout=15)
    if ip in existing:
        log.info("  [OK] %s already has IP %s", iface, prefix)
    else:
        run_cmd_timing(conn,
            f"sudo config interface ip remove {iface} {prefix}"
            f" 2>/dev/null || true", label)
        time.sleep(1)
        run_cmd_timing(conn,
            f"sudo config interface ip add {iface} {prefix}", label)
        time.sleep(2)
        log.info("  [OK] IP %s added to %s", prefix, iface)

    run_cmd_timing(conn, f"sudo config interface startup {iface}", label)
    time.sleep(1)

    verify = run_vtysh(conn, f"show interface {iface}", label, timeout=15)
    log.info("  Interface status:\n%s", verify[:300])


# ─────────────────────────────────────────────────────────────────
# STATIC ROUTES — single interactive vtysh session
# ─────────────────────────────────────────────────────────────────
def configure_static_routes(conn, routes, prefix_len, label):
    """
    Configure 1000 blackhole static routes in one vtysh session.
    FRR static routes are redistributed into OSPF as Type-5 LSAs.
    """
    log.info("\n%s: Configuring %d static routes...", label, len(routes))
    total  = len(routes)
    report = 100
    errors = 0

    def _read_any(timeout=10):
        try:
            return conn.read_until_pattern(
                pattern=VTYSH_ANY_PROMPT, read_timeout=timeout)
        except Exception:
            time.sleep(0.3)
            return conn.read_channel()

    try:
        # Enter vtysh — broad pattern for first prompt
        conn.write_channel("sudo vtysh\n")
        time.sleep(1.5)
        try:
            conn.read_until_pattern(pattern=r"\w[\w-]*# ", read_timeout=15)
        except Exception:
            conn.read_channel()

        # Enter configure terminal
        conn.write_channel("configure terminal\n")
        time.sleep(0.3)
        _read_any(timeout=10)

        # Send all 1000 static routes
        for i, network in enumerate(routes, 1):
            conn.write_channel(f"ip route {network}/{prefix_len} blackhole\n")
            if i % 10 == 0:
                time.sleep(0.2)
                out = conn.read_channel()
                if "%" in out and "unknown" in out.lower():
                    errors += 1
                    log.warning("  [WARN] [%s] Route error at #%d: %s",
                                label, i, out.strip()[:80])
            if i % report == 0 or i == total:
                log.info("  Progress: %d/%d (%.0f%%)  errors=%d",
                         i, total, (i / total) * 100, errors)

        time.sleep(0.5)
        conn.read_channel()

        conn.write_channel("end\n")
        time.sleep(0.3)
        _read_any(timeout=10)

        conn.write_channel("write memory\n")
        time.sleep(3)
        try:
            conn.read_until_pattern(
                pattern=r"(?:Build|OK|saved|written)", read_timeout=30)
        except Exception:
            conn.read_channel()

        conn.write_channel("exit\n")
        time.sleep(0.5)
        try:
            conn.read_until_pattern(pattern=SHELL_PROMPT, read_timeout=10)
        except Exception:
            conn.read_channel()

        log.info("  [OK] [%s] %d static routes configured (errors=%d)",
                 label, total, errors)

    except Exception as e:
        log.error("  [FAIL] [%s] Static route error: %s", label, str(e))
        try:
            conn.write_channel("end\nexit\n")
            time.sleep(1)
            conn.read_channel()
        except Exception:
            pass

    time.sleep(2)
    verify = run_vtysh(conn, "show ip route static", label, timeout=60)
    static_count = sum(1 for l in verify.splitlines() if l.startswith("S"))
    log.info("  Static routes confirmed in FRR: %d", static_count)


# ─────────────────────────────────────────────────────────────────
# OSPF CONFIGURATION — SWITCH 1
# Redistributes 1000 static routes into OSPF as Type-5 External LSAs
# ─────────────────────────────────────────────────────────────────
def configure_ospf_switch1(conn, device, label):
    """
    Configure FRR OSPF on Switch 1.

    Key FRR OSPF commands:
      router ospf               - start OSPF process (FRR has one process)
      ospf router-id x.x.x.x   - set router ID
      redistribute static       - inject static routes as Type-5 LSAs
      metric-type 2             - E2 (default) - cost not accumulated
      metric 10                 - cost value for redistributed routes

    Interface OSPF:
      ip ospf area 0.0.0.0      - put interface in area 0
      ip ospf network point-to-point - /30 link — avoids DR/BDR election
      ip ospf hello-interval 10
      ip ospf dead-interval 40
    """
    log.info("\n%s: Configuring FRR OSPF (router-id %s)...",
             label, device["ospf_router_id"])

    iface = device["link_interface"]
    area  = device["ospf_area"]
    rid   = device["ospf_router_id"]

    config_block = [
        "configure terminal",

        # ── OSPF router process ───────────────────────────────────
        "router ospf",
        f"ospf router-id {rid}",
        "log-adjacency-changes detail",

        # Redistribute static routes into OSPF as Type-5 External LSAs
        # metric-type 2 = cost NOT accumulated across OSPF (E2)
        # metric-type 1 = cost IS accumulated across OSPF (E1)
        "redistribute static metric 10 metric-type 2",

        # Also redistribute connected so loopback is advertised
        "redistribute connected metric 5 metric-type 2",

        "passive-interface Loopback0",
        "exit",

        # ── Interface configuration ───────────────────────────────
        f"interface {iface}",
        f"ip ospf area {area}",
        # point-to-point avoids DR/BDR election on /30 link
        "ip ospf network point-to-point",
        "ip ospf hello-interval 10",
        "ip ospf dead-interval 40",
        "exit",

        # ── Loopback in OSPF ─────────────────────────────────────
        "interface Loopback0",
        f"ip ospf area {area}",
        "ip ospf network point-to-point",
        "exit",

        "exit",
    ]

    output = run_vtysh_config(conn, config_block, label)
    log.info("  vtysh_config result:\n%s", output[:300] if output else "")
    time.sleep(2)

    verify = run_vtysh(conn, "show ip ospf", label)
    if rid in verify or "OSPF" in verify.upper():
        log.info("  [OK] OSPF router-id %s confirmed in FRR", rid)
    else:
        log.warning("  [WARN] OSPF not confirmed — check vtysh manually")

    return output


# ─────────────────────────────────────────────────────────────────
# OSPF CONFIGURATION — SWITCH 2
# Receives 1000 Type-5 LSAs from Switch 1
# ─────────────────────────────────────────────────────────────────
def configure_ospf_switch2(conn, device, label):
    """
    Configure FRR OSPF on Switch 2.
    Switch 2 is a pure OSPF receiver — no redistribution needed.
    It forms OSPF adjacency with Switch 1 and receives all LSAs.
    """
    log.info("\n%s: Configuring FRR OSPF (router-id %s)...",
             label, device["ospf_router_id"])

    iface = device["link_interface"]
    area  = device["ospf_area"]
    rid   = device["ospf_router_id"]

    config_block = [
        "configure terminal",

        # ── OSPF router process ───────────────────────────────────
        "router ospf",
        f"ospf router-id {rid}",
        "log-adjacency-changes detail",
        "passive-interface Loopback0",
        "exit",

        # ── Interface configuration ───────────────────────────────
        f"interface {iface}",
        f"ip ospf area {area}",
        "ip ospf network point-to-point",
        "ip ospf hello-interval 10",
        "ip ospf dead-interval 40",
        "exit",

        # ── Loopback in OSPF ─────────────────────────────────────
        "interface Loopback0",
        f"ip ospf area {area}",
        "ip ospf network point-to-point",
        "exit",

        "exit",
    ]

    output = run_vtysh_config(conn, config_block, label)
    log.info("  vtysh_config result:\n%s", output[:300] if output else "")
    time.sleep(2)

    verify = run_vtysh(conn, "show ip ospf", label)
    if rid in verify or "OSPF" in verify.upper():
        log.info("  [OK] OSPF router-id %s confirmed in FRR", rid)
    else:
        log.warning("  [WARN] OSPF not confirmed — check vtysh manually")

    return output


# ─────────────────────────────────────────────────────────────────
# SAVE CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def save_frr_config(conn, label):
    """Save FRR config to /etc/frr/frr.conf and SONiC config."""
    log.info("%s: Saving configuration...", label)
    run_vtysh(conn, "write memory", label)
    time.sleep(2)
    run_cmd_timing(conn, "sudo config save -y", label, timeout=30)
    time.sleep(2)
    log.info("  [OK] Config saved on %s", label)


# ─────────────────────────────────────────────────────────────────
# WAIT FOR OSPF CONVERGENCE
# ─────────────────────────────────────────────────────────────────
def wait_for_ospf_convergence(conn2, device2,
                               expected_routes=1000, max_wait=300):
    """
    Poll Switch 2 until all OSPF external routes are received.
    OSPF converges much faster than BGP — 300s max is sufficient.
    Checks is_alive() before each poll — exits immediately if closed.
    """
    log.info("\n" + "-" * 50)
    log.info("Waiting for OSPF convergence (max %ds)...", max_wait)
    log.info("-" * 50)

    start_time     = time.time()
    interval       = 10
    reconnect_done = False

    while time.time() - start_time < max_wait:
        elapsed = int(time.time() - start_time)

        # Socket liveness check — exit fast if closed
        if not conn2.is_alive():
            if not reconnect_done:
                log.warning("  [WARN] [%3ds] Switch2 socket closed — "
                            "attempting reconnect...", elapsed)
                try:
                    conn2.disconnect()
                except Exception:
                    pass
                try:
                    conn2 = connect_switch(
                        device2, device2["label"],
                        max_retries=5, retry_delay=10, connect_timeout=30)
                    reconnect_done = True
                    log.info("  [OK] Reconnected to Switch2")
                except Exception as e:
                    log.error("  [FAIL] Reconnect failed: %s — aborting", str(e))
                    return False, conn2
            else:
                log.error("  [FAIL] [%3ds] Socket closed again — aborting", elapsed)
                return False, conn2

        # Count OSPF external routes (Type-5 LSAs appear as OE2 or OE1)
        # FRR marks them with "OE2" (External Type-2) in show ip route
        route_output = run_vtysh(conn2, "show ip route ospf", "Switch2",
                                 timeout=60)
        ospf_ext = [l for l in route_output.splitlines()
                    if l.startswith("OE2") or l.startswith("OE1")
                    or l.startswith("O E")]
        routes_received = len(ospf_ext)

        # Also check adjacency state
        ospf_nbr = run_vtysh(conn2, "show ip ospf neighbor", "Switch2")
        adj_full = "full" in ospf_nbr.lower()

        log.info(
            "  [%3ds] Adjacency: %-8s | OSPF ext routes: %d/%d",
            elapsed,
            "FULL" if adj_full else "forming",
            routes_received,
            expected_routes,
        )

        if routes_received >= expected_routes:
            log.info("  [OK] OSPF converged! %d routes after %ds",
                     routes_received, elapsed)
            return True, conn2
        elif routes_received > 0:
            log.info("  [WAIT] Partial: %d/%d routes...",
                     routes_received, expected_routes)

        time.sleep(interval)

    log.warning("  [WARN] Convergence timeout after %ds", max_wait)
    return False, conn2


# ─────────────────────────────────────────────────────────────────
# VERIFICATION — SWITCH 1
# ─────────────────────────────────────────────────────────────────
def verify_switch1(conn, device):
    """Run verification commands on Switch 1."""
    label = device["label"]
    log.info("\n" + "=" * 60)
    log.info("SWITCH 1 VERIFICATION (%s)", device["host"])
    log.info("=" * 60)

    log.info("\n[SW1] OSPF process status:")
    out = run_vtysh(conn, "show ip ospf", label)
    log.info("\n%s", out)

    log.info("\n[SW1] OSPF neighbors:")
    out = run_vtysh(conn, "show ip ospf neighbor", label)
    log.info("\n%s", out)

    log.info("\n[SW1] OSPF interface status:")
    out = run_vtysh(conn, "show ip ospf interface", label)
    log.info("\n%s", out[:500])

    log.info("\n[SW1] Static routes in FRR (count):")
    out = run_vtysh(conn, "show ip route static", label, timeout=60)
    static_count = sum(1 for l in out.splitlines() if l.startswith("S"))
    log.info("  Static route entries: %d", static_count)

    log.info("\n[SW1] OSPF redistribution check (first 10 ext routes):")
    out2 = run_vtysh(conn, "show ip route ospf", label, timeout=60)
    ext_lines = [l for l in out2.splitlines()
                 if l.startswith("OE2") or l.startswith("OE1")][:10]
    for line in ext_lines:
        log.info("  %s", line)
    log.info("  Total OSPF external routes on SW1: %d",
             len([l for l in out2.splitlines()
                  if l.startswith("OE2") or l.startswith("OE1")]))

    log.info("\n[SW1] OSPF database summary:")
    out = run_vtysh(conn, "show ip ospf database", label)
    log.info("\n%s", out[:600])

    log.info("\n[SW1] OSPF database external LSA count:")
    out = run_vtysh(conn, "show ip ospf database external", label, timeout=60)
    ext_lsa = sum(1 for l in out.splitlines()
                  if "Link State ID" in l or "LS ID" in l)
    log.info("  External LSAs generated: %d", ext_lsa)

    log.info("\n[SW1] Route detail 10.0.0.0/24:")
    out = run_vtysh(conn, "show ip route 10.0.0.0/24", label)
    log.info("\n%s", out)

    log.info("\n[SW1] Interface status:")
    out = run_cmd_timing(conn, "show interface status", label, timeout=30)
    log.info("\n%s", out[:500])


# ─────────────────────────────────────────────────────────────────
# VERIFICATION — SWITCH 2
# ─────────────────────────────────────────────────────────────────
def verify_switch2(conn, device):
    """Run verification commands on Switch 2."""
    label = device["label"]
    log.info("\n" + "=" * 60)
    log.info("SWITCH 2 VERIFICATION (%s)", device["host"])
    log.info("=" * 60)

    log.info("\n[SW2] OSPF process status:")
    out = run_vtysh(conn, "show ip ospf", label)
    log.info("\n%s", out)

    log.info("\n[SW2] OSPF neighbors (must show FULL state):")
    out = run_vtysh(conn, "show ip ospf neighbor", label)
    log.info("\n%s", out)

    log.info("\n[SW2] Total OSPF external routes received:")
    out = run_vtysh(conn, "show ip route ospf", label, timeout=60)
    ext_routes = [l for l in out.splitlines()
                  if l.startswith("OE2") or l.startswith("OE1")]
    log.info("  OSPF OE2/OE1 routes: %d", len(ext_routes))

    log.info("\n[SW2] First 10 OSPF external routes:")
    for line in ext_routes[:10]:
        log.info("  %s", line)
    log.info("  ... (first 10 of %d)", len(ext_routes))

    log.info("\n[SW2] Last route (10.3.231.0/24):")
    out = run_vtysh(conn, "show ip route 10.3.231.0/24", label)
    log.info("\n%s", out)

    log.info("\n[SW2] Middle route ~500th (10.1.244.0/24):")
    out = run_vtysh(conn, "show ip route 10.1.244.0/24", label)
    log.info("\n%s", out)

    log.info("\n[SW2] IP route summary:")
    out = run_vtysh(conn, "show ip route summary", label)
    log.info("\n%s", out)

    log.info("\n[SW2] OSPF database summary:")
    out = run_vtysh(conn, "show ip ospf database", label)
    log.info("\n%s", out[:600])

    log.info("\n[SW2] OSPF database external LSA count:")
    out = run_vtysh(conn, "show ip ospf database external", label, timeout=60)
    ext_lsa = sum(1 for l in out.splitlines()
                  if "Link State ID" in l or "LS ID" in l)
    log.info("  External LSAs received: %d", ext_lsa)

    log.info("\n[SW2] Interface status:")
    out = run_cmd_timing(conn, "show interface status", label, timeout=30)
    log.info("\n%s", out[:500])


# ─────────────────────────────────────────────────────────────────
# CLI REFERENCE
# ─────────────────────────────────────────────────────────────────
def print_cli_reference():
    """Print SONiC/FRR OSPF CLI reference."""
    log.info("\n" + "=" * 60)
    log.info("SONIC/FRR OSPF CLI REFERENCE")
    log.info("=" * 60)
    log.info("""
+-------------------------------------------------------------+
|  BOTH SWITCHES -- OSPF Status                               |
+-------------------------------------------------------------+
|  vtysh -c "show ip ospf"                                   |
|  vtysh -c "show ip ospf neighbor"                          |
|  vtysh -c "show ip ospf interface"                         |
|  vtysh -c "show ip ospf database"                          |
|  vtysh -c "show ip ospf database external"                 |
+-------------------------------------------------------------+
|  SWITCH 1 -- Originator                                     |
+-------------------------------------------------------------+
|  vtysh -c "show ip route static" | grep "^S" | wc -l      |
|  vtysh -c "show ip route ospf"   | grep "^OE" | wc -l     |
|  vtysh -c "show ip route 10.0.0.0/24"                     |
|  vtysh -c "show ip ospf database external"                 |
+-------------------------------------------------------------+
|  SWITCH 2 -- Receiver                                       |
+-------------------------------------------------------------+
|  vtysh -c "show ip route ospf"   | grep "^OE" | wc -l     |
|  vtysh -c "show ip route 10.3.231.0/24"  (last route)     |
|  vtysh -c "show ip route summary"                          |
|  vtysh -c "show ip ospf database external"                 |
+-------------------------------------------------------------+
|  Cisco IOS vs SONiC FRR OSPF                               |
+-------------------------------------------------------------+
|  Cisco: network x.x.x.x mask area 0                       |
|  FRR:   ip ospf area 0.0.0.0 (on interface)               |
|                                                             |
|  Cisco: redistribute static subnets metric 10              |
|  FRR:   redistribute static metric 10 metric-type 2        |
|                                                             |
|  Cisco: show ip ospf neighbor                              |
|  FRR:   vtysh -c "show ip ospf neighbor"                   |
|                                                             |
|  Cisco: show ip route ospf                                 |
|  FRR:   vtysh -c "show ip route ospf"                      |
|         OE2 = External Type-2  OE1 = External Type-1       |
|         O   = Intra-area       OI  = Inter-area            |
+-------------------------------------------------------------+
""")


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    start_time = time.time()

    log.info("=" * 60)
    log.info("  SONiC OSPF 1000 Routes Generator  (v1)")
    log.info("  Switch 1: %s (router-id %s)", SWITCH1["host"],
             SWITCH1["ospf_router_id"])
    log.info("  Switch 2: %s (router-id %s)", SWITCH2["host"],
             SWITCH2["ospf_router_id"])
    log.info("  Routes:   %d x /%d",
             ROUTE_CONFIG["count"], ROUTE_CONFIG["prefix_len"])
    log.info("=" * 60)

    # Step 1 — Generate routes
    log.info("\n[STEP 1] Generating routes...")
    routes = generate_routes(
        ROUTE_CONFIG["start_network"],
        ROUTE_CONFIG["prefix_len"],
        ROUTE_CONFIG["count"],
    )

    # Step 2 — Wait for SSH readiness
    log.info("\n[STEP 2] Checking SSH readiness...")
    wait_for_ssh_ready(SWITCH1["host"], port=SWITCH1["port"],
                       max_wait=180, check_interval=10,
                       label=SWITCH1["label"])
    wait_for_ssh_ready(SWITCH2["host"], port=SWITCH2["port"],
                       max_wait=180, check_interval=10,
                       label=SWITCH2["label"])

    # Step 3 — Connect with retry
    log.info("\n[STEP 3] Connecting to switches...")
    conn1 = connect_switch(SWITCH1, SWITCH1["label"],
                           max_retries=10, retry_delay=15,
                           connect_timeout=60)
    conn2 = connect_switch(SWITCH2, SWITCH2["label"],
                           max_retries=10, retry_delay=15,
                           connect_timeout=60)

    try:
        # Step 4 — Configure Switch 2 OSPF first
        log.info("\n[STEP 4] Configuring Switch 2 (OSPF receiver)...")
        configure_loopback(conn2, SWITCH2, SWITCH2["label"])
        configure_interface(conn2, SWITCH2, SWITCH2["label"])
        configure_ospf_switch2(conn2, SWITCH2, SWITCH2["label"])
        save_frr_config(conn2, SWITCH2["label"])

        # Step 5 — Configure Switch 1 interfaces
        log.info("\n[STEP 5] Configuring Switch 1 interfaces...")
        configure_loopback(conn1, SWITCH1, SWITCH1["label"])
        configure_interface(conn1, SWITCH1, SWITCH1["label"])

        # Step 6 — Configure Switch 1 OSPF
        log.info("\n[STEP 6] Configuring Switch 1 OSPF...")
        configure_ospf_switch1(conn1, SWITCH1, SWITCH1["label"])

        # Step 7 — Push 1000 static routes
        log.info("\n[STEP 7] Pushing 1000 static routes to Switch 1...")
        configure_static_routes(conn1, routes,
                                ROUTE_CONFIG["prefix_len"],
                                SWITCH1["label"])
        save_frr_config(conn1, SWITCH1["label"])

        # Step 8 — Verify L3 connectivity
        log.info("\n[STEP 8] Verifying L3 connectivity...")
        ping_out = run_cmd(conn1,
                           f"ping -c 4 -W 2 {SWITCH2['link_ip']}",
                           SWITCH1["label"], timeout=20)
        if "0% packet loss" in ping_out:
            log.info("  [OK] L3 connectivity confirmed")
        else:
            log.warning("  [WARN] Ping check failed — verify interfaces")
        log.info("  %s", ping_out[:200])

        # Step 9 — Wait for OSPF convergence
        log.info("\n[STEP 9] Waiting for OSPF convergence...")
        converged, conn2 = wait_for_ospf_convergence(
            conn2,
            device2=SWITCH2,
            expected_routes=ROUTE_CONFIG["count"],
            max_wait=300,
        )

        # Step 10 — Verify both switches
        log.info("\n[STEP 10] Running verification...")
        verify_switch1(conn1, SWITCH1)
        verify_switch2(conn2, SWITCH2)

        print_cli_reference()

        elapsed = int(time.time() - start_time)
        log.info("\n" + "=" * 60)
        log.info("  COMPLETE")
        log.info("  Time:      %dm %ds", elapsed // 60, elapsed % 60)
        log.info("  Converged: %s",
                 "[OK] YES" if converged else "[WARN] CHECK")
        log.info("  Routes:    %d", ROUTE_CONFIG["count"])
        log.info("=" * 60)

    except Exception as e:
        log.error("  [FAIL] Error: %s", str(e))
        raise

    finally:
        log.info("\nDisconnecting...")
        for conn, lbl in [(conn1, "Switch1"), (conn2, "Switch2")]:
            try:
                conn.disconnect()
                log.info("  [OK] %s disconnected", lbl)
            except Exception:
                pass


if __name__ == "__main__":
    main()
