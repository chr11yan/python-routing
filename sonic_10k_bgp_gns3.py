#!/usr/bin/env python3
"""
sonic_bgp_10k_routes.py  (v4 — 10k routes, admin/admin, no SyntaxWarnings)
════════════════════════════════════════════════════════════════════
Generates 10000 BGP routes between two Dell SONiC switches.

Topology:
                      eBGP Session
  ┌──────────────┐   192.168.100.0/30   ┌──────────────┐
  │   Switch 1   │◄───────────────────►│   Switch 2   │
  │   AS 65001   │  .1            .2   │   AS 65002   │
  │  192.168.1.2 │                     │192.168.18.2  │
  └──────────────┘                     └──────────────┘

Fixes in v3 (on top of v2):
  FIX A — Prompt patterns: removed $ anchor — replaced with \\s
           $ = end-of-string in read_until_pattern (no MULTILINE)
           so sonic# followed by \n never matched. \\s matches
           the space/newline after # immediately.

  FIX B — _prompt_for_cmd: check exit/end FIRST before MODE_MAP
           MODE_MAP had "exit"->VTYSH_CONFIG_PROMPT which
           short-circuited before context-sensitive logic ran.
           Second 'exit' was always returning CONFIG_PROMPT
           instead of EXEC_PROMPT.

  FIX C — _update_mode: extracted to standalone function,
           mirrors _prompt_for_cmd logic exactly, called
           AFTER command executes (not before).

  FIX D — connect_switch: added retry loop with configurable
           max_retries and retry_delay to handle EOF in
           transport thread and other transient SSH failures.

  FIX E — wait_for_ssh_ready: TCP port check before connecting
           ensures sshd is fully initialised before Netmiko
           attempts the SSH handshake.

  FIX F — Logging: UTF-8 encoding on all handlers to avoid
           UnicodeEncodeError on Windows cp1252 console.

Requirements:
  pip install netmiko paramiko

Usage:
  python sonic_bgp_1000_routes.py
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
# FIX F — LOGGING SETUP: UTF-8 safe for Windows and Linux
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
            f"sonic_bgp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
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
    "session_timeout":  600,        # FIX 3: keep alive during long config
    "hostname":         "sonic-sw1",
    "label":            "Switch1",
    "bgp_as":           65001,
    "bgp_router_id":    "1.1.1.1",
    "bgp_peer_ip":      "192.168.100.2",
    "bgp_peer_as":      65002,
    "bgp_interface":    "Ethernet0",
    "bgp_link_ip":      "192.168.100.1",
    "bgp_link_prefix":  "192.168.100.1/30",
    "bgp_link_mask":    "255.255.255.252",
    "loopback_ip":      "1.1.1.1",
    "loopback_prefix":  "1.1.1.1/32",
}

SWITCH2 = {
    "host":             "192.168.18.2",
    "port":             22,
    "device_type":      "linux",
    "username":         "admin",
    "password":         "admin",
    "timeout":          60,
    "auth_timeout":     30,
    "session_timeout":  600,        # FIX 3: keep alive during long config
    "hostname":         "sonic-sw2",
    "label":            "Switch2",
    "bgp_as":           65002,
    "bgp_router_id":    "2.2.2.2",
    "bgp_peer_ip":      "192.168.100.1",
    "bgp_peer_as":      65001,
    "bgp_interface":    "Ethernet0",
    "bgp_link_ip":      "192.168.100.2",
    "bgp_link_prefix":  "192.168.100.2/30",
    "bgp_link_mask":    "255.255.255.252",
    "loopback_ip":      "2.2.2.2",
    "loopback_prefix":  "2.2.2.2/32",
}

ROUTE_CONFIG = {
    "count":            10000,
    "start_network":    "10.0.0.0",
    "prefix_len":       24,
    "next_hop":         "blackhole",
    "batch_size":       50,
}


# ─────────────────────────────────────────────────────────────────
# FIX A — PROMPT PATTERNS: \s instead of $ anchor
#
# WHY: read_until_pattern has no re.MULTILINE flag.
#      $ means end-of-entire-string, not end-of-line.
#      Buffer is "sonic# \n" — # is NOT at end of string
#      so \S+#\s*$ never matches → 20s timeout every time.
#
# FIX: Use \s (whitespace) after # — matches the space or
#      newline that always follows the prompt immediately.
#      Pattern \w[\w-]*#\s is also specific enough to avoid
#      false matches on # characters inside command output.
# ─────────────────────────────────────────────────────────────────
# FIX H: patterns prefixed with \n so read_until_pattern only
# matches the prompt when it appears at the START OF A NEW LINE.
# Without \n the pattern can false-match inside FRR output text
# (e.g. "sonic(config-router)" appearing in a debug message body)
# causing the script to return too early with partial output or
# hang because the real prompt never matches after a false match
# consumed part of the buffer.
#
# NOTE: read_until_pattern includes the matched text in the return
# value, so the leading \n is consumed and does not appear in the
# cleaned output that callers see.
# FIX 1: replaced hardcoded "sonic" with \w[\w-]* so any hostname
# works (not just hostnames starting with "sonic"). The \n prefix
# is kept to anchor match to start of a new line, preventing false
# matches inside FRR output body text.
VTYSH_EXEC_PROMPT   = r"\n\w[\w-]*# "
VTYSH_CONFIG_PROMPT = r"\n\w[\w-]*\(config\)# "
VTYSH_ROUTER_PROMPT = r"\n\w[\w-]*\(config-router\)# "
VTYSH_AF_PROMPT     = r"\n\w[\w-]*\(config-router-af\)# "
VTYSH_IF_PROMPT     = r"\n\w[\w-]*\(config-if\)# "
VTYSH_ANY_PROMPT    = r"\n\w[\w-]*(?:\([^)]*\))?# "
SHELL_PROMPT        = r"\n[^@\s]+@\S+[#$] "


# ─────────────────────────────────────────────────────────────────
# HELPER — strip prompt lines from timing-based output
# ─────────────────────────────────────────────────────────────────
def _strip_prompt(output):
    """
    Remove SONiC shell prompt lines from send_command_timing output.
    Handles: admin@sonic:~$  ****@sonic:~$  root@sonic:/path#
    """
    cleaned = []
    for line in output.splitlines():
        if re.search(r"[^@\s]+@[^:]+:[^$#]*[$#]\s*", line):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


# ─────────────────────────────────────────────────────────────────
# run_cmd — timing-based, no pattern issues
# ─────────────────────────────────────────────────────────────────
def run_cmd(conn, command, label="", timeout=30):
    """
    Run a Linux shell command on SONiC using timing-based read.
    Avoids read_until_pattern entirely — no pattern errors.
    """
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
        log.error(
            "  [FAIL] [%s] run_cmd error '%s': %s",
            label, command[:60], str(e)
        )
        return ""


# ─────────────────────────────────────────────────────────────────
# run_vtysh — timing-based show commands
# ─────────────────────────────────────────────────────────────────
def run_vtysh(conn, vtysh_command, label="", timeout=60):
    """Run a FRR vtysh show/exec command via timing-based read."""
    # FIX 3: check socket before attempting command — avoids
    # confusing "Socket is closed" error messages in the log
    if not conn.is_alive():
        log.warning(
            "  [WARN] [%s] run_vtysh skipped — connection not alive",
            label,
        )
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
        log.error(
            "  [FAIL] [%s] run_vtysh error '%s': %s",
            label, vtysh_command[:60], str(e)
        )
        return ""


# ─────────────────────────────────────────────────────────────────
# run_cmd_timing — for SONiC config CLI commands
# ─────────────────────────────────────────────────────────────────
def run_cmd_timing(conn, command, label="", timeout=30):
    """Run SONiC config command with timing-based read."""
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
        log.error("  [FAIL] [%s] run_cmd_timing error: %s", label, str(e))
        return ""


# ─────────────────────────────────────────────────────────────────
# FIX B + C — _prompt_for_cmd and _update_mode
#
# FIX B: exit/end checked FIRST before MODE_MAP lookup.
#        Previously MODE_MAP had "exit"->VTYSH_CONFIG_PROMPT
#        which returned before the context-sensitive if-block
#        ran — so second 'exit' always got CONFIG_PROMPT wrong.
#
# FIX C: _update_mode is a standalone function called AFTER
#        the command executes, mirroring _prompt_for_cmd exactly.
# ─────────────────────────────────────────────────────────────────
def _prompt_for_cmd(cmd, current_mode):
    """
    Return expected vtysh prompt pattern AFTER this command runs.

    Order of evaluation:
      1. exit / end — context-sensitive, checked FIRST
      2. MODE_MAP   — fixed transitions, checked second
      3. Default    — stay in current mode

    Modes:
      exec   -> sonic#
      config -> sonic(config)#
      router -> sonic(config-router)#
      af     -> sonic(config-router-af)#
      iface  -> sonic(config-if)#        [FIX G]
    """
    cl = cmd.lower().strip()

    # ── 1. Context-sensitive commands — MUST be first ────────────
    if cl == "exit":
        if current_mode == "af":
            return VTYSH_ROUTER_PROMPT      # af     -> router
        elif current_mode == "router":
            return VTYSH_CONFIG_PROMPT      # router -> config
        elif current_mode == "iface":
            return VTYSH_CONFIG_PROMPT      # iface  -> config  [FIX G]
        elif current_mode == "config":
            return VTYSH_EXEC_PROMPT        # config -> exec
        else:
            return VTYSH_EXEC_PROMPT        # exec   -> exec (no-op)

    if cl == "end":
        return VTYSH_EXEC_PROMPT            # any depth -> exec always

    # ── 2. Fixed-transition commands via MODE_MAP ─────────────────
    MODE_MAP = {
        "configure terminal":  VTYSH_CONFIG_PROMPT,
        "router bgp":          VTYSH_ROUTER_PROMPT,
        "address-family":      VTYSH_AF_PROMPT,
        "exit-address-family": VTYSH_ROUTER_PROMPT,
        "interface":           VTYSH_IF_PROMPT,     # FIX G: interface X -> config-if
    }
    for keyword, prompt in MODE_MAP.items():
        if cl.startswith(keyword):
            return prompt

    # ── 3. All other commands — stay in current mode ──────────────
    mode_prompts = {
        "exec":   VTYSH_EXEC_PROMPT,
        "config": VTYSH_CONFIG_PROMPT,
        "router": VTYSH_ROUTER_PROMPT,
        "af":     VTYSH_AF_PROMPT,
        "iface":  VTYSH_IF_PROMPT,         # FIX G
    }
    return mode_prompts.get(current_mode, VTYSH_ANY_PROMPT)


def _update_mode(cmd, current_mode):
    """
    Return new mode string after command executes.
    Must mirror _prompt_for_cmd logic exactly.
    Called AFTER the command — not before.
    """
    cl = cmd.lower().strip()

    # ── 1. Context-sensitive — FIRST ─────────────────────────────
    if cl == "exit":
        if current_mode == "af":
            return "router"
        elif current_mode == "router":
            return "config"
        elif current_mode == "iface":
            return "config"             # iface -> config  [FIX G]
        elif current_mode == "config":
            return "exec"               # second exit -> exec
        else:
            return "exec"

    if cl == "end":
        return "exec"                   # always exec from any depth

    # ── 2. Fixed transitions ──────────────────────────────────────
    if cl == "configure terminal":      return "config"
    if cl.startswith("router bgp"):     return "router"
    if cl.startswith("address-family"): return "af"
    if cl == "exit-address-family":     return "router"
    if cl.startswith("interface"):      return "iface"   # FIX G

    # ── 3. No mode change ─────────────────────────────────────────
    return current_mode


# ─────────────────────────────────────────────────────────────────
# run_vtysh_config — interactive vtysh session with fixed prompts
# ─────────────────────────────────────────────────────────────────
def run_vtysh_config(conn, config_block, label=""):
    """
    Run a FRR vtysh configuration block interactively.
    Uses write_channel + read_until_pattern per command
    with correct per-mode prompt patterns (no $ anchor).
    """
    results      = []
    errors       = []
    current_mode = "exec"

    def _read_until(pattern, timeout=20):
        """
        Read until prompt pattern found in buffer.
        FIX H: if pattern not found within timeout, fall back to
        timing-based read so the script never hangs indefinitely.
        The timing fallback reads whatever is in the buffer after
        a short settle delay and returns it — the next command
        will then re-sync on the correct prompt.
        """
        try:
            out = conn.read_until_pattern(
                pattern=pattern,
                read_timeout=timeout,
            )
            return out.strip()
        except Exception as e:
            log.debug(
                "  [%s] read_until miss pattern='%s': %s — using timing fallback",
                label, pattern, str(e)[:60]
            )
            # Timing fallback — wait for output to settle then read all
            time.sleep(2.0)
            fallback = conn.read_channel()
            if fallback.strip():
                log.debug(
                    "  [%s] timing fallback got: ...%s",
                    label, fallback.strip()[-40:]
                )
            return fallback.strip()

    try:
        # ── Enter interactive vtysh ──────────────────────────────
        # FIX 1: Use broad pattern for initial entry — the first
        # prompt after "sudo vtysh" has NO leading \n (nothing
        # precedes it), so VTYSH_EXEC_PROMPT (which requires \n)
        # would never match. Use r"\w[\w-]*# " (no \n prefix)
        # for this first read only.
        conn.write_channel("sudo vtysh\n")
        time.sleep(1.5)
        init = _read_until(r"\w[\w-]*# ", timeout=15)
        log.debug("  [%s] vtysh entered: ...%s", label, init[-20:])

        # ── Send each command one at a time ──────────────────────
        for cmd in config_block:
            cmd = cmd.strip()
            if not cmd or cmd.startswith("!"):
                continue

            # Get expected prompt BEFORE updating mode  [FIX B]
            expected = _prompt_for_cmd(cmd, current_mode)

            log.debug(
                "  [%s] mode=%-8s  CMD: %-40s  expect: %s",
                label, current_mode, cmd, expected,
            )

            # Send command
            conn.write_channel(f"{cmd}\n")
            time.sleep(0.3)

            # Read until expected prompt
            out = _read_until(expected, timeout=20)

            # Update mode AFTER command executes  [FIX C]
            current_mode = _update_mode(cmd, current_mode)

            log.debug(
                "  [%s] mode now=%-8s  response: ...%s",
                label, current_mode, out[-40:],
            )

            results.append(f"[{cmd}]->{out[-60:]}")

            # Check for FRR errors in response
            if re.search(
                r"^%\s+(?:Unknown|Invalid|Incomplete)",
                out, re.MULTILINE,
            ):
                errors.append(cmd)
                log.warning(
                    "  [WARN] [%s] FRR rejected '%s': %s",
                    label, cmd, out[:100],
                )

        # ── Exit vtysh cleanly ───────────────────────────────────
        # Send 'end' to ensure we are at exec depth
        conn.write_channel("end\n")
        time.sleep(0.3)
        _read_until(VTYSH_EXEC_PROMPT, timeout=10)

        # Exit to Linux shell
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
        log.warning(
            "  [WARN] [%s] %d FRR error(s): %s",
            label, len(errors), errors,
        )
    else:
        log.debug("  [OK] [%s] All config commands accepted", label)

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
            f"{ipaddress.IPv4Address(next_addr)}/{prefix_len}",
            strict=False,
        )
    log.info(
        "Generated %d routes: %s/%d -> %s/%d",
        count, routes[0], prefix_len, routes[-1], prefix_len,
    )
    return routes


# ─────────────────────────────────────────────────────────────────
# FIX E — wait_for_ssh_ready: TCP + SSH banner check
# ─────────────────────────────────────────────────────────────────
def wait_for_ssh_ready(host, port=22, max_wait=180,
                       check_interval=10, label=""):
    """
    Wait until SSH is fully ready on the switch.
    Checks TCP port open AND SSH banner present.
    Prevents EOF in transport thread on fast connection attempts.
    """
    log.info("%s: Waiting for SSH on %s:%d...", label, host, port)
    start  = time.time()
    opened = False

    while time.time() - start < max_wait:
        elapsed = int(time.time() - start)
        try:
            # Step 1 — TCP port open?
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()

            if not opened:
                log.info("  [%3ds] TCP port %d open on %s", elapsed, port, host)
                opened = True
                # Extra settle — sshd may not be fully ready yet
                log.info("  Waiting 10s for SSH daemon to initialise...")
                time.sleep(10)

            # Step 2 — SSH banner present?
            try:
                sock2   = socket.create_connection((host, port), timeout=5)
                banner  = sock2.recv(256)
                sock2.close()
                if b"SSH" in banner:
                    log.info(
                        "  [OK] SSH ready on %s:%d after %ds",
                        host, port, elapsed,
                    )
                    return True
            except Exception:
                pass

        except (socket.timeout, ConnectionRefusedError, OSError):
            log.info(
                "  [%3ds] %s:%d not ready yet...", elapsed, host, port
            )

        time.sleep(check_interval)

    log.warning("  [WARN] SSH not ready on %s:%d after %ds", host, port, max_wait)
    return False


# ─────────────────────────────────────────────────────────────────
# FIX D — connect_switch: retry loop for transient SSH failures
# ─────────────────────────────────────────────────────────────────
def connect_switch(device, label,
                   max_retries=10,
                   retry_delay=15,
                   connect_timeout=60):
    """
    Connect to SONiC switch via SSH with automatic retry.
    Handles: EOF in transport, connection refused, timeout.
    Auth failures exit immediately — no point retrying.
    """
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
        # FIX 2: SSH keepalive prevents server closing idle connection
        # while the other switch is being configured (can take minutes)
        "keepalive":       60,   # send keepalive every 60 seconds
    }

    last_error = None

    for attempt in range(1, max_retries + 1):
        log.info(
            "Connecting to %s (%s) attempt %d/%d...",
            label, device["host"], attempt, max_retries,
        )
        try:
            conn = ConnectHandler(**conn_params)
            log.info(
                "  [OK] Connected to %s (attempt %d/%d)",
                label, attempt, max_retries,
            )
            return conn

        except NetmikoAuthenticationException as e:
            log.error(
                "  [FAIL] Auth failed on %s — check credentials: %s",
                label, str(e)
            )
            sys.exit(1)

        except NetmikoTimeoutException as e:
            last_error = e
            log.warning(
                "  [WARN] Timeout on %s attempt %d/%d: %s",
                label, attempt, max_retries, str(e)[:80]
            )

        except Exception as e:
            last_error = e
            err = str(e).lower()
            if "eof"               in err: reason = "EOF in transport (SSH not ready)"
            elif "refused"         in err: reason = "Connection refused (sshd starting)"
            elif "timed out"       in err: reason = "Connection timed out"
            elif "no route"        in err: reason = "Network unreachable"
            else:                          reason = str(e)[:80]
            log.warning(
                "  [WARN] [%s] attempt %d/%d: %s",
                label, attempt, max_retries, reason,
            )

        if attempt < max_retries:
            log.info(
                "  Retrying in %ds (%d attempts left)...",
                retry_delay, max_retries - attempt,
            )
            time.sleep(retry_delay)

    log.error(
        "  [FAIL] Could not connect to %s after %d attempts. Last: %s",
        label, max_retries, str(last_error)[:120],
    )
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────
# INTERFACE CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def configure_interface(conn, device, label):
    """Configure BGP link interface on SONiC."""
    log.info("\n%s: Configuring interface %s...",
             label, device["bgp_interface"])

    iface  = device["bgp_interface"]
    prefix = device["bgp_link_prefix"]
    ip     = device["bgp_link_ip"]

    existing = run_cmd(
        conn, f"ip addr show {iface} | grep {ip}", label, timeout=15
    )

    if ip in existing:
        log.info("  [OK] %s already has IP %s", iface, prefix)
    else:
        run_cmd_timing(
            conn,
            f"sudo config interface ip remove {iface} {prefix}"
            f" 2>/dev/null || true",
            label,
        )
        time.sleep(1)
        run_cmd_timing(
            conn,
            f"sudo config interface ip add {iface} {prefix}",
            label,
        )
        time.sleep(2)
        log.info("  [OK] IP %s added to %s", prefix, iface)

    run_cmd_timing(conn, f"sudo config interface startup {iface}", label)
    time.sleep(1)

    # show interface EthernetX is a vtysh/FRR command, not Linux shell
    verify = run_vtysh(conn, f"show interface {iface}", label, timeout=15)
    log.info("  Interface status:\n%s", verify[:300])


def configure_loopback(conn, device, label):
    """Configure loopback with multi-method fallback."""
    log.info("%s: Configuring loopback...", label)

    lb_prefix = device["loopback_prefix"]
    lb_ip     = device["loopback_ip"]

    existing = run_cmd(
        conn, f"ip addr show Loopback0 | grep {lb_ip}", label, timeout=15
    )
    if lb_ip in existing:
        log.info("  [OK] Loopback0 already has IP %s", lb_prefix)
        return

    # Method 1 — SONiC config CLI
    out = run_cmd_timing(
        conn,
        f"sudo config interface ip add Loopback0 {lb_prefix}",
        label,
    )
    time.sleep(1)

    # Method 2 — redis-cli if SONiC CLI rejected
    if "invalid" in out.lower() or "error" in out.lower():
        log.warning("  [WARN] SONiC CLI rejected Loopback0 — trying redis...")
        run_cmd_timing(
            conn,
            'sudo redis-cli -n 4 HSET "LOOPBACK_INTERFACE|Loopback0"'
            ' "NULL" "NULL"',
            label,
        )
        run_cmd_timing(
            conn,
            f'sudo redis-cli -n 4 HSET '
            f'"LOOPBACK_INTERFACE|Loopback0|{lb_prefix}" "scope" "global"',
            label,
        )
        time.sleep(2)
        run_cmd_timing(
            conn,
            f"sudo config interface ip add Loopback0 {lb_prefix}",
            label,
        )
        time.sleep(1)

    # Method 3 — Linux ip command + FRR vtysh for persistence
    verify = run_cmd(
        conn, f"ip addr show Loopback0 | grep {lb_ip}", label, timeout=15
    )
    if lb_ip not in verify:
        log.warning("  [WARN] Falling back to Linux ip command...")
        run_cmd_timing(conn, "sudo ip link set Loopback0 up", label)
        run_cmd_timing(
            conn, f"sudo ip addr add {lb_prefix} dev Loopback0", label
        )
        run_vtysh_config(conn, [
            "configure terminal",
            "interface Loopback0",
            f"ip address {lb_prefix}",
            "end",
        ], label)

    # Final verify
    time.sleep(1)
    verify = run_cmd(
        conn, f"ip addr show Loopback0 | grep {lb_ip}", label, timeout=15
    )
    if lb_ip in verify:
        log.info("  [OK] Loopback0 IP %s confirmed", lb_prefix)
    else:
        log.error("  [FAIL] Loopback0 IP %s NOT configured!", lb_prefix)


# ─────────────────────────────────────────────────────────────────
# BGP CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def configure_bgp_switch1(conn, device, label):
    """Configure FRR BGP on Switch 1 — redistributes static routes."""
    log.info("\n%s: Configuring FRR BGP (AS %d)...", label, device["bgp_as"])

    config_block = [
        "configure terminal",
        f"router bgp {device['bgp_as']}",
        f"bgp router-id {device['bgp_router_id']}",
        "bgp log-neighbor-changes",
        f"neighbor {device['bgp_peer_ip']} remote-as {device['bgp_peer_as']}",
        f"neighbor {device['bgp_peer_ip']} description eBGP-to-Switch2",
        f"neighbor {device['bgp_peer_ip']} timers 10 30",
        f"neighbor {device['bgp_peer_ip']} timers connect 10",
        "address-family ipv4 unicast",
        f"neighbor {device['bgp_peer_ip']} activate",
        "redistribute static",
        "redistribute connected",
        "exit-address-family",
        "exit",   # router -> config
        "exit",   # config -> exec   [FIX B ensures EXEC_PROMPT here]
    ]

    output = run_vtysh_config(conn, config_block, label)
    log.info("  vtysh_config result:\n%s", output[:300] if output else "")
    time.sleep(2)

    verify = run_vtysh(conn, "show running-config", label)
    if f"router bgp {device['bgp_as']}" in verify:
        log.info("  [OK] BGP AS %d confirmed in FRR", device["bgp_as"])
    else:
        log.warning("  [WARN] BGP config not confirmed — check vtysh manually")

    return output


def configure_bgp_switch2(conn, device, label):
    """Configure FRR BGP on Switch 2 — receives routes from Switch 1."""
    log.info("\n%s: Configuring FRR BGP (AS %d)...", label, device["bgp_as"])

    config_block = [
        "configure terminal",
        f"router bgp {device['bgp_as']}",
        f"bgp router-id {device['bgp_router_id']}",
        "bgp log-neighbor-changes",
        f"neighbor {device['bgp_peer_ip']} remote-as {device['bgp_peer_as']}",
        f"neighbor {device['bgp_peer_ip']} description eBGP-to-Switch1",
        f"neighbor {device['bgp_peer_ip']} timers 10 30",
        f"neighbor {device['bgp_peer_ip']} timers connect 10",
        f"neighbor {device['bgp_peer_ip']} maximum-prefix 15000 80 warning-only",
        "address-family ipv4 unicast",
        f"neighbor {device['bgp_peer_ip']} activate",
        # FIX I: soft-reconfiguration inbound required so FRR stores
        # a copy of received routes in its Adj-RIB-In table.
        # Without this, "show bgp neighbors x received-routes" returns:
        #   "% Inbound soft reconfiguration not enabled"
        # It also allows "clear bgp soft in" without tearing down session.
        f"neighbor {device['bgp_peer_ip']} soft-reconfiguration inbound",
        "exit-address-family",
        "exit",   # router -> config
        "exit",   # config -> exec
    ]

    output = run_vtysh_config(conn, config_block, label)
    log.info("  vtysh_config result:\n%s", output[:300] if output else "")
    time.sleep(2)

    verify = run_vtysh(conn, "show running-config", label)
    if f"router bgp {device['bgp_as']}" in verify:
        log.info("  [OK] BGP AS %d confirmed in FRR", device["bgp_as"])
    else:
        log.warning("  [WARN] BGP config not confirmed — check vtysh manually")

    return output


# ─────────────────────────────────────────────────────────────────
# STATIC ROUTES — single interactive vtysh session
# ─────────────────────────────────────────────────────────────────
def configure_static_routes(conn, routes, prefix_len, label):
    """
    Configure 1000 static routes in one interactive vtysh session.
    Uses VTYSH_ANY_PROMPT (no $ anchor) for reliable detection.
    """
    log.info("\n%s: Configuring %d static routes...", label, len(routes))

    total  = len(routes)
    report = 100
    errors = 0

    def _read_any_prompt(timeout=10):
        """Read until any vtysh prompt — \\s not $ anchor."""
        try:
            return conn.read_until_pattern(
                pattern=VTYSH_ANY_PROMPT,
                read_timeout=timeout,
            )
        except Exception:
            time.sleep(0.3)
            return conn.read_channel()

    try:
        # Enter vtysh — use broad pattern (no \n prefix) for first prompt
        conn.write_channel("sudo vtysh\n")
        time.sleep(1.5)
        try:
            conn.read_until_pattern(pattern=r"\w[\w-]*# ", read_timeout=15)
        except Exception:
            conn.read_channel()

        # Enter configure terminal
        conn.write_channel("configure terminal\n")
        time.sleep(0.3)
        _read_any_prompt(timeout=10)

        # Send all routes
        for i, network in enumerate(routes, 1):
            conn.write_channel(f"ip route {network}/{prefix_len} blackhole\n")

            # Drain buffer every 10 commands
            if i % 10 == 0:
                time.sleep(0.2)
                out = conn.read_channel()
                if "%" in out and "unknown" in out.lower():
                    errors += 1
                    log.warning(
                        "  [WARN] [%s] Route error at #%d: %s",
                        label, i, out.strip()[:80]
                    )

            if i % report == 0 or i == total:
                log.info(
                    "  Progress: %d/%d (%.0f%%)  errors=%d",
                    i, total, (i / total) * 100, errors,
                )

        # Flush buffer
        time.sleep(0.5)
        conn.read_channel()

        # end + write memory + exit
        conn.write_channel("end\n")
        time.sleep(0.3)
        _read_any_prompt(timeout=10)

        conn.write_channel("write memory\n")
        time.sleep(3)
        try:
            conn.read_until_pattern(
                pattern=r"(?:Build|OK|saved|written)",
                read_timeout=30,
            )
        except Exception:
            conn.read_channel()

        conn.write_channel("exit\n")
        time.sleep(0.5)
        try:
            conn.read_until_pattern(pattern=SHELL_PROMPT, read_timeout=10)
        except Exception:
            conn.read_channel()

        log.info(
            "  [OK] [%s] %d static routes configured (errors=%d)",
            label, total, errors,
        )

    except Exception as e:
        log.error("  [FAIL] [%s] Static route error: %s", label, str(e))
        try:
            conn.write_channel("end\nexit\n")
            time.sleep(1)
            conn.read_channel()
        except Exception:
            pass

    # Verify count
    time.sleep(2)
    verify = run_vtysh(conn, "show ip route static", label, timeout=60)
    static_count = sum(1 for l in verify.splitlines() if l.startswith("S"))
    log.info("  Static routes confirmed in FRR: %d", static_count)


# ─────────────────────────────────────────────────────────────────
# SAVE CONFIGURATION
# ─────────────────────────────────────────────────────────────────
def save_frr_config(conn, label):
    """Save FRR config to /etc/frr/frr.conf and SONiC config."""
    log.info("%s: Saving configuration...", label)
    output = run_vtysh(conn, "write memory", label)
    time.sleep(2)
    run_cmd_timing(conn, "sudo config save -y", label, timeout=30)
    time.sleep(2)
    log.info("  [OK] Config saved on %s", label)
    return output


# ─────────────────────────────────────────────────────────────────
# BGP CONVERGENCE WAIT
# ─────────────────────────────────────────────────────────────────
def wait_for_bgp_convergence(conn2, device2,
                              expected_routes=10000, max_wait=600):
    """
    Poll Switch 2 until all BGP routes are received.

    FIX 2: Three improvements:
      a) Check conn2.is_alive() before every poll — if socket is
         closed exit immediately with clear error instead of
         looping for max_wait minutes printing "Unknown/0".
      b) Attempt one reconnect if socket drops during polling
         so a brief TCP drop does not abort the whole wait.
      c) Reduce poll interval to 10s (was 15s) for faster detection.
    """
    log.info("\n" + "-" * 50)
    log.info("Waiting for BGP convergence (max %ds)...", max_wait)
    log.info("-" * 50)

    start_time     = time.time()
    interval       = 10
    reconnect_done = False          # attempt reconnect once only

    while time.time() - start_time < max_wait:
        elapsed = int(time.time() - start_time)

        # ── FIX 2a/2b — socket liveness check ───────────────────
        if not conn2.is_alive():
            if not reconnect_done:
                log.warning(
                    "  [WARN] [%3ds] Switch2 socket closed — "
                    "attempting reconnect...", elapsed
                )
                try:
                    conn2.disconnect()
                except Exception:
                    pass
                try:
                    conn2 = connect_switch(
                        device2, device2["label"],
                        max_retries=5, retry_delay=10,
                        connect_timeout=30,
                    )
                    reconnect_done = True
                    log.info("  [OK] Reconnected to Switch2")
                except Exception as e:
                    log.error(
                        "  [FAIL] Reconnect failed: %s — "
                        "aborting convergence wait", str(e)
                    )
                    return False
            else:
                log.error(
                    "  [FAIL] [%3ds] Switch2 socket closed again "
                    "after reconnect — aborting", elapsed
                )
                return False

        # ── Poll BGP summary ─────────────────────────────────────
        summary_text = run_vtysh(
            conn2, "show bgp ipv4 unicast summary", "Switch2"
        )

        # Detect socket error in output
        if "socket is closed" in summary_text.lower() or            "error" in summary_text.lower() and not summary_text.strip():
            log.warning(
                "  [WARN] [%3ds] BGP summary returned error: %s",
                elapsed, summary_text[:80]
            )
            time.sleep(interval)
            continue

        prefixes_received = 0
        peer_state        = "Unknown"

        for line in summary_text.splitlines():
            if SWITCH1["bgp_link_ip"] in line:
                parts = line.split()
                if len(parts) >= 9:
                    peer_state = parts[8] if len(parts) > 8 else "?"
                    try:
                        prefixes_received = int(parts[-1])
                    except ValueError:
                        peer_state = parts[-1]

        log.info(
            "  [%3ds] Peer: %-15s | State: %-12s | Prefixes: %d/%d",
            elapsed, SWITCH1["bgp_link_ip"],
            peer_state, prefixes_received, expected_routes,
        )

        if prefixes_received >= expected_routes:
            log.info(
                "  [OK] BGP converged! %d routes after %ds",
                prefixes_received, elapsed,
            )
            return True
        elif prefixes_received > 0:
            log.info(
                "  [WAIT] Partial: %d/%d routes...",
                prefixes_received, expected_routes,
            )

        time.sleep(interval)

    log.warning("  [WARN] Convergence timeout after %ds", max_wait)
    return False


# ─────────────────────────────────────────────────────────────────
# VERIFICATION — SWITCH 1
# ─────────────────────────────────────────────────────────────────
def verify_switch1(conn, device):
    """Run verification commands on Switch 1."""
    label = device["label"]
    log.info("\n" + "=" * 60)
    log.info("SWITCH 1 VERIFICATION (%s)", device["host"])
    log.info("=" * 60)

    log.info("\n[SW1] BGP Summary:")
    out = run_vtysh(conn, "show bgp ipv4 unicast summary", label)
    log.info("\n%s", out)

    log.info("\n[SW1] BGP best path count:")
    out2 = run_vtysh(conn, "show bgp ipv4 unicast", label)
    best = sum(1 for l in out2.splitlines() if l.strip().startswith("*>"))
    log.info("  Best paths: %d", best)

    log.info("\n[SW1] Static routes in FRR:")
    out3 = run_vtysh(conn, "show ip route static", label, timeout=60)
    static_count = sum(1 for l in out3.splitlines() if l.startswith("S"))
    log.info("  Static route entries: %d", static_count)

    log.info("\n[SW1] First 10 BGP routes:")
    lines = [l for l in out2.splitlines() if "*>" in l][:10]
    for line in lines:
        log.info("  %s", line)
    log.info("  ... (first 10 of 1000)")

    log.info("\n[SW1] Route detail 10.0.0.0/24:")
    out = run_vtysh(conn, "show bgp ipv4 unicast 10.0.0.0/24", label)
    log.info("\n%s", out)

    log.info("\n[SW1] Advertised to Switch 2 (first 10):")
    out = run_vtysh(
        conn,
        f"show bgp ipv4 unicast neighbors"
        f" {device['bgp_peer_ip']} advertised-routes",
        label, timeout=60,
    )
    lines = [l for l in out.splitlines() if "*>" in l][:10]
    for line in lines:
        log.info("  %s", line)
    log.info("  Total advertised: %d",
             sum(1 for l in out.splitlines() if "*>" in l))

    log.info("\n[SW1] Interface status:")
    # "show interface status" is a SONiC CLI cmd — run via Linux shell
    # It lists all interfaces with speed/oper/admin status columns
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

    log.info("\n[SW2] BGP Summary:")
    out = run_vtysh(conn, "show bgp ipv4 unicast summary", label)
    log.info("\n%s", out)

    log.info("\n[SW2] Total BGP routes received:")
    out2 = run_vtysh(conn, "show bgp ipv4 unicast", label)
    best = sum(1 for l in out2.splitlines() if l.strip().startswith("*>"))
    log.info("  Best paths: %d", best)

    log.info("\n[SW2] First 10 routes received:")
    lines = [l for l in out2.splitlines() if "*>" in l][:10]
    for line in lines:
        log.info("  %s", line)
    log.info("  ... (first 10 of 1000)")

    log.info("\n[SW2] Last route (10.39.15.0/24):")
    out = run_vtysh(conn, "show bgp ipv4 unicast 10.39.15.0/24", label)
    log.info("\n%s", out)

    log.info("\n[SW2] Middle route ~5000th (10.19.135.0/24):")
    out = run_vtysh(conn, "show bgp ipv4 unicast 10.19.135.0/24", label)
    log.info("\n%s", out)

    log.info("\n[SW2] IP route summary:")
    out = run_vtysh(conn, "show ip route summary", label)
    log.info("\n%s", out)

    log.info("\n[SW2] BGP routes in FRR routing table (first 10):")
    # ip route show proto bgp does not work on SONiC — FRR manages
    # BGP routes internally. Use vtysh show ip route | grep ^B instead.
    out = run_vtysh(conn, "show ip route", label, timeout=60)
    bgp_lines = [l for l in out.splitlines() if l.startswith("B")][:10]
    log.info("\n%s", "\n".join(bgp_lines))

    out_count = len([l for l in out.splitlines() if l.startswith("B")])
    log.info("  Total BGP routes in FRR table: %d", out_count)

    log.info("\n[SW2] Received from Switch 1 (first 10):")
    out = run_vtysh(
        conn,
        f"show bgp ipv4 unicast neighbors"
        f" {device['bgp_peer_ip']} received-routes",
        label, timeout=60,
    )
    lines = [l for l in out.splitlines() if "*>" in l][:10]
    for line in lines:
        log.info("  %s", line)

    log.info("\n[SW2] Interface status:")
    # "show interface status" is a SONiC CLI cmd — run via Linux shell
    out = run_cmd_timing(conn, "show interface status", label, timeout=30)
    log.info("\n%s", out[:500])


# ─────────────────────────────────────────────────────────────────
# CLI REFERENCE
# ─────────────────────────────────────────────────────────────────
def print_cli_reference():
    """Print SONiC/FRR CLI reference."""
    log.info("\n" + "=" * 60)
    log.info("SONIC/FRR CLI REFERENCE")
    log.info("=" * 60)
    log.info("""
+-------------------------------------------------------------+
|  SWITCH 1 -- BGP Originator                                 |
+-------------------------------------------------------------+
|  vtysh -c "show bgp ipv4 unicast summary"                  |
|  vtysh -c "show bgp ipv4 unicast" | grep "^*>" | wc -l    |
|  vtysh -c "show ip route static"  | grep "^S"  | wc -l    |
|  vtysh -c "show bgp ipv4 unicast 10.0.0.0/24"             |
|  vtysh -c "show bgp ipv4 unicast neighbors                 |
|             192.168.100.2 advertised-routes"               |
+-------------------------------------------------------------+
|  SWITCH 2 -- BGP Receiver                                   |
+-------------------------------------------------------------+
|  vtysh -c "show bgp ipv4 unicast summary"                  |
|  vtysh -c "show bgp ipv4 unicast" | grep "^*>" | wc -l    |
|  vtysh -c "show bgp ipv4 unicast 10.39.15.0/24"           |
|  vtysh -c "show bgp ipv4 unicast neighbors                 |
|             192.168.100.1 received-routes"                 |
|  sudo vtysh -c "show ip route" | grep "^B" | wc -l        |
+-------------------------------------------------------------+
|  BOTH SWITCHES                                              |
+-------------------------------------------------------------+
|  sudo systemctl status frr                                  |
|  sudo tail -f /var/log/frr/bgpd.log                       |
|  ping 192.168.100.1 -c 4    (from SW2)                    |
|  ping 192.168.100.2 -c 4    (from SW1)                    |
+-------------------------------------------------------------+
""")


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    start_time = time.time()

    log.info("=" * 60)
    log.info("  SONiC BGP 1000 Routes Generator  (v3)")
    log.info("  Switch 1: %s (AS %d)", SWITCH1["host"], SWITCH1["bgp_as"])
    log.info("  Switch 2: %s (AS %d)", SWITCH2["host"], SWITCH2["bgp_as"])
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
    wait_for_ssh_ready(
        SWITCH1["host"], port=SWITCH1["port"],
        max_wait=180, check_interval=10, label=SWITCH1["label"],
    )
    wait_for_ssh_ready(
        SWITCH2["host"], port=SWITCH2["port"],
        max_wait=180, check_interval=10, label=SWITCH2["label"],
    )

    # Step 3 — Connect with retry
    log.info("\n[STEP 3] Connecting to switches...")
    conn1 = connect_switch(
        SWITCH1, SWITCH1["label"],
        max_retries=10, retry_delay=15, connect_timeout=60,
    )
    conn2 = connect_switch(
        SWITCH2, SWITCH2["label"],
        max_retries=10, retry_delay=15, connect_timeout=60,
    )

    try:
        # Step 4 — Configure Switch 2
        log.info("\n[STEP 4] Configuring Switch 2...")
        configure_loopback(conn2, SWITCH2, SWITCH2["label"])
        configure_interface(conn2, SWITCH2, SWITCH2["label"])
        configure_bgp_switch2(conn2, SWITCH2, SWITCH2["label"])
        save_frr_config(conn2, SWITCH2["label"])

        # Step 5 — Configure Switch 1 interfaces
        log.info("\n[STEP 5] Configuring Switch 1 interfaces...")
        configure_loopback(conn1, SWITCH1, SWITCH1["label"])
        configure_interface(conn1, SWITCH1, SWITCH1["label"])

        # Step 6 — Configure Switch 1 BGP
        log.info("\n[STEP 6] Configuring Switch 1 BGP...")
        configure_bgp_switch1(conn1, SWITCH1, SWITCH1["label"])

        # Step 7 — Push 1000 static routes
        log.info("\n[STEP 7] Pushing 1000 static routes...")
        configure_static_routes(
            conn1, routes,
            ROUTE_CONFIG["prefix_len"],
            SWITCH1["label"],
        )
        save_frr_config(conn1, SWITCH1["label"])

        # Step 8 — Verify L3 connectivity
        log.info("\n[STEP 8] Verifying L3 connectivity...")
        ping_out = run_cmd(
            conn1,
            f"ping -c 4 -W 2 {SWITCH2['bgp_link_ip']}",
            SWITCH1["label"], timeout=20,
        )
        if "0% packet loss" in ping_out:
            log.info("  [OK] L3 connectivity confirmed")
        else:
            log.warning("  [WARN] Ping check failed — verify interfaces")
        log.info("  %s", ping_out[:200])

        # Step 9 — Wait for BGP convergence
        log.info("\n[STEP 9] Waiting for BGP convergence...")
        converged = wait_for_bgp_convergence(
            conn2,
            device2=SWITCH2,
            expected_routes=ROUTE_CONFIG["count"],
            max_wait=600,
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
        log.info("  Converged: %s", "[OK] YES" if converged else "[WARN] CHECK")
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
