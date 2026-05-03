"""
Quarantine helpers for DOME Network Defense System

REAL NETWORK ISOLATION:
- Linux Gateway Mode: iptables enforcement (blocks at network layer)
- Safe Mode (default): Simulated enforcement (logs only)

Configuration via backend/config.py:
- settings.safe_mode (default: true)
- settings.gateway_mode (default: false)

Real enforcement requires:
1. settings.safe_mode=false
2. settings.gateway_mode=true
3. Linux OS
4. Root privileges (os.geteuid() == 0)

All enforcement actions are logged to logs/enforcement.log
"""

import subprocess
import platform
import os
import logging
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path
from ..config import settings

# Configure enforcement logger
ENFORCEMENT_LOG_DIR = Path("logs")
ENFORCEMENT_LOG_DIR.mkdir(exist_ok=True)
enforcement_logger = logging.getLogger("avighna.enforcement")
enforcement_logger.setLevel(logging.INFO)
if not enforcement_logger.handlers:
    handler = logging.FileHandler(ENFORCEMENT_LOG_DIR / "enforcement.log")
    handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    ))
    enforcement_logger.addHandler(handler)


def _can_enforce() -> tuple[bool, str]:
    """
    Check if real enforcement is allowed.
    
    Returns:
        (can_enforce: bool, reason: str)
    """
    if settings.safe_mode:
        return (False, "safe_mode=true (enforcement disabled)")
    
    if not settings.gateway_mode:
        return (False, "gateway_mode=false (not running as gateway)")
    
    system = platform.system()
    if system not in ["Linux", "Windows"]:
        return (False, f"OS={system} (only Linux/Windows supported)")
    
    # Check privileges based on OS
    if system == "Linux":
        if os.geteuid() != 0:
            return (False, "Not running as root (UID != 0)")
    elif system == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return (False, "Not running as Administrator")
        except Exception:
            return (False, "Cannot verify Administrator privileges")
    
    return (True, "All enforcement requirements met")


def _rule_exists(chain: str, ip: str, comment: str) -> bool:
    """
    Check if iptables rule already exists (Linux only).
    
    Args:
        chain: iptables chain (INPUT, FORWARD)
        ip: IP address to check
        comment: Rule comment to match
    
    Returns:
        True if rule exists, False otherwise
    """
    try:
        # Use iptables -C to check if rule exists
        cmd = [
            "iptables", "-C", chain,
            "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", comment
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def _windows_rule_exists(rule_name: str) -> bool:
    """
    Check if Windows Firewall rule already exists.
    
    Args:
        rule_name: Firewall rule name to check
    
    Returns:
        True if rule exists, False otherwise
    """
    try:
        cmd = [
            "powershell", "-Command",
            f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.returncode == 0 and result.stdout.strip() != ""
    except Exception:
        return False


def enforce_block_ip(device_id: str, ip: str) -> Dict[str, Any]:
    """
    REAL ENFORCEMENT: Block device IP using OS-specific firewall.
    
    Linux: iptables (FORWARD + INPUT chains)
    Windows: New-NetFirewallRule (inbound + outbound, all profiles)
    
    Rules are idempotent (checks before adding).
    
    Args:
        device_id: Device identifier for logging/tagging
        ip: IP address to block
    
    Returns:
        dict with action, status, commands, and result details
    """
    timestamp = datetime.utcnow().isoformat()
    can_enforce, reason = _can_enforce()
    system = platform.system()
    
    result = {
        "action": "enforce_block_ip",
        "device_id": device_id,
        "ip": ip,
        "os": system,
        "timestamp": timestamp,
        "status": "simulated" if not can_enforce else "pending",
        "reason": reason,
        "commands": [],
        "rules_added": []
    }
    
    print(f"\n{'='*60}")
    print(f"🚨 QUARANTINE ACTION: Blocking IP {ip}")
    print(f"   Device: {device_id}")
    print(f"   OS: {system}")
    print(f"   Mode: {'REAL ENFORCEMENT' if can_enforce else 'SIMULATED'}")
    print(f"   Reason: {reason}")
    print(f"{'='*60}")
    
    if system == "Linux":
        return _enforce_block_ip_linux(device_id, ip, can_enforce, result)
    elif system == "Windows":
        return _enforce_block_ip_windows(device_id, ip, can_enforce, result)
    else:
        result["status"] = "unsupported"
        result["error"] = f"OS {system} not supported"
        print(f"❌ FAILED: Unsupported OS\n")
        return result


def _enforce_block_ip_linux(device_id: str, ip: str, can_enforce: bool, result: Dict[str, Any]) -> Dict[str, Any]:
    """Linux-specific IP blocking using iptables."""
    comment = f"AVIGHNA:{device_id}"
    
    # Define iptables rules
    rules = [
        {
            "chain": "FORWARD",
            "description": "Block forwarded traffic (LAN/WAN)",
            "cmd": [
                "iptables", "-A", "FORWARD",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", comment
            ]
        },
        {
            "chain": "INPUT",
            "description": "Block direct access to gateway",
            "cmd": [
                "iptables", "-A", "INPUT",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", comment
            ]
        }
    ]
    
    if not can_enforce:
        # SIMULATED MODE: Log commands that would be executed
        for rule in rules:
            cmd_str = " ".join(rule["cmd"])
            result["commands"].append(cmd_str)
            print(f"[SIMULATED] {rule['description']}")
            print(f"            {cmd_str}")
            enforcement_logger.info(
                f"SIMULATED | device_id={device_id} | ip={ip} | "
                f"action=block | chain={rule['chain']} | command={cmd_str}"
            )
        result["status"] = "simulated"
        print(f"✓ Block action: SIMULATED (safe mode)\n")
        return result
    
    # REAL ENFORCEMENT MODE
    try:
        for rule in rules:
            chain = rule["chain"]
            cmd = rule["cmd"]
            cmd_str = " ".join(cmd)
            result["commands"].append(cmd_str)
            
            # Check if rule already exists (idempotent)
            if _rule_exists(chain, ip, comment):
                print(f"[SKIP] Rule already exists: {chain} chain for {ip}")
                enforcement_logger.info(
                    f"SKIP | device_id={device_id} | ip={ip} | "
                    f"action=block | chain={chain} | reason=rule_exists"
                )
                result["rules_added"].append(f"{chain} (already exists)")
                continue
            
            # Execute iptables command
            print(f"[EXECUTING] {rule['description']}")
            print(f"            {cmd_str}")
            
            exec_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if exec_result.returncode == 0:
                result["rules_added"].append(f"{chain} (success)")
                enforcement_logger.info(
                    f"SUCCESS | device_id={device_id} | ip={ip} | "
                    f"action=block | chain={chain} | command={cmd_str}"
                )
                print(f"✅ SUCCESS: {chain} rule added")
            else:
                error_msg = exec_result.stderr.strip()
                result["rules_added"].append(f"{chain} (failed: {error_msg})")
                enforcement_logger.error(
                    f"FAILED | device_id={device_id} | ip={ip} | "
                    f"action=block | chain={chain} | error={error_msg}"
                )
                print(f"❌ FAILED: {chain} rule - {error_msg}")
                result["status"] = "partial_failure"
        
        # If we got here without partial_failure, it's success
        if result["status"] != "partial_failure":
            result["status"] = "enforced"
        
        print(f"✓ Block action: {result['status'].upper()}\n")
        
    except subprocess.TimeoutExpired:
        result["status"] = "failed"
        result["error"] = "Command timeout"
        enforcement_logger.error(
            f"TIMEOUT | device_id={device_id} | ip={ip} | action=block"
        )
        print(f"❌ FAILED: Command timeout\n")
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        enforcement_logger.error(
            f"ERROR | device_id={device_id} | ip={ip} | "
            f"action=block | error={str(e)}"
        )
        print(f"❌ FAILED: {str(e)}\n")
    
    return result


def _enforce_block_ip_windows(device_id: str, ip: str, can_enforce: bool, result: Dict[str, Any]) -> Dict[str, Any]:
    """Windows-specific IP blocking using Windows Firewall."""
    rule_name_in = f"AVIGHNA:{device_id}:{ip}:IN"
    rule_name_out = f"AVIGHNA:{device_id}:{ip}:OUT"
    
    # Define Windows Firewall rules
    rules = [
        {
            "direction": "Inbound",
            "rule_name": rule_name_in,
            "description": "Block inbound traffic from device",
            "cmd": [
                "powershell", "-Command",
                f"New-NetFirewallRule -DisplayName '{rule_name_in}' "
                f"-Direction Inbound -Action Block "
                f"-RemoteAddress {ip} "
                f"-Profile Domain,Private,Public "
                f"-Enabled True"
            ]
        },
        {
            "direction": "Outbound",
            "rule_name": rule_name_out,
            "description": "Block outbound traffic to device",
            "cmd": [
                "powershell", "-Command",
                f"New-NetFirewallRule -DisplayName '{rule_name_out}' "
                f"-Direction Outbound -Action Block "
                f"-RemoteAddress {ip} "
                f"-Profile Domain,Private,Public "
                f"-Enabled True"
            ]
        }
    ]
    
    if not can_enforce:
        # SIMULATED MODE
        for rule in rules:
            cmd_str = " ".join(rule["cmd"])
            result["commands"].append(cmd_str)
            print(f"[SIMULATED] {rule['description']}")
            print(f"            Rule: {rule['rule_name']}")
            enforcement_logger.info(
                f"SIMULATED | device_id={device_id} | ip={ip} | "
                f"action=block | direction={rule['direction']} | rule={rule['rule_name']}"
            )
        result["status"] = "simulated"
        print(f"✓ Block action: SIMULATED (safe mode)\n")
        return result
    
    # REAL ENFORCEMENT MODE
    try:
        for rule in rules:
            direction = rule["direction"]
            rule_name = rule["rule_name"]
            cmd = rule["cmd"]
            cmd_str = " ".join(cmd)
            result["commands"].append(cmd_str)
            
            # Check if rule already exists (idempotent)
            if _windows_rule_exists(rule_name):
                print(f"[SKIP] Rule already exists: {rule_name}")
                enforcement_logger.info(
                    f"SKIP | device_id={device_id} | ip={ip} | "
                    f"action=block | direction={direction} | reason=rule_exists"
                )
                result["rules_added"].append(f"{direction} (already exists)")
                continue
            
            # Execute PowerShell command
            print(f"[EXECUTING] {rule['description']}")
            print(f"            Rule: {rule_name}")
            
            exec_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if exec_result.returncode == 0:
                result["rules_added"].append(f"{direction} (success)")
                enforcement_logger.info(
                    f"SUCCESS | device_id={device_id} | ip={ip} | "
                    f"action=block | direction={direction} | rule={rule_name}"
                )
                print(f"✅ SUCCESS: {direction} rule added")
            else:
                error_msg = exec_result.stderr.strip() or exec_result.stdout.strip()
                result["rules_added"].append(f"{direction} (failed: {error_msg[:100]})")
                enforcement_logger.error(
                    f"FAILED | device_id={device_id} | ip={ip} | "
                    f"action=block | direction={direction} | error={error_msg[:200]}"
                )
                print(f"❌ FAILED: {direction} rule - {error_msg[:100]}")
                result["status"] = "partial_failure"
        
        if result["status"] != "partial_failure":
            result["status"] = "enforced"
        
        print(f"✓ Block action: {result['status'].upper()}\n")
        
    except subprocess.TimeoutExpired:
        result["status"] = "failed"
        result["error"] = "Command timeout"
        enforcement_logger.error(
            f"TIMEOUT | device_id={device_id} | ip={ip} | action=block"
        )
        print(f"❌ FAILED: Command timeout\n")
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        enforcement_logger.error(
            f"ERROR | device_id={device_id} | ip={ip} | "
            f"action=block | error={str(e)}"
        )
        print(f"❌ FAILED: {str(e)}\n")
    
    return result


def block_ip(ip: str) -> Dict[str, Any]:
    """
    Legacy function for backward compatibility.
    Calls enforce_block_ip with generic device_id.
    """
    return enforce_block_ip("unknown", ip)


def enforce_unblock_ip(device_id: str, ip: str) -> Dict[str, Any]:
    """
    REAL ENFORCEMENT: Unblock device IP by removing OS-specific firewall rules.
    
    Linux: Remove iptables rules (FORWARD + INPUT chains)
    Windows: Remove Windows Firewall rules (inbound + outbound)
    
    Args:
        device_id: Device identifier for logging/tagging
        ip: IP address to unblock
    
    Returns:
        dict with action, status, commands, and result details
    """
    timestamp = datetime.utcnow().isoformat()
    can_enforce, reason = _can_enforce()
    system = platform.system()
    
    result = {
        "action": "enforce_unblock_ip",
        "device_id": device_id,
        "ip": ip,
        "os": system,
        "timestamp": timestamp,
        "status": "simulated" if not can_enforce else "pending",
        "reason": reason,
        "commands": [],
        "rules_removed": []
    }
    
    print(f"\n{'='*60}")
    print(f"✓ QUARANTINE LIFT: Unblocking IP {ip}")
    print(f"   Device: {device_id}")
    print(f"   OS: {system}")
    print(f"   Mode: {'REAL ENFORCEMENT' if can_enforce else 'SIMULATED'}")
    print(f"{'='*60}")
    
    if system == "Linux":
        return _enforce_unblock_ip_linux(device_id, ip, can_enforce, result)
    elif system == "Windows":
        return _enforce_unblock_ip_windows(device_id, ip, can_enforce, result)
    else:
        result["status"] = "unsupported"
        result["error"] = f"OS {system} not supported"
        print(f"❌ FAILED: Unsupported OS\n")
        return result


def _enforce_unblock_ip_linux(device_id: str, ip: str, can_enforce: bool, result: Dict[str, Any]) -> Dict[str, Any]:
    """Linux-specific IP unblocking using iptables."""
    comment = f"AVIGHNA:{device_id}"
    
    # Define iptables rules to remove
    rules = [
        {
            "chain": "FORWARD",
            "description": "Remove FORWARD chain block",
            "cmd": [
                "iptables", "-D", "FORWARD",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", comment
            ]
        },
        {
            "chain": "INPUT",
            "description": "Remove INPUT chain block",
            "cmd": [
                "iptables", "-D", "INPUT",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", comment
            ]
        }
    ]
    
    if not can_enforce:
        # SIMULATED MODE
        for rule in rules:
            cmd_str = " ".join(rule["cmd"])
            result["commands"].append(cmd_str)
            print(f"[SIMULATED] {rule['description']}")
            print(f"            {cmd_str}")
            enforcement_logger.info(
                f"SIMULATED | device_id={device_id} | ip={ip} | "
                f"action=unblock | chain={rule['chain']} | command={cmd_str}"
            )
        result["status"] = "simulated"
        print(f"✓ Unblock action: SIMULATED (safe mode)\n")
        return result
    
    # REAL ENFORCEMENT MODE
    try:
        for rule in rules:
            chain = rule["chain"]
            cmd = rule["cmd"]
            cmd_str = " ".join(cmd)
            result["commands"].append(cmd_str)
            
            # Check if rule exists before trying to remove
            if not _rule_exists(chain, ip, comment):
                print(f"[SKIP] Rule doesn't exist: {chain} chain for {ip}")
                enforcement_logger.info(
                    f"SKIP | device_id={device_id} | ip={ip} | "
                    f"action=unblock | chain={chain} | reason=rule_not_found"
                )
                result["rules_removed"].append(f"{chain} (not found)")
                continue
            
            # Execute iptables command
            print(f"[EXECUTING] {rule['description']}")
            print(f"            {cmd_str}")
            
            exec_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if exec_result.returncode == 0:
                result["rules_removed"].append(f"{chain} (success)")
                enforcement_logger.info(
                    f"SUCCESS | device_id={device_id} | ip={ip} | "
                    f"action=unblock | chain={chain} | command={cmd_str}"
                )
                print(f"✅ SUCCESS: {chain} rule removed")
            else:
                error_msg = exec_result.stderr.strip()
                result["rules_removed"].append(f"{chain} (failed: {error_msg})")
                enforcement_logger.error(
                    f"FAILED | device_id={device_id} | ip={ip} | "
                    f"action=unblock | chain={chain} | error={error_msg}"
                )
                print(f"❌ FAILED: {chain} rule - {error_msg}")
                result["status"] = "partial_failure"
        
        if result["status"] != "partial_failure":
            result["status"] = "enforced"
        
        print(f"✓ Unblock action: {result['status'].upper()}\n")
        
    except subprocess.TimeoutExpired:
        result["status"] = "failed"
        result["error"] = "Command timeout"
        enforcement_logger.error(
            f"TIMEOUT | device_id={device_id} | ip={ip} | action=unblock"
        )
        print(f"❌ FAILED: Command timeout\n")
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        enforcement_logger.error(
            f"ERROR | device_id={device_id} | ip={ip} | "
            f"action=unblock | error={str(e)}"
        )
        print(f"❌ FAILED: {str(e)}\n")
    
    return result


def _enforce_unblock_ip_windows(device_id: str, ip: str, can_enforce: bool, result: Dict[str, Any]) -> Dict[str, Any]:
    """Windows-specific IP unblocking using Windows Firewall."""
    rule_name_in = f"AVIGHNA:{device_id}:{ip}:IN"
    rule_name_out = f"AVIGHNA:{device_id}:{ip}:OUT"
    
    # Define Windows Firewall rules to remove
    rules = [
        {
            "direction": "Inbound",
            "rule_name": rule_name_in,
            "description": "Remove inbound block rule",
            "cmd": [
                "powershell", "-Command",
                f"Remove-NetFirewallRule -DisplayName '{rule_name_in}' -ErrorAction SilentlyContinue"
            ]
        },
        {
            "direction": "Outbound",
            "rule_name": rule_name_out,
            "description": "Remove outbound block rule",
            "cmd": [
                "powershell", "-Command",
                f"Remove-NetFirewallRule -DisplayName '{rule_name_out}' -ErrorAction SilentlyContinue"
            ]
        }
    ]
    
    if not can_enforce:
        # SIMULATED MODE
        for rule in rules:
            cmd_str = " ".join(rule["cmd"])
            result["commands"].append(cmd_str)
            print(f"[SIMULATED] {rule['description']}")
            print(f"            Rule: {rule['rule_name']}")
            enforcement_logger.info(
                f"SIMULATED | device_id={device_id} | ip={ip} | "
                f"action=unblock | direction={rule['direction']} | rule={rule['rule_name']}"
            )
        result["status"] = "simulated"
        print(f"✓ Unblock action: SIMULATED (safe mode)\n")
        return result
    
    # REAL ENFORCEMENT MODE
    try:
        for rule in rules:
            direction = rule["direction"]
            rule_name = rule["rule_name"]
            cmd = rule["cmd"]
            cmd_str = " ".join(cmd)
            result["commands"].append(cmd_str)
            
            # Check if rule exists before trying to remove
            if not _windows_rule_exists(rule_name):
                print(f"[SKIP] Rule doesn't exist: {rule_name}")
                enforcement_logger.info(
                    f"SKIP | device_id={device_id} | ip={ip} | "
                    f"action=unblock | direction={direction} | reason=rule_not_found"
                )
                result["rules_removed"].append(f"{direction} (not found)")
                continue
            
            # Execute PowerShell command
            print(f"[EXECUTING] {rule['description']}")
            print(f"            Rule: {rule_name}")
            
            exec_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Remove-NetFirewallRule with -ErrorAction SilentlyContinue always returns 0
            # Check if rule still exists to verify removal
            if not _windows_rule_exists(rule_name):
                result["rules_removed"].append(f"{direction} (success)")
                enforcement_logger.info(
                    f"SUCCESS | device_id={device_id} | ip={ip} | "
                    f"action=unblock | direction={direction} | rule={rule_name}"
                )
                print(f"✅ SUCCESS: {direction} rule removed")
            else:
                error_msg = exec_result.stderr.strip() or "Rule still exists after removal attempt"
                result["rules_removed"].append(f"{direction} (failed: {error_msg[:100]})")
                enforcement_logger.error(
                    f"FAILED | device_id={device_id} | ip={ip} | "
                    f"action=unblock | direction={direction} | error={error_msg[:200]}"
                )
                print(f"❌ FAILED: {direction} rule - {error_msg[:100]}")
                result["status"] = "partial_failure"
        
        if result["status"] != "partial_failure":
            result["status"] = "enforced"
        
        print(f"✓ Unblock action: {result['status'].upper()}\n")
        
    except subprocess.TimeoutExpired:
        result["status"] = "failed"
        result["error"] = "Command timeout"
        enforcement_logger.error(
            f"TIMEOUT | device_id={device_id} | ip={ip} | action=unblock"
        )
        print(f"❌ FAILED: Command timeout\n")
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        enforcement_logger.error(
            f"ERROR | device_id={device_id} | ip={ip} | "
            f"action=unblock | error={str(e)}"
        )
        print(f"❌ FAILED: {str(e)}\n")
    
    return result


def unblock_ip(ip: str) -> Dict[str, Any]:
    """
    Legacy function for backward compatibility.
    Calls enforce_unblock_ip with generic device_id.
    """
    return enforce_unblock_ip("unknown", ip)


def disconnect_wifi(device_id_or_mac: str) -> Dict[str, Any]:
    """
    Simulate WiFi disconnection for a device.
    
    In real scenario:
    - Windows: netsh wlan set profileorder / connect-disallowed
    - Linux: nmcli device disconnect <iface>
    - Android: Would require app to listen & disconnect
    """
    print(f"\n{'='*60}")
    print(f"📡 QUARANTINE ACTION: WiFi Disconnect for {device_id_or_mac}")
    print(f"{'='*60}")
    
    result = {
        "action": "wifi_disconnect",
        "device": device_id_or_mac,
        "status": "simulated",
        "note": "In real scenario, would disconnect WiFi for this device"
    }
    
    system = platform.system()
    
    if system == "Windows":
        print(f"[Windows] Would run: netsh wlan set profilename=<network> connectnow=0")
        result["status"] = "simulated"
    elif system == "Linux":
        print(f"[Linux] Would run: nmcli device disconnect <interface>")
        result["status"] = "simulated"
    else:
        print(f"[{system}] WiFi disconnect simulation")
        result["status"] = "simulated"
    
    # For Android/Termux: this would be handled by the Termux agent
    # detecting the quarantine status and dropping connection
    print(f"ℹ️  For Android: Device should detect quarantine and auto-disconnect")
    print(f"✓ WiFi disconnect action: {result['status']}\n")
    return result


def list_avighna_rules() -> Dict[str, Any]:
    """
    List all firewall rules created by AVIGHNA.
    
    Linux: Lists iptables rules with AVIGHNA comment
    Windows: Lists Windows Firewall rules with AVIGHNA prefix
    
    Returns:
        dict with rules grouped by chain/direction and device
    """
    system = platform.system()
    result = {
        "action": "list_rules",
        "os": system,
        "timestamp": datetime.utcnow().isoformat(),
        "rules": {},
        "total_count": 0
    }
    
    if system == "Linux":
        return _list_avighna_rules_linux(result)
    elif system == "Windows":
        return _list_avighna_rules_windows(result)
    else:
        result["error"] = f"OS {system} not supported"
        return result


def _list_avighna_rules_linux(result: Dict[str, Any]) -> Dict[str, Any]:
    """List AVIGHNA iptables rules on Linux."""
    result["rules"] = {"FORWARD": [], "INPUT": []}
    
    try:
        # List all iptables rules with line numbers
        for chain in ["FORWARD", "INPUT"]:
            cmd = ["iptables", "-L", chain, "-n", "--line-numbers"]
            exec_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if exec_result.returncode == 0:
                # Parse output for AVIGHNA rules
                lines = exec_result.stdout.split("\n")
                for line in lines:
                    if "AVIGHNA:" in line:
                        result["rules"][chain].append(line.strip())
                        result["total_count"] += 1
        
        print(f"\n{'='*60}")
        print(f"📋 AVIGHNA IPTABLES RULES (Linux)")
        print(f"{'='*60}")
        for chain, rules in result["rules"].items():
            print(f"\n{chain} chain: {len(rules)} rule(s)")
            for rule in rules:
                print(f"  {rule}")
        print(f"\nTotal: {result['total_count']} rule(s)\n")
        
    except Exception as e:
        result["error"] = str(e)
        print(f"❌ Failed to list rules: {str(e)}\n")
    
    return result


def _list_avighna_rules_windows(result: Dict[str, Any]) -> Dict[str, Any]:
    """List AVIGHNA Windows Firewall rules."""
    result["rules"] = {"Inbound": [], "Outbound": []}
    
    try:
        cmd = [
            "powershell", "-Command",
            "Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'AVIGHNA:*'} | "
            "Select-Object DisplayName,Direction,Action,Enabled | Format-Table -AutoSize"
        ]
        
        exec_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if exec_result.returncode == 0:
            lines = exec_result.stdout.strip().split("\n")
            for line in lines:
                if "AVIGHNA:" in line:
                    if "Inbound" in line:
                        result["rules"]["Inbound"].append(line.strip())
                        result["total_count"] += 1
                    elif "Outbound" in line:
                        result["rules"]["Outbound"].append(line.strip())
                        result["total_count"] += 1
        
        print(f"\n{'='*60}")
        print(f"📋 AVIGHNA WINDOWS FIREWALL RULES")
        print(f"{'='*60}")
        for direction, rules in result["rules"].items():
            print(f"\n{direction}: {len(rules)} rule(s)")
            for rule in rules:
                print(f"  {rule}")
        print(f"\nTotal: {result['total_count']} rule(s)\n")
        
    except Exception as e:
        result["error"] = str(e)
        print(f"❌ Failed to list rules: {str(e)}\n")
    
    return result


def isolate_device_completely(device_id: str, ip: str = None, mac: str = None) -> Dict[str, Any]:
    """
    Complete isolation: block IP + disconnect WiFi + create network barrier
    
    Uses enforce_block_ip for real network isolation when in gateway mode.
    
    Returns detailed quarantine report
    """
    print(f"\n{'='*70}")
    print(f"🔒 CRITICAL: COMPLETE DEVICE ISOLATION")
    print(f"   Device: {device_id}")
    print(f"   IP: {ip}")
    print(f"   MAC: {mac}")
    print(f"{'='*70}\n")
    
    isolation_report = {
        "device_id": device_id,
        "timestamp": datetime.utcnow().isoformat(),
        "actions": []
    }
    
    # Block by IP using real enforcement
    if ip:
        block_result = enforce_block_ip(device_id, ip)
        isolation_report["actions"].append(block_result)
    else:
        isolation_report["actions"].append({
            "action": "block_ip",
            "status": "skipped",
            "reason": "No IP address provided"
        })
    
    # Disconnect WiFi (still simulated - requires hostapd integration)
    wifi_result = disconnect_wifi(mac or device_id)
    isolation_report["actions"].append(wifi_result)
    
    print(f"✓ Device isolation complete\n")
    
    return isolation_report

