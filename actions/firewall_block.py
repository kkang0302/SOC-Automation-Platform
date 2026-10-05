import subprocess
import platform
import logging

logger = logging.getLogger(__name__)

def block_ip_firewall(ip_address):
    """
    Executes native OS commands to block an IP address via iptables (Linux)
    or netsh advfirewall (Windows). Safely skips private/loopback IPs.
    """
    if not ip_address:
        return False, "Invalid or empty IP address"

    # Protect loopback and local subnet from accidental lockouts
    whitelist = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
    if ip_address in whitelist or ip_address.startswith("127."):
        return False, f"Safeguard triggered: Cannot block protected loopback IP ({ip_address})"

    os_type = platform.system()
    try:
        if os_type == "Linux":
            # Check if iptables rule already exists
            check_cmd = f"sudo iptables -C INPUT -s {ip_address} -j DROP"
            check_res = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            if check_res.returncode == 0:
                return True, f"IP {ip_address} is already blocked in iptables"

            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"[FIREWALL] Successfully blocked {ip_address} via iptables")
            return True, f"Blocked {ip_address} via iptables DROP rule"

        elif os_type == "Windows":
            rule_name = f"SOC_AUTO_BLOCK_{ip_address}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"[FIREWALL] Successfully blocked {ip_address} via Windows Firewall")
            return True, f"Blocked {ip_address} via Windows Firewall rule ({rule_name})"

        else:
            return False, f"Unsupported Operating System ({os_type})"

    except subprocess.CalledProcessError as e:
        logger.error(f"[FIREWALL ERROR] Command failed to block IP {ip_address}: {e}")
        return False, f"Firewall command failed: {e}"
    except Exception as e:
        logger.error(f"[FIREWALL ERROR] Unexpected error: {e}")
        return False, str(e)
