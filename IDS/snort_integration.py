import os
import logging
import hashlib
import socket
import subprocess
import time
from alert_logger import write_alert_to_file
from typing import List, Dict, Optional, Tuple

# Define a class for integrating Snort IPS into a Python-based detection system
class SnortIntegration:
    """
    This class handles integration with Snort IPS.
    It validates Snort installation, rule paths, control socket,
    and allows sending block commands based on IDS alerts.
    """

    def __init__(self, config, logger=None):
        # Initialize the configuration and logger
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

        # Load paths and settings from config
        self.snort_enabled = config.snort_enabled
        self.snort_socket_path = config.snort_unix_socket
        self.snort_rule_paths = [config.snort_rules_path]
        self.snort_bin_path = getattr(config, 'snort_bin_path', '/usr/local/bin/snort')
        self.snort_drop_rules_path = [config.snort_drop_rules_path]

        # Track valid rules, previously forwarded alerts, and blocked flows
        self.valid_rules = set()
        self.forwarded_alerts = set()
        self.active_blocks = {}

        # Run initialization steps if Snort is enabled
        if self.snort_enabled:
            self._initialize_snort_integration()

    def _initialize_snort_integration(self):
        # Validate Snort binary, rules, and control socket availability
        self._validate_snort_installation()
        self._validate_rule_paths()
        self._validate_socket()

    def _validate_snort_installation(self):
        # Check if Snort is installed by running `snort -V`
        try:
            result = subprocess.run(
                [self.snort_bin_path, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("Snort verification failed")
            self.logger.info(f"Snort verified: {result.stdout.decode()[:50]}...")
        except Exception as e:
            # Disable Snort integration if the binary is not working
            self.logger.error(f"Snort validation failed: {str(e)}")
            self.snort_enabled = False

    def _validate_rule_paths(self):
        # Ensure the rule files actually exist
        missing_rules = []
        for path in self.snort_rule_paths:
            if not os.path.exists(path):
                missing_rules.append(path)
                self.logger.warning(f"Snort rule path missing: {path}")

        # Disable Snort if rule files are missing
        if missing_rules:
            self.logger.error("Missing Snort rule paths - blocking may be ineffective")
            self.snort_enabled = False
            raise FileNotFoundError(
                f"Missing Snort rule paths: {', '.join(missing_rules)}\n"
                "Configure rules in snort.conf and ensure paths exist"
            )

    def _validate_socket(self):
        # Check if the Unix domain socket used to send block commands exists
        if not os.path.exists(self.snort_socket_path):
            self.logger.error("Snort control socket missing - blocking disabled")
            self.snort_enabled = False
            raise FileNotFoundError(
                "Snort socket not found. Ensure snort.conf contains:\n"
                f"config unix_socket: {self.snort_socket_path}\n"
                "config enable_active_drops"
            )

    def forward_alert(self, alert_type: str, details: Dict, packet) -> Tuple[bool, str]:
        # Forward alert to Snort and trigger block if necessary
        if not self.snort_enabled:
            return False, "Snort integration disabled"

        # Check if alert matches any Snort rule (stubbed as always true for now)
        rule_check = self._check_against_snort_rules(packet)
        if not rule_check[0]:
            return False, f"Alert not covered by Snort rules: {rule_check[1]}"

        # Generate unique flow ID for the alert to prevent duplicates
        flow_id = self._generate_flow_signature(packet)
        if flow_id in self.forwarded_alerts:
            return True, "Duplicate alert - already processed"

        # Send drop command to Snort for blocking
        success = self._execute_snort_block(packet, alert_type)

        # Record blocked flow details
        self.active_blocks[flow_id] = {
            "alert_type": alert_type,
            "timestamp": time.time(),
            "packet_info": self._extract_packet_info(packet)
        }

        # Write basic alert to alert file
        alert_message = f"Alert Type: {alert_type}, Flow ID: {flow_id}, Timestamp: {time.time()}"
        write_alert_to_file(alert_message)

        # Log detailed alert info into Snort alert log file
        snort_alert_log = "/usr/local/etc/snort/ids_alert.txt"
        try:
            os.makedirs(os.path.dirname(snort_alert_log), exist_ok=True)
            with open(snort_alert_log, "a") as f:
                f.write(
                    f"[Snort Forwarded Alert] {alert_type} | Flow ID: {flow_id} "
                    f"| Src: {packet.get('IP', {}).get('src', 'N/A')} -> "
                    f"Dst: {packet.get('IP', {}).get('dst', 'N/A')} | "
                    f"Message: {details.get('message', 'N/A')} | "
                    f"Confidence: {details.get('confidence', 'N/A')} | "
                    f"Time: {time.ctime()}\n"
                )
            print("[DEBUG] Snort alert written successfully")
        except Exception as e:
            print(f"[ERROR] Failed to write to Snort alert file: {e}")

        return True, "Blocking executed successfully" if success else "Blocking failed, but alert logged"

    def _check_against_snort_rules(self, packet) -> Tuple[bool, str]:
        # Placeholder check: Always returns that the packet is covered by a rule
        return (True, "community.rules:2019399")

    def _generate_flow_signature(self, packet) -> str:
        # Generate a unique flow ID using src/dst IP and protocol, hashed
        try:
            return hashlib.sha256(
                f"{packet['IP'].src}:{packet['IP'].dst}:{packet['IP'].proto}".encode()
            ).hexdigest()[:16]
        except KeyError:
            # If IP fields are missing, hash entire packet
            return hashlib.sha256(str(packet).encode()).hexdigest()[:16]

    def _extract_packet_info(self, packet) -> Dict:
        # Extract basic info from packet (IP addresses, ports, protocol)
        return {
            "src_ip": packet.get('IP', {}).get('src', "N/A"),
            "dst_ip": packet.get('IP', {}).get('dst', "N/A"),
            "protocol": packet.get('IP', {}).get('proto', 0),
            "src_port": packet.get('TCP', {}).get('sport', 0),
            "dst_port": packet.get('TCP', {}).get('dport', 0)
        }

    def _execute_snort_block(self, packet, alert_type: str) -> bool:
        # Construct and send the Snort block command over socket
        try:
            cmd = self._build_block_command(packet)
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.connect(self.snort_socket_path)
                sock.send(cmd.encode())
            self.logger.info(f"Blocked {alert_type} traffic: {cmd}")
            return True
        except Exception as e:
            self.logger.error(f"Block command failed: {str(e)}")
            return False

    def _build_block_command(self, packet) -> str:
        # Build a Snort drop command string based on the protocol and packet info
        proto_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}

        try:
            ip = packet.get('IP', {})
            proto = proto_map.get(ip.get('proto', 0), 'ip')
            src_port = packet.get('TCP', {}).get('sport', 0)
            dst_port = packet.get('TCP', {}).get('dport', 0)

            return f"drop {proto} {ip.get('src', 'any')} {src_port} -> {ip.get('dst', 'any')} {dst_port}"
        except KeyError:
            # Return generic drop rule if something fails
            return "drop ip any any -> any any"

    def get_blocked_flows(self) -> Dict:
        # Returns dictionary of all active blocked flows
        return self.active_blocks

    def validate_rule_coverage(self, alert_types: List[str]) -> Dict[str, Tuple[bool, List[str]]]:
        # Placeholder: Assume all alert types are covered by a dummy rule
        return {atype: (True, ["community.rule:12345"]) for atype in alert_types}
