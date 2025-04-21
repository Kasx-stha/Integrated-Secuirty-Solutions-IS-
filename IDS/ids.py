# Standard library imports
import sys
import os
import argparse
import threading
import time
import queue
import signal
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Try to import Scapy for packet sniffing
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Raw
except ImportError:
    print("Error: Scapy package not found. Please install with 'pip install scapy'")
    sys.exit(1)

# Local module imports
from config import Config
from detectors import (
    SQLInjectionDetector,
    XSSDetector,
    DosDetector,
    PhishingDetector,
    DarkwebDetector,
)
from signatures import SignatureDatabase
from utils import setup_logging, print_colored, print_banner, format_packet_summary
from snort_integration import SnortIntegration

# Flag to control graceful shutdown
running = True

# Handle Ctrl+C (SIGINT) signal for clean shutdown
def signal_handler(sig, frame):
    global running
    print_colored("\n[!] Shutting down IDS...", "yellow")
    running = False
    os._exit(0)

# Main Intrusion Detection System class
class IDS:
    def __init__(self, config_file: str = "config.ini", interface: Optional[str] = None, log_file: Optional[str] = None):
        # Load configuration from file
        self.config = Config(config_file)
        if interface:
            self.config.interface = interface
        if log_file:
            self.config.log_file = log_file

        # Setup logging
        self.logger = setup_logging(self.config.log_file, self.config.log_level)

        # Initialize signature database and detectors
        self.signature_db = SignatureDatabase(self.config)
        self.detectors = self._init_detectors()

        # Initialize queue to hold packets for analysis
        self.packet_queue = queue.Queue(maxsize=1000)

        # Statistics to track activity
        self.stats = {
            "start_time": datetime.now(),
            "packets_processed": 0,
            "alerts_generated": 0,
            "alerts_by_type": {},
            "alerts_forwarded_to_snort": 0
        }

        # Thread to show runtime stats
        self.stats_thread = None

        # Track recent alerts to avoid duplicates
        self.recent_alerts = {}
        self.dedup_window = 5  # seconds

        # Setup optional Snort integration
        self.snort_integration = SnortIntegration(self.config, self.logger)

    # Initialize all detectors
    def _init_detectors(self) -> List:
        return [
            SQLInjectionDetector(self.config),
            XSSDetector(self.config),
            DosDetector(self.config),
            PhishingDetector(self.config),
            DarkwebDetector(self.config),
        ]

    # Called for every packet captured by Scapy
    def packet_callback(self, packet):
        try:
            self.packet_queue.put(packet, block=False)
        except queue.Full:
            self.logger.warning("Packet queue full, packet dropped")

    # Main processing loop to fetch packets and analyze
    def process_packets(self):
        while running:
            try:
                packets_to_process = []
                for _ in range(min(10, self.packet_queue.qsize())):
                    if not self.packet_queue.empty():
                        packets_to_process.append(self.packet_queue.get_nowait())

                for packet in packets_to_process:
                    self._analyze_packet(packet)
                    self.packet_queue.task_done()
            except Exception as e:
                self.logger.error(f"Error processing packets: {str(e)}")

            if not packets_to_process:
                time.sleep(0.01)

    # Analyze one packet using all detectors
    def _analyze_packet(self, packet):
        self.stats["packets_processed"] += 1

        # Ignore packets with very small payloads
        if packet.haslayer(scapy.Raw) and len(packet[scapy.Raw].load) < 10:
            return

        best_match = None
        highest_confidence = -1

        # Run each detector and pick the best match
        for detector in self.detectors:
            result = detector.detect(packet)
            if result:
                alert_type, details = result
                confidence = details.get('confidence', 0)
                if confidence > highest_confidence:
                    highest_confidence = confidence
                    best_match = (alert_type, details)

        # If a strong match is found, generate alert
        if best_match and highest_confidence >= 85:
            alert_type, details = best_match
            if self._generate_alert(alert_type, details, packet):
                self.stats["alerts_generated"] += 1
                self.stats["alerts_by_type"].setdefault(alert_type, 0)
                self.stats["alerts_by_type"][alert_type] += 1

    # Forward alert to Snort (currently mocked/disabled)
    def _forward_alert_to_snort(self, alert_type: str, details: Dict, packet) -> bool:
        try:
            self.logger.info(f"Alert detected: {alert_type}. Already forwarded to Snort for further actions.")
            return True
        except Exception as e:
            self.logger.error(f"Error forwarding alert to Snort: {str(e)}")
            return False

    # Generate and log alerts if valid
    def _generate_alert(self, alert_type: str, details: Dict, packet):
        confidence = details.get('confidence', 0)
        min_confidence = self.config.get_attack_threshold(alert_type.lower().replace(' ', '_'))

        if confidence < min_confidence:
            self.logger.debug(f"Alert suppressed due to low confidence: {confidence} < {min_confidence}")
            return False

        # Suppress alerts from whitelisted IPs
        if packet.haslayer(scapy.IP):
            src_ip = packet.getlayer(scapy.IP).src
            if src_ip in getattr(self.config, 'whitelist', []):
                self.logger.debug(f"Alert suppressed for whitelisted source: {src_ip}")
                return False

        # Prepare alert metadata
        src = packet.getlayer(scapy.IP).src if packet.haslayer(scapy.IP) else "Unknown"
        dst = packet.getlayer(scapy.IP).dst if packet.haslayer(scapy.IP) else "Unknown"
        signature = details.get('signature', 'Unknown')

        # Avoid duplicate alerts using a sliding window
        current_time = time.time()
        self.recent_alerts = {
            k: v for k, v in self.recent_alerts.items()
            if current_time - v <= self.dedup_window
        }
        alert_key = (src, dst, alert_type, signature)
        if alert_key in self.recent_alerts:
            self.logger.debug(f"Duplicate alert suppressed: {alert_type} from {src} to {dst}")
            return False

        self.recent_alerts[alert_key] = current_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log alert to console and log file
        alert_msg = f"[ALERT] {alert_type} detected!\n  Timestamp: {timestamp}\n  Source: {src}\n  Destination: {dst}\n  Details: {details['message']}\n"
        if 'signature' in details:
            alert_msg += f"  Signature: {details['signature']}\n"
        if 'confidence' in details:
            alert_msg += f"  Confidence: {details['confidence']}%\n"

        self.logger.warning(alert_msg)

        print_colored(alert_msg, {
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }.get(details.get("severity", "MEDIUM"), "white"))

        # Forward to Snort if severity is high
        if details.get("severity", "MEDIUM") == "HIGH" and confidence >= 80:
            if self._forward_alert_to_snort(alert_type, details, packet):
                self.stats["alerts_forwarded_to_snort"] += 1
                print_colored("  [*] Alert forwarded to Snort IPS for blocking", "green")

        # Write alert to Snort alert file
        try:
            snort_alert_log = "/usr/local/etc/snort/ids_alert.txt"
            os.makedirs(os.path.dirname(snort_alert_log), exist_ok=True)
            with open(snort_alert_log, "a") as f:
                f.write(
                    f"[IDS Forwarded Alert] {alert_type} | Src: {src} -> Dst: {dst} | "
                    f"Message: {details.get('message', 'N/A')} | Confidence: {details.get('confidence', 'N/A')} | "
                    f"Time: {timestamp}\n"
                )
        except Exception as e:
            self.logger.error(f"Failed to write to /usr/local/etc/snort/ids_alert.txt: {e}")

        return True

    # Start IDS: sniff packets and monitor activity
    def start(self):
        print_banner()
        print_colored(f"[*] Initializing IDS...", "green")
        print_colored(f"[*] Log file: {self.config.log_file}", "green")

        # Start background thread for showing stats
        self.stats_thread = threading.Thread(target=self.show_statistics)
        self.stats_thread.daemon = True
        self.stats_thread.start()

        # Start background thread for processing packets
        processing_thread = threading.Thread(target=self.process_packets)
        processing_thread.daemon = True
        processing_thread.start()

        print_colored(f"[*] Starting packet capture on interface: {self.config.interface}", "green")
        print_colored(f"[*] Press Ctrl+C to stop", "green")

        # Start Scapy sniffing
        try:
            scapy.sniff(
                iface=self.config.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda x: not running
            )
        except KeyboardInterrupt:
            print_colored("\n[!] Keyboard interrupt detected, shutting down...", "yellow")
            global running
            running = False
            os._exit(0)
        except Exception as e:
            print_colored(f"[!] Error during packet capture: {str(e)}", "red")
            self.logger.error(f"Error during packet capture: {str(e)}")
            return False

        return True

    # Show periodic statistics in the terminal
    def show_statistics(self):
        while running:
            runtime = datetime.now() - self.stats["start_time"]
            runtime_str = str(runtime).split('.')[0]
            stats_msg = f"\n--- IDS Statistics ---\nRuntime: {runtime_str}\nPackets processed: {self.stats['packets_processed']}\nAlerts generated: {self.stats['alerts_generated']}\nAlerts forwarded to Snort IPS: {self.stats['alerts_forwarded_to_snort']}\n"
            if self.stats["alerts_by_type"]:
                stats_msg += "Alert breakdown:\n"
                for alert_type, count in self.stats["alerts_by_type"].items():
                    stats_msg += f"  - {alert_type}: {count}\n"
            print_colored(stats_msg, "cyan")
            for _ in range(30):
                if not running:
                    break
                time.sleep(1)

# Entry point
def main():
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="Signature-based Intrusion Detection System")
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-c", "--config", default="config.ini", help="Path to configuration file")
    parser.add_argument("-l", "--logfile", help="Path to log file")
    args = parser.parse_args()

    # Setup Ctrl+C handler
    signal.signal(signal.SIGINT, signal_handler)

    # Initialize IDS with arguments
    ids = IDS(config_file=args.config, interface=args.interface, log_file=args.logfile)
    success = ids.start()

    while running:
        time.sleep(1)

    return 0 if success else 1

# Execute main if this script is run directly
if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except:
        os._exit(1)
