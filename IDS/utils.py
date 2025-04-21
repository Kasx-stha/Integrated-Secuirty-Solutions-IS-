# Utilities Module
# This module provides utility functions used across the IDS project, including logging,
# terminal printing, packet formatting, and entropy calculations.

import os
import logging
import math
from collections import Counter
from typing import Dict

import scapy.all as scapy  # Used for packet parsing and analysis

# ------------------------------------------
# Logging Setup
# ------------------------------------------

def setup_logging(log_file: str, log_level: int) -> logging.Logger:
    """
    Set up logging for the IDS system.
    
    Args:
        log_file: The path to the log file to write logs.
        log_level: Logging level (DEBUG, INFO, etc.).
    
    Returns:
        Configured Logger instance.
    """
    # Create log directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Create a logger with specified name and level
    logger = logging.getLogger("ids")
    logger.setLevel(log_level)
    
    # Create a file handler to write logs to file
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    # Set the format of the log messages
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    
    # Add the file handler to the logger
    logger.addHandler(file_handler)
    
    return logger


# ------------------------------------------
# Console Output Helpers
# ------------------------------------------

def print_colored(text: str, color: str = "white"):
    """
    Print colored text to the console using ANSI escape codes.
    
    Args:
        text: Message to print.
        color: Desired text color.
    """
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "purple": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }
    
    print(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")


def print_banner():
    """
    Display a stylized IDS ASCII banner at startup.
    """
    banner = """
╔══════════════════════════════════════════════════╗
║                                                  ║
║   ██╗██████╗ ███████╗    ███████╗██╗   ██╗███████╗   ║
║   ██║██╔══██╗██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝   ║
║   ██║██║  ██║███████╗    ███████╗ ╚████╔╝ ███████╗   ║
║   ██║██║  ██║╚════██║    ╚════██║  ╚██╔╝  ╚════██║   ║
║   ██║██████╔╝███████║    ███████║   ██║   ███████║   ║
║   ╚═╝╚═════╝ ╚══════╝    ╚══════╝   ╚═╝   ╚══════╝   ║
║                                                  ║
║        Signature-based Intrusion Detection       ║
║                                                  ║
╚══════════════════════════════════════════════════╝
"""
    print_colored(banner, "cyan")


# ------------------------------------------
# Packet Summary Formatter
# ------------------------------------------

def format_packet_summary(packet) -> str:
    """
    Format packet summary with useful network protocol details.
    
    Args:
        packet: Scapy packet object.
        
    Returns:
        String with protocol-level summary (e.g., IP, TCP, HTTP).
    """
    summary = packet.summary()
    details = []
    
    # Include IP source and destination
    if packet.haslayer(scapy.IP):
        ip = packet.getlayer(scapy.IP)
        details.append(f"IP {ip.src} -> {ip.dst}")
    
    # Include TCP info with flags
    if packet.haslayer(scapy.TCP):
        tcp = packet.getlayer(scapy.TCP)
        flags = _format_tcp_flags(tcp.flags)
        details.append(f"TCP {tcp.sport} -> {tcp.dport} [{flags}]")
    
    # Include UDP info
    elif packet.haslayer(scapy.UDP):
        udp = packet.getlayer(scapy.UDP)
        details.append(f"UDP {udp.sport} -> {udp.dport}")
    
    # Include ICMP type and code
    if packet.haslayer(scapy.ICMP):
        icmp = packet.getlayer(scapy.ICMP)
        details.append(f"ICMP type={icmp.type} code={icmp.code}")
    
    # Attempt to parse HTTP methods from Raw payload
    if packet.haslayer(scapy.Raw):
        raw_data = packet[scapy.Raw].load
        try:
            data_str = raw_data.decode('utf-8', errors='ignore')
            if data_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                http_line = data_str.split("\n")[0].strip()
                details.append(f"HTTP: {http_line}")
        except:
            pass
    
    return " | ".join(details) if details else summary


# ------------------------------------------
# TCP Flag Formatter
# ------------------------------------------

def _format_tcp_flags(flags: int) -> str:
    """
    Convert TCP flag bitmask into human-readable characters.
    
    Args:
        flags: Integer representation of TCP flags.
        
    Returns:
        String (e.g., "S" for SYN, "A" for ACK).
    """
    flag_map = {
        0x01: 'F',  # FIN
        0x02: 'S',  # SYN
        0x04: 'R',  # RST
        0x08: 'P',  # PSH
        0x10: 'A',  # ACK
        0x20: 'U',  # URG
        0x40: 'E',  # ECE
        0x80: 'C'   # CWR
    }
    
    result = ""
    for bit, char in flag_map.items():
        if flags & bit:
            result += char
    
    return result if result else "-"


# ------------------------------------------
# Entropy Calculation
# ------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """
    Compute the Shannon entropy of a byte string.
    Entropy helps identify random-looking or obfuscated data.
    
    Args:
        data: Raw byte content to analyze.
        
    Returns:
        Float value between 0 (low randomness) and 8 (high randomness).
    """
    if not data:
        return 0.0
    
    # Count frequency of each byte
    counter = Counter(data)
    
    # Compute entropy using the Shannon formula
    entropy = 0.0
    for count in counter.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy
