"""
Utilities Module

This module contains utility functions for the IDS.
"""

import os
import logging
import math
from collections import Counter
from typing import Dict

import scapy.all as scapy


def setup_logging(log_file: str, log_level: int) -> logging.Logger:
    """
    Set up logging for the IDS
    
    Args:
        log_file: Path to log file
        log_level: Logging level
    
    Returns:
        Logger instance
    """
    # Create log directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging
    logger = logging.getLogger("ids")
    logger.setLevel(log_level)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(file_handler)
    
    return logger


def print_colored(text: str, color: str = "white"):
    """
    Print colored text to the console
    
    Args:
        text: Text to print
        color: Color to use
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
    """Print the IDS banner"""
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


def format_packet_summary(packet) -> str:
    """
    Format packet information for display
    
    Args:
        packet: Scapy packet
        
    Returns:
        Formatted string with packet details
    """
    summary = packet.summary()
    details = []
    
    # Add IP information if available
    if packet.haslayer(scapy.IP):
        ip = packet.getlayer(scapy.IP)
        details.append(f"IP {ip.src} -> {ip.dst}")
    
    # Add TCP/UDP information if available
    if packet.haslayer(scapy.TCP):
        tcp = packet.getlayer(scapy.TCP)
        flags = _format_tcp_flags(tcp.flags)
        details.append(f"TCP {tcp.sport} -> {tcp.dport} [{flags}]")
    elif packet.haslayer(scapy.UDP):
        udp = packet.getlayer(scapy.UDP)
        details.append(f"UDP {udp.sport} -> {udp.dport}")
    
    # Add ICMP information if available
    if packet.haslayer(scapy.ICMP):
        icmp = packet.getlayer(scapy.ICMP)
        details.append(f"ICMP type={icmp.type} code={icmp.code}")
    
    # Add HTTP information if available
    if packet.haslayer(scapy.Raw):
        raw_data = packet[scapy.Raw].load
        try:
            data_str = raw_data.decode('utf-8', errors='ignore')
            if data_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                # Extract first line of HTTP request
                http_line = data_str.split("\n")[0].strip()
                details.append(f"HTTP: {http_line}")
        except:
            pass
    
    if details:
        return " | ".join(details)
    return summary


def _format_tcp_flags(flags: int) -> str:
    """
    Format TCP flags as a string
    
    Args:
        flags: TCP flags as integer
        
    Returns:
        String representation of flags
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


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Bytes to calculate entropy for
        
    Returns:
        Entropy value between 0 and 8
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    counter = Counter(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy
