import os
import configparser  # Used to read/write INI configuration files
import logging
from typing import Dict  # For type hinting

# -----------------------------------------
# Configuration class for IDS settings
# -----------------------------------------
class Config:
    """Configuration manager for IDS"""

    def __init__(self, config_file: str = "config.ini"):
        """
        Initialize the configuration manager
        
        Args:
            config_file: Path to the configuration file
        """
        self.config = configparser.ConfigParser()  # INI-style config reader/writer

        # -----------------------------
        # Default configuration values
        # -----------------------------
        self.interface = "eth0"  # Default network interface
        self.log_file = "/home/kali/IDS/ids.log"  # Default path for log file
        self.log_level = logging.INFO  # Default logging level
        self.signatures_dir = "signatures"  # Default signature directory
        self.update_url = ""  # Default update URL (empty means no auto-update)

        # Default detection thresholds for different attack types (0-100)
        self.attack_thresholds = {
            "sql_injection": 70,
            "xss": 70,
            "dos_ddos": 70,
            "phishing": 70,
            "malware": 70,
            "darkweb": 70,
        }

        self.whitelist = []  # List of whitelisted IPs (empty initially)

        # Snort integration defaults
        self.snort_enabled = True
        self.snort_unix_socket = "/usr/local/etc/snort/snort_alert.sock"
        self.snort_rules_path = "/usr/local/etc/rules/snort3-community-rules/snort3-community.rules"
        self.snort_drop_rules_path = "/usr/local/etc/rules/drop-pack"

        # -----------------------------
        # Load or create configuration
        # -----------------------------
        if os.path.exists(config_file):
            self.load_config(config_file)  # Load existing config if found
        else:
            self.create_default_config(config_file)  # Otherwise, create one with defaults

    def load_config(self, config_file: str):
        """
        Load configuration values from the given file
        
        Args:
            config_file: Path to the configuration file
        """
        try:
            self.config.read(config_file)  # Parse the config file

            # Load network interface
            if self.config.has_section('Network'):
                if self.config.has_option('Network', 'Interface'):
                    self.interface = self.config.get('Network', 'Interface')

            # Load logging settings
            if self.config.has_section('Logging'):
                if self.config.has_option('Logging', 'LogFile'):
                    self.log_file = self.config.get('Logging', 'LogFile')
                if self.config.has_option('Logging', 'LogLevel'):
                    level_str = self.config.get('Logging', 'LogLevel')
                    self.log_level = self._parse_log_level(level_str)  # Convert string to log level

            # Load signature-related settings
            if self.config.has_section('Signatures'):
                if self.config.has_option('Signatures', 'Directory'):
                    self.signatures_dir = self.config.get('Signatures', 'Directory')
                if self.config.has_option('Signatures', 'UpdateURL'):
                    self.update_url = self.config.get('Signatures', 'UpdateURL')

            # Load attack detection thresholds
            if self.config.has_section('Thresholds'):
                for attack_type in self.attack_thresholds:
                    if self.config.has_option('Thresholds', attack_type):
                        threshold = self.config.getint('Thresholds', attack_type)
                        self.attack_thresholds[attack_type] = threshold

            # Load whitelist IP addresses
            if self.config.has_section('Whitelist'):
                if self.config.has_option('Whitelist', 'IPs'):
                    whitelist_ips = self.config.get('Whitelist', 'IPs')
                    if whitelist_ips:
                        self.whitelist = [ip.strip() for ip in whitelist_ips.split(',')]

            # Load Snort settings
            if self.config.has_section('Snort'):
                if self.config.has_option('Snort', 'Enabled'):
                    self.snort_enabled = self.config.getboolean('Snort', 'Enabled')
                if self.config.has_option('Snort', 'UnixSocket'):
                    self.snort_unix_socket = self.config.get('Snort', 'UnixSocket')
                if self.config.has_option('Snort', 'SnortRulesPath'):
                    self.snort_rules_path = self.config.get('Snort', 'SnortRulesPath')
                if self.config.has_option('Snort', 'Snortdroppath'):
                    self.snort_drop_rules_path = self.config.get('Snort', 'Snortdroppath')

        except Exception as e:
            print(f"Error loading configuration: {str(e)}")
            print("Using default configuration")  # Fallback to defaults if anything fails

    def create_default_config(self, config_file: str):
        """
        Create a default configuration file if none exists
        
        Args:
            config_file: Path to the configuration file to create
        """
        # Fill all config sections with current default values

        self.config['Network'] = {
            'Interface': self.interface
        }

        self.config['Logging'] = {
            'LogFile': self.log_file,
            'LogLevel': 'INFO'
        }

        self.config['Signatures'] = {
            'Directory': self.signatures_dir,
            'UpdateURL': self.update_url
        }

        self.config['Thresholds'] = {
            attack_type: str(threshold)
            for attack_type, threshold in self.attack_thresholds.items()
        }

        self.config['Whitelist'] = {
            'IPs': '127.0.0.1'  # Default localhost IP as whitelisted
        }

        self.config['Snort'] = {
            'Enabled': str(self.snort_enabled),
            'UnixSocket': self.snort_unix_socket,
            'SnortRulesPath': self.snort_rules_path,
            'Snortdroppath': self.snort_drop_rules_path
        }

        # Save the config file to disk
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)  # Ensure directory exists
            with open(config_file, 'w') as f:
                self.config.write(f)  # Write all config sections to file
        except Exception as e:
            print(f"Error creating configuration file: {str(e)}")

    def _parse_log_level(self, level_str: str) -> int:
        """
        Convert string log level (e.g., 'INFO') into logging module constant
        
        Args:
            level_str: String form of the log level
            
        Returns:
            Python logging level constant
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return level_map.get(level_str.upper(), logging.INFO)  # Default to INFO if unknown

    def get_attack_threshold(self, attack_type: str) -> int:
        """
        Get the threshold confidence value for a given attack type
        
        Args:
            attack_type: Name of the attack (e.g., 'sql_injection')
            
        Returns:
            Confidence threshold (0-100)
        """
        return self.attack_thresholds.get(attack_type, 70)  # Default is 70

    def set_attack_threshold(self, attack_type: str, threshold: int):
        """
        Set or update the threshold confidence value for a specific attack
        
        Args:
            attack_type: Name of the attack
            threshold: New threshold value (0-100)
        
        Raises:
            ValueError: If threshold is outside the allowed range
        """
        if 0 <= threshold <= 100:
            self.attack_thresholds[attack_type] = threshold  # Update in memory
            if self.config.has_section('Thresholds'):
                self.config['Thresholds'][attack_type] = str(threshold)  # Update in file object
        else:
            raise ValueError("Threshold must be between 0 and 100")  # Prevent invalid values
