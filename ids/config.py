import os
import configparser
import logging
from typing import Dict

class Config:
    """Configuration manager for IDS"""
    
    def __init__(self, config_file: str = "config.ini"):
        """
        Initialize configuration
        
        Args:
            config_file: Path to the configuration file
        """
        self.config = configparser.ConfigParser()
        
        # Set default values
        self.interface = "eth0"
        self.log_file = "/home/kali/IDS/ids.log"
        self.log_level = logging.INFO
        self.signatures_dir = "signatures"
        self.update_url = ""
        self.attack_thresholds = {
            "sql_injection": 80,
            "xss": 80,
            "dos_ddos": 80,
            "phishing": 80,
            "malware": 80,
            "darkweb": 80,
            
        }
        self.whitelist = []
        
        # Snort integration defaults
        self.snort_enabled = True
        self.snort_unix_socket = "/usr/local/etc/snort/snort_alert.sock"
        self.snort_rules_path = "/usr/local/etc/rules/snort3-community-rules/snort3-community.rules"
        self.snort_drop_rules_path = "/usr/local/etc/rules/drop-pack"

	        
        # Load or create configuration file
        if os.path.exists(config_file):
            self.load_config(config_file)
        else:
            self.create_default_config(config_file)
         
 
    def load_config(self, config_file: str):
        """
        Load configuration from file
        
        Args:
            config_file: Path to the configuration file
        """
        try:
            self.config.read(config_file)
            
            # Network settings
            if self.config.has_section('Network'):
                if self.config.has_option('Network', 'Interface'):
                    self.interface = self.config.get('Network', 'Interface')
            
            # Logging settings
            if self.config.has_section('Logging'):
                if self.config.has_option('Logging', 'LogFile'):
                    self.log_file = self.config.get('Logging', 'LogFile')
                if self.config.has_option('Logging', 'LogLevel'):
                    level_str = self.config.get('Logging', 'LogLevel')
                    self.log_level = self._parse_log_level(level_str)
            
            # Signatures settings
            if self.config.has_section('Signatures'):
                if self.config.has_option('Signatures', 'Directory'):
                    self.signatures_dir = self.config.get('Signatures', 'Directory')
                if self.config.has_option('Signatures', 'UpdateURL'):
                    self.update_url = self.config.get('Signatures', 'UpdateURL')
            
            # Attack threshold settings
            if self.config.has_section('Thresholds'):
                for attack_type in self.attack_thresholds:
                    if self.config.has_option('Thresholds', attack_type):
                        threshold = self.config.getint('Thresholds', attack_type)
                        self.attack_thresholds[attack_type] = threshold
            
            # Whitelist settings
            if self.config.has_section('Whitelist'):
                if self.config.has_option('Whitelist', 'IPs'):
                    whitelist_ips = self.config.get('Whitelist', 'IPs')
                    if whitelist_ips:
                        self.whitelist = [ip.strip() for ip in whitelist_ips.split(',')]
            
            # Snort integration settings
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
            print("Using default configuration")
    
    def create_default_config(self, config_file: str):
        """
        Create default configuration file
        
        Args:
            config_file: Path to the configuration file to create
        """
        # Network section
        self.config['Network'] = {
            'Interface': self.interface
        }
        
        # Logging section
        self.config['Logging'] = {
            'LogFile': self.log_file,
            'LogLevel': 'INFO'
        }
        
        # Signatures section
        self.config['Signatures'] = {
            'Directory': self.signatures_dir,
            'UpdateURL': self.update_url
        }
        
        # Thresholds section
        self.config['Thresholds'] = {
            attack_type: str(threshold) 
            for attack_type, threshold in self.attack_thresholds.items()
        }
        
        # Whitelist section
        self.config['Whitelist'] = {
            'IPs': '127.0.0.1'
        }
        
        # Snort integration section
        self.config['Snort'] = {
            'Enabled': str(self.snort_enabled),
            'UnixSocket': self.snort_unix_socket,
            'SnortRulesPath': self.snort_rules_path,
            'Snortdroppath': self.snort_drop_rules_path
        }
        
        # Write to file
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                self.config.write(f)
        except Exception as e:
            print(f"Error creating configuration file: {str(e)}")
    
    def _parse_log_level(self, level_str: str) -> int:
        """
        Parse log level string to logging module constant
        
        Args:
            level_str: String representation of log level
            
        Returns:
            Logging level constant
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        
        return level_map.get(level_str.upper(), logging.INFO)
    
    def get_attack_threshold(self, attack_type: str) -> int:
        """
        Get threshold for specific attack type
        
        Args:
            attack_type: Type of attack
            
        Returns:
            Confidence threshold for alerting (percentage 0-100)
        """
        return self.attack_thresholds.get(attack_type, 70)
    
    def set_attack_threshold(self, attack_type: str, threshold: int):
        """
        Set threshold for specific attack type
        
        Args:
            attack_type: Type of attack
            threshold: Confidence threshold for alerting (percentage 0-100)
        """
        if 0 <= threshold <= 100:
            self.attack_thresholds[attack_type] = threshold
            # Also update in config file if it exists
            if self.config.has_section('Thresholds'):
                self.config['Thresholds'][attack_type] = str(threshold)
        else:
            raise ValueError("Threshold must be between 0 and 100")
