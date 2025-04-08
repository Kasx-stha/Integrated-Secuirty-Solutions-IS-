"""
Signatures Module

This module contains the signature patterns and rules for different attack types.
It provides a unified interface for loading and accessing signatures.
"""

import os
import re
import json
import urllib.request
from scapy.all import Raw
from typing import Dict, List, Optional

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class SignatureDatabase:
    """Signature database for attack detection"""

    def __init__(self, config):
        """
        Initialize the signature database

        Args:
            config: Configuration object with signature settings
        """
        self.config = config

        # Signature storage
        self.signatures = {
            "sql_injection": [],
            "xss": [],
            "dos_ddos": [],
            "phishing": [],
            "malware": [],
            "darkweb": [],

        }

        # Load signatures
        self._load_signatures()

    def _load_signatures(self):
        """Load all signatures from the signatures directory"""
        # First load built-in regex patterns
        self._load_regex_patterns()

        # Then load Yara rules if available
        if YARA_AVAILABLE:
            self._load_yara_rules()

    def _load_regex_patterns(self):
        """Load built-in regex patterns for attack types"""
        # SQL Injection patterns
        self.signatures["sql_injection"].extend([
            {
                "description": "SQL Injection - Basic SELECT",
                "regex": re.compile(r"(?i)\b(SELECT|UNION\s+SELECT)\b.*\bFROM\b"),
                "severity": "MEDIUM"
            },
            {
                "description": "SQL Injection - OR condition",
                "regex": re.compile(r"(?i)('|\")\s*OR\s*('|\")\s*('|\")\s*=\s*('|\")"),
                "severity": "MEDIUM"
            },
            {
                "description": "SQL Injection - Comment termination",
                "regex": re.compile(r"(?i)(\b(?:AND|OR)\b\s+[\w\d]+\s*=\s*[\w\d]+\s*--)|(?:;\s*--\s*$)"),
                "severity": "HIGH"
            },
            {
                "description": "SQL Injection - UNION attacks",
                "regex": re.compile(r"(?i)UNION\s+(?:ALL\s+)?SELECT"),
                "severity": "HIGH"
            },
            {
                "description": "SQL Injection - Blind",
                "regex": re.compile(r"(?i)(?:\bWAITFOR\b.*\bDELAY\b)|(?:\bBENCHMARK\b.*\()"),
                "severity": "HIGH"
            }
        ])

        # XSS patterns
        self.signatures["xss"].extend([
            {
                "description": "XSS - Basic script tags",
                "regex": re.compile(r"(?i)<script[^>]*>[^<]*<\/script>|<script[^>]*>"),
                "severity": "MEDIUM"
            },
            {
                "description": "XSS - Event handlers",
                "regex": re.compile(r"(?i)(?:\bon[a-z]{3,17}\s*=)|(?:javascript:)"),
                "severity": "MEDIUM"
            },
            {
                "description": "XSS - Alert or eval functions",
                "regex": re.compile(r"(?i)(?:\balert\s*\()|(?:\beval\s*\()"),
                "severity": "HIGH"
            },
            {
                "description": "XSS - HTML injection",
                "regex": re.compile(
                    r"(?i)<[a-z]{3,10}[^>]*>[^<]*(?:\balert\b|\bonfocus\b|\bonload\b)[^<]*<\/[a-z]{3,10}>"),
                "severity": "HIGH"
            }
        ])

        # DoS/DDoS patterns (tool signatures)
        self.signatures["dos_ddos"].extend([
            {
                "description": "DoS tool - LOIC signature",
                "regex": re.compile(r"(?i)loic|hoic|Low Orbit Ion Cannon|High Orbit Ion Cannon"),
                "severity": "HIGH"
            },
            {
                "description": "DoS tool - Slowloris signature",
                "regex": re.compile(r"(?i)slowloris|slow\s*http"),
                "severity": "HIGH"
            }
        ])

        # Phishing patterns
        self.signatures["phishing"].extend([
            {
                "description": "Phishing - Fake login forms",
                "regex": re.compile(r"(?i)<form[^>]*>.*?(?:user|login|email|password).*?<\/form>"),
                "severity": "MEDIUM"
            },
            {
                "description": "Phishing - Domain spoofing indicators",
                "regex": re.compile(r"(?i)(?:paypa1|g00gle|faceb00k|amaz0n|micros0ft)\.(?:com|net|org)"),
                "severity": "HIGH"
            },
            {
                "description": "Phishing - Common phishing keywords",
                "regex": re.compile(r"(?i)verify.*?account|confirm.*?payment|update.*?billing|security.*?alert"),
                "severity": "MEDIUM"
            }
        ])

        # Malware patterns
        self.signatures["malware"].extend([
            {
                "description": "Malware - Command and control patterns",
                "regex": re.compile(r"(?i)(?:bot|c2|command\s*control).*?(?:server|callback|beacon|check[_\s]*in)"),
                "severity": "HIGH"
            },
            {
                "description": "Malware - File download",
                "regex": re.compile(r"(?i)(?:\/[a-z0-9_\-]+\.exe|\.dll|\.ps1|\.bat|\.sh|\.cmd)\s+HTTP"),
                "severity": "MEDIUM"
            },
            {
                "description": "Malware - Base64 encoded PE headers",
                "regex": re.compile(r"(?:TVqQ|TVpQ|TVrh)AAA[A-Za-z0-9+/=]{20,}"),
                "severity": "HIGH"
            }
        ])

        # Darkweb patterns
        self.signatures["darkweb"].extend([
            {
                "description": "TOR network access",
                "regex": re.compile(r"(?i)\.onion|TorBrowser|tor\s*network|hidden\s*service"),
                "severity": "MEDIUM"
            },
            {
                "description": "Darkweb marketplace keywords",
                "regex": re.compile(r"(?i)silk\s*road|alphabay|dream\s*market|hydra\s*market|dark\s*market"),
                "severity": "HIGH"
            }
        ])


    def _load_yara_rules(self):
        """Load Yara rules from files if available"""
        if not YARA_AVAILABLE:
            return

        signatures_dir = "signatures"

        # Check if signatures directory exists
        if not os.path.exists(signatures_dir):
            os.makedirs(signatures_dir, exist_ok=True)

            # Create example Yara rules
            self._create_example_yara_rules(signatures_dir)

        # Load all .yar files from signatures directory
        try:
            for filename in os.listdir(signatures_dir):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    filepath = os.path.join(signatures_dir, filename)

                    try:
                        # Compile Yara rule
                        rule = yara.compile(filepath=filepath)

                        # Determine attack type from filename
                        if 'sql' in filename.lower():
                            self.signatures["sql_injection"].append({"yara_rule": rule, "severity": "HIGH"})
                        elif 'xss' in filename.lower():
                            self.signatures["xss"].append({"yara_rule": rule, "severity": "HIGH"})
                        elif 'dos' in filename.lower() or 'ddos' in filename.lower():
                            self.signatures["dos_ddos"].append({"yara_rule": rule, "severity": "HIGH"})
                        elif 'phish' in filename.lower():
                            self.signatures["phishing"].append({"yara_rule": rule, "severity": "HIGH"})
                        elif 'malware' in filename.lower():
                            self.signatures["malware"].append({"yara_rule": rule, "severity": "HIGH"})
                        elif 'darkweb' in filename.lower() or 'tor' in filename.lower():
                            self.signatures["darkweb"].append({"yara_rule": rule, "severity": "HIGH"})
                        else:
                            # If can't determine type, add to all categories
                            for attack_type in self.signatures:
                                self.signatures[attack_type].append({"yara_rule": rule, "severity": "MEDIUM"})
                    except Exception as e:
                        print(f"Error loading Yara rule {filepath}: {str(e)}")
        except Exception as e:
            print(f"Error loading Yara rules: {str(e)}")

    def _create_example_yara_rules(self, signatures_dir):
        """Create example Yara rules in the signatures directory"""
        examples = {
            "sql_injection.yar": """
rule SQL_Injection_Basic {
    meta:
        description = "Detects basic SQL injection attempts"
        severity = "high"
    strings:
        $sql1 = "UNION SELECT" nocase
        $sql2 = "1=1--" nocase
        $sql3 = "OR 1=1" nocase
        $sql4 = "' OR '" nocase
        $sql5 = "admin'--" nocase
    condition:
        any of them
}
""",
            "xss.yar": """
rule XSS_Basic_Script_Tags {
    meta:
        description = "Detects basic XSS attempts using script tags"
        severity = "high"
    strings:
        $xss1 = "<script>" nocase
        $xss2 = "alert(" nocase
        $xss3 = "document.cookie" nocase
        $xss4 = "javascript:" nocase
        $xss5 = "onerror=" nocase
    condition:
        any of them
}
""",
            "malware.yar": """
rule Malware_Executable_Download {
    meta:
        description = "Detects attempts to download executable files"
        severity = "high"
    strings:
        $exe1 = ".exe" nocase
        $exe2 = ".dll" nocase
        $exe3 = ".bat" nocase
        $exe4 = ".ps1" nocase
        $exe5 = "GET" nocase
    condition:
        any of ($exe*) and $exe5
}
""",
            "darkweb.yar": """
rule Darkweb_Tor_Access {
    meta:
        description = "Detects attempts to access TOR hidden services"
        severity = "medium"
    strings:
        $tor1 = ".onion" nocase
        $tor2 = "TorBrowser" nocase
        $tor3 = "hidden service" nocase
    condition:
        any of them
}
"""
        }

        for filename, content in examples.items():
            try:
                filepath = os.path.join(signatures_dir, filename)
                with open(filepath, 'w') as f:
                    f.write(content)
            except Exception as e:
                print(f"Error creating example Yara rule {filename}: {str(e)}")

    def update_signatures(self, signature_type: str = "all"):
        """
        Update signatures from remote source or local files

        Args:
            signature_type: Type of signatures to update (default is 'all')
        """
        # If update URL is specified in config, download signatures
        if self.config.update_url:
            try:
                update_url = self.config.update_url
                with urllib.request.urlopen(update_url) as response:
                    data = json.loads(response.read().decode('utf-8'))

                    # Process downloaded signatures
                    if signature_type == "all":
                        for attack_type, patterns in data.items():
                            if attack_type in self.signatures:
                                # Convert string patterns to compiled regex
                                for pattern in patterns:
                                    if "pattern" in pattern:
                                        pattern["regex"] = re.compile(pattern["pattern"])
                                        del pattern["pattern"]

                                # Update signatures
                                self.signatures[attack_type].extend(patterns)
                    elif signature_type in self.signatures and signature_type in data:
                        # Update only specific type
                        patterns = data[signature_type]
                        for pattern in patterns:
                            if "pattern" in pattern:
                                pattern["regex"] = re.compile(pattern["pattern"])
                                del pattern["pattern"]

                        self.signatures[signature_type].extend(patterns)
            except Exception as e:
                print(f"Error updating signatures: {str(e)}")

        # Reload Yara rules
        if YARA_AVAILABLE:
            self._load_yara_rules()

    def get_patterns(self, attack_type: str) -> List[Dict]:
        """
        Get patterns for a specific attack type

        Args:
            attack_type: Type of attack to get patterns for

        Returns:
            List of pattern dictionaries
        """
        if attack_type in self.signatures:
            return self.signatures[attack_type]
        return []

