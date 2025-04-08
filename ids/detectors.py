"""
Detectors Module

This module contains detector classes for different types of attacks.
Each detector implements pattern matching logic specific to an attack type.
"""

import re
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Union

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Raw
except ImportError:
    print("Error: Scapy package not found. Please install with 'pip install scapy'")
    import sys

    sys.exit(1)

from signatures import SignatureDatabase


class BaseDetector(ABC):
    """Base detector class that all specific detectors inherit from"""

    def __init__(self, config):
        """
        Initialize the detector

        Args:
            config: Configuration object with detection settings
        """
        self.config = config
        self.signature_db = SignatureDatabase(config)
        self.attack_type = "Unknown"

    @abstractmethod
    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        """
        Detect attacks in the given packet

        Args:
            packet: Scapy packet to analyze

        Returns:
            Tuple of (attack_type, details) if attack detected, None otherwise
        """
        pass

    def _extract_payload(self, packet) -> Optional[bytes]:
        """
        Extract payload data from packet for inspection

        Args:
            packet: Scapy packet

        Returns:
            Payload bytes if available, None otherwise
        """
        payload = None

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
        elif hasattr(packet, 'load'):
            payload = packet.load

        return payload

    def _match_regex_patterns(self, data: Union[str, bytes], patterns: List[Dict]) -> Optional[Dict]:
        """
        Match data against regex patterns with enhanced validation to eliminate false positives

        Args:
            data: String or bytes data to match against
            patterns: List of pattern dictionaries

        Returns:
            Match details dictionary if matched, None otherwise
        """
        if not data:
            return None

        # Convert bytes to string if needed
        if isinstance(data, bytes):
            try:
                data_str = data.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                data_str = str(data)
        else:
            data_str = data

        # Skip very short data as it's unlikely to contain attacks
        if len(data_str) < 10:
            return None

        # Check for unambiguous text that would indicate this is not an attack
        safe_indicators = [
            'Content-Type:',
            'User-Agent:',
            'Accept:',
            'Host:',
            'Referer:',
            'Connection:',
            'Cache-Control:',
            'Date:',
            'Content-Length:',
            'Authorization:',
            'Cookie:',
            'Server:',
            'Expires:',
            'Last-Modified:',
            'ETag:',
            'X-Requested-With:',
            'X-Frame-Options:',
            'Server:',
            'X-Powered-By:',
            'Pragma:',
            'Last-Modified:',
            '<!DOCTYPE html>',
            '<html',
            '</html>',
            '<head>',
            '<body>',
            '<div>',
            'HTTP/',
            'OPTIONS ',
            'GET /',
            'POST /',
            'HEAD /',
            'function(',
            'var ',
            'const ',
            'let ',
            'window.',
            'document.',
            'addEventListener',
            '<link rel=',
            '<meta ',
            '<title>',
            '<script src=',
            '<style>',
            '@media'
        ]

        # Quick check for common HTTP headers/content (not normally attack vectors)
        # For byte strings, convert indicators to bytes for comparison
        is_normal_http = False
        try:
            if isinstance(data, bytes):
                # Convert indicators to bytes and check if any are in the data
                for indicator in safe_indicators:
                    indicator_bytes = indicator.encode()
                    if indicator_bytes in data:
                        is_normal_http = True
                        break
            else:
                # For string data, check directly
                for indicator in safe_indicators:
                    if indicator in data_str:
                        is_normal_http = True
                        break
        except:
            # If any error occurs during comparison, don't mark as normal HTTP
            pass

        for pattern in patterns:
            if 'regex' in pattern:
                match = pattern['regex'].search(data_str)
                if match:
                    matched_text = match.group(0)

                    # Base confidence score
                    confidence = 75

                    # Increase confidence based on factors that indicate a real attack
                    if 'SELECT' in matched_text.upper() and 'FROM' in matched_text.upper():
                        confidence += 10
                    if 'UNION' in matched_text.upper() and 'SELECT' in matched_text.upper():
                        confidence += 15
                    if 'script' in matched_text.lower() and 'alert' in matched_text.lower():
                        confidence += 15
                    if '%20' in matched_text or '%27' in matched_text:  # URL encoded spaces or quotes
                        confidence += 10
                    if len(matched_text) > 30:  # Longer matches are more likely to be real attacks
                        confidence += 5

                    # Decrease confidence if this appears to be normal HTTP traffic
                    if is_normal_http:
                        confidence -= 30

                    # Only return high-confidence matches
                    if confidence >= 85:
                        return {
                            'message': f"Detected {pattern['description']}",
                            'signature': pattern['regex'].pattern,
                            'matched_text': matched_text,
                            'severity': pattern.get('severity', 'MEDIUM'),
                            'confidence': confidence
                        }
            elif 'yara_rule' in pattern and hasattr(pattern['yara_rule'], 'match'):
                # Handle Yara rules if present
                try:
                    matches = pattern['yara_rule'].match(data=data)
                    if matches:
                        return {
                            'message': f"Matched Yara rule: {matches[0].rule}",
                            'signature': f"Yara rule: {matches[0].rule}",
                            'severity': pattern.get('severity', 'HIGH'),
                            'confidence': 95
                        }
                except Exception:
                    # Yara matching might fail for various reasons
                    pass

        return None


class SQLInjectionDetector(BaseDetector):
    """Detector for SQL Injection attacks"""

    def __init__(self, config):
        super().__init__(config)
        self.attack_type = "SQL Injection"

    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        # Get HTTP request data if available
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = self._extract_payload(packet)
            if payload:
                patterns = self.signature_db.get_patterns("sql_injection")
                match = self._match_regex_patterns(payload, patterns)
                if match:
                    return (self.attack_type, match)

        return None


class XSSDetector(BaseDetector):
    """Detector for Cross-Site Scripting (XSS) attacks"""

    def __init__(self, config):
        super().__init__(config)
        self.attack_type = "Cross-Site Scripting"

    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        # Check HTTP data for XSS payloads
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = self._extract_payload(packet)
            if payload:
                patterns = self.signature_db.get_patterns("xss")
                match = self._match_regex_patterns(payload, patterns)
                if match:
                    return (self.attack_type, match)

        return None


class DosDetector(BaseDetector):
    """Detector for DoS and DDoS attacks"""

    def __init__(self, config):
        super().__init__(config)
        self.attack_type = "DoS/DDoS Attack"

        # Initialize state for tracking
        self.state = {
            'syn_counts': {},  # Track SYN packets by source
            'last_cleanup': time.time(),  # Last time we cleaned up old entries
            'detection_window': 5,  # Time window in seconds
            'syn_threshold': 50,  # SYN packets threshold in window
            'ping_counts': {},  # Track ICMP echo requests
            'ping_threshold': 50,  # ICMP echo request threshold
            'http_counts': {},  # Track HTTP requests
            'http_threshold': 200  # HTTP request threshold
        }

    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        # First check if packet contains DoS tool signatures
        if packet.haslayer(scapy.Raw):
            payload = self._extract_payload(packet)
            if payload:
                patterns = self.signature_db.get_patterns("dos_ddos")
                match = self._match_regex_patterns(payload, patterns)
                if match:
                    return (self.attack_type, match)

        # Check for SYN flood
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags & 0x02:  # SYN flag set
            result = self._check_syn_flood(packet)
            if result:
                return (self.attack_type, result)

        # Check for ICMP flood
        if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 8:  # Echo Request
            result = self._check_icmp_flood(packet)
            if result:
                return (self.attack_type, result)

        # Check for HTTP flood
        if self._is_http_request(packet):
            result = self._check_http_flood(packet)
            if result:
                return (self.attack_type, result)

        # Clean up old entries periodically
        current_time = time.time()
        if current_time - self.state['last_cleanup'] > 10:  # Clean every 10 seconds
            self._cleanup_old_entries(current_time)
            self.state['last_cleanup'] = current_time

        return None

    def _is_http_request(self, packet) -> bool:
        """Check if packet contains an HTTP request"""
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                return payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD '))
            except:
                return False
        return False

    def _check_syn_flood(self, packet) -> Optional[Dict]:
        """Check for SYN flood attacks"""
        if not packet.haslayer(scapy.IP):
            return None

        src_ip = packet[scapy.IP].src
        current_time = time.time()

        if src_ip not in self.state['syn_counts']:
            self.state['syn_counts'][src_ip] = {'count': 0, 'first_seen': current_time}

        self.state['syn_counts'][src_ip]['count'] += 1

        # Check if count exceeds threshold within window
        count = self.state['syn_counts'][src_ip]['count']
        first_seen = self.state['syn_counts'][src_ip]['first_seen']

        if current_time - first_seen <= self.state['detection_window'] and count >= self.state['syn_threshold']:
            # Reset counter after detection
            self.state['syn_counts'][src_ip] = {'count': 0, 'first_seen': current_time}

            return {
                'message': f"SYN flood detected from {src_ip}",
                'signature': "SYN packet rate exceeded threshold",
                'severity': 'HIGH',
                'confidence': 80,
                'count': count,
                'window': self.state['detection_window']
            }

        return None

    def _check_icmp_flood(self, packet) -> Optional[Dict]:
        """Check for ICMP flood attacks"""
        if not packet.haslayer(scapy.IP):
            return None

        src_ip = packet[scapy.IP].src
        current_time = time.time()

        if src_ip not in self.state['ping_counts']:
            self.state['ping_counts'][src_ip] = {'count': 0, 'first_seen': current_time}

        self.state['ping_counts'][src_ip]['count'] += 1

        # Check if count exceeds threshold within window
        count = self.state['ping_counts'][src_ip]['count']
        first_seen = self.state['ping_counts'][src_ip]['first_seen']

        if current_time - first_seen <= self.state['detection_window'] and count >= self.state['ping_threshold']:
            # Reset counter after detection
            self.state['ping_counts'][src_ip] = {'count': 0, 'first_seen': current_time}

            return {
                'message': f"ICMP flood detected from {src_ip}",
                'signature': "ICMP packet rate exceeded threshold",
                'severity': 'HIGH',
                'confidence': 85,
                'count': count,
                'window': self.state['detection_window']
            }

        return None

    def _check_http_flood(self, packet) -> Optional[Dict]:
        """Check for HTTP flood attacks"""
        if not packet.haslayer(scapy.IP):
            return None

        src_ip = packet[scapy.IP].src
        current_time = time.time()

        if src_ip not in self.state['http_counts']:
            self.state['http_counts'][src_ip] = {'count': 0, 'first_seen': current_time}

        self.state['http_counts'][src_ip]['count'] += 1

        # Check if count exceeds threshold within window
        count = self.state['http_counts'][src_ip]['count']
        first_seen = self.state['http_counts'][src_ip]['first_seen']

        if current_time - first_seen <= self.state['detection_window'] and count >= self.state['http_threshold']:
            # Reset counter after detection
            self.state['http_counts'][src_ip] = {'count': 0, 'first_seen': current_time}

            return {
                'message': f"HTTP flood detected from {src_ip}",
                'signature': "HTTP request rate exceeded threshold",
                'severity': 'HIGH',
                'confidence': 85,
                'count': count,
                'window': self.state['detection_window']
            }

        return None

    def _cleanup_old_entries(self, current_time: float):
        """Remove old entries from tracking dictionaries"""
        window = self.state['detection_window']

        # Clean SYN tracking
        for ip in list(self.state['syn_counts'].keys()):
            if current_time - self.state['syn_counts'][ip]['first_seen'] > window:
                del self.state['syn_counts'][ip]

        # Clean ICMP tracking
        for ip in list(self.state['ping_counts'].keys()):
            if current_time - self.state['ping_counts'][ip]['first_seen'] > window:
                del self.state['ping_counts'][ip]

        # Clean HTTP tracking
        for ip in list(self.state['http_counts'].keys()):
            if current_time - self.state['http_counts'][ip]['first_seen'] > window:
                del self.state['http_counts'][ip]


class PhishingDetector(BaseDetector):
    """Detector for phishing attempts"""

    def __init__(self, config):
        super().__init__(config)
        self.attack_type = "Phishing Attempt"

        # List of common legitimate domains (to compare for typosquatting)
        self.common_domains = [
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "netflix.com", "paypal.com", "instagram.com",
            "twitter.com", "linkedin.com", "yahoo.com", "gmail.com"
        ]

    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = self._extract_payload(packet)
            if payload:
                # Check against phishing signatures
                patterns = self.signature_db.get_patterns("phishing")
                match = self._match_regex_patterns(payload, patterns)
                if match:
                    return (self.attack_type, match)

                # Check for domain typosquatting if HTTP data
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if any(x in payload_str for x in ['HTTP', 'GET', 'POST', 'Host:']):
                        result = self._check_domain_typosquatting(payload)
                        if result:
                            return (self.attack_type, result)
                except:
                    pass

        return None

    def _check_domain_typosquatting(self, payload: bytes) -> Optional[Dict]:
        """Check for typosquatting domains that could indicate phishing"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # Try to extract hostname from HTTP headers
            host_match = re.search(r'Host:\s+([^\r\n]+)', payload_str, re.IGNORECASE)
            if host_match:
                domain = host_match.group(1).strip()

                # Check if domain is similar to a common domain but not exact
                for common_domain in self.common_domains:
                    if domain != common_domain and self._similar_domain(domain, common_domain):
                        return {
                            'message': f"Potential typosquatting detected: {domain} similar to {common_domain}",
                            'signature': "Domain typosquatting",
                            'severity': 'MEDIUM',
                            'confidence': 85
                        }
        except Exception:
            pass

        return None

    def _similar_domain(self, domain1: str, domain2: str) -> bool:
        """
        Check if domains are similar using a simple distance metric
        This is a simplified implementation - a real one would use proper Levenshtein distance
        """
        # Quick exact check
        if domain1 == domain2:
            return False  # Exact match is not typosquatting

        # Remove common subdomains
        domain1 = domain1.lower().replace('www.', '')
        domain2 = domain2.lower().replace('www.', '')

        # Check for character substitution (o -> 0, i -> 1, etc.)
        d1_normalized = domain1.replace('0', 'o').replace('1', 'i').replace('3', 'e')
        d2_normalized = domain2.replace('0', 'o').replace('1', 'i').replace('3', 'e')
        if d1_normalized == d2_normalized:
            return True

        # Check for addition/removal of single character
        if len(domain1) == len(domain2) + 1 or len(domain1) == len(domain2) - 1:
            if domain1 in domain2 or domain2 in domain1:
                return True

        # Check for transposition of characters
        if len(domain1) == len(domain2):
            diff_count = sum(1 for a, b in zip(domain1, domain2) if a != b)
            if diff_count <= 2:
                return True

        # Check for addition of common TLDs (.com, .net, .org)
        d1_base = domain1.split('.')[0]
        d2_base = domain2.split('.')[0]
        if d1_base == d2_base:
            return True

        return False


class MalwareDetector(BaseDetector):
    """Detector for malware downloads and malicious traffic"""

    def __init__(self, config):
        super().__init__(config)
        self.attack_type = "Malware Activity"

        # Known malicious file extensions (narrowed down to more specific high-risk ones)
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr',
            '.pif', '.cmd', '.msi', '.msp'
        ]

        # Safe domains that should never trigger malware alerts
        self.safe_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'cloudflare.com', 'akamai.net', 'office365.com',
            'windows.com', 'adobe.com', 'mozilla.org', 'firefox.com'
        ]

    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        # Only process TCP packets with payload
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = self._extract_payload(packet)
            if not payload or len(payload) < 20:  # Ignore very small payloads
                return None

            # Skip payloads from safe domains
            if self._is_from_safe_domain(packet, payload):
                return None

            # Apply stricter detection logic
            if self._is_likely_normal_traffic(payload):
                return None

            # Check against malware signatures
            patterns = self.signature_db.get_patterns("malware")
            match = self._match_regex_patterns(payload, patterns)
            if match:
                # Increase detection threshold to require higher confidence
                if match.get('confidence', 0) < 90:
                    return None
                return (self.attack_type, match)

            # Check for suspicious downloads with stricter criteria
            result = self._check_malicious_download(payload)
            if result:
                return (self.attack_type, result)

        return None

    def _is_from_safe_domain(self, packet, payload) -> bool:
        """Check if traffic is from a known safe domain"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # Extract host from Host header if present
            host_match = re.search(r'Host:\s+([^\r\n]+)', payload_str, re.IGNORECASE)
            if host_match:
                host = host_match.group(1).lower()
                for safe_domain in self.safe_domains:
                    if safe_domain in host:
                        return True
        except:
            pass
        return False

    def _is_likely_normal_traffic(self, payload) -> bool:
        """Check if this is likely normal web traffic"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # Common patterns in normal web traffic
            normal_patterns = [
                # Static content
                r'\.css', r'\.js', r'\.png', r'\.jpg', r'\.gif', r'\.svg',
                # Common APIs
                r'/api/v\d', r'/graphql', r'/status',
                # Common HTTP headers
                r'Accept-Encoding:', r'Accept-Language:', r'Cache-Control:'
            ]

            # If multiple normal patterns are found, it's likely normal traffic
            pattern_matches = sum(1 for p in normal_patterns if re.search(p, payload_str, re.IGNORECASE))
            if pattern_matches >= 3:
                return True

            # Check for standard web page content
            if any(x in payload_str for x in ['<!DOCTYPE html>', '<html', '<head', '<body']):
                return True

        except:
            pass
        return False

    def _check_malicious_download(self, payload: bytes) -> Optional[Dict]:
        """Check for suspicious file downloads with improved accuracy"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # Only consider HTTP responses with executable content
            if 'HTTP/1.' in payload_str and 'Content-Type:' in payload_str:
                content_type = re.search(r'Content-Type:\s+([^\r\n]+)', payload_str, re.IGNORECASE)
                if content_type:
                    ct_value = content_type.group(1).lower()
                    # More specific content type matching
                    if any(x in ct_value for x in ['application/x-msdownload', 'application/exe']):
                        # Look for additional indicators to confirm
                        if 'Content-Disposition: attachment' in payload_str:
                            return {
                                'message': f"Suspicious file download detected with Content-Type: {ct_value}",
                                'signature': "Executable content type",
                                'severity': 'HIGH',
                                'confidence': 95
                            }

            # Check for download request with suspicious extensions
            if any(x in payload_str for x in ['GET', 'POST']):
                for ext in self.suspicious_extensions:
                    # More specific pattern matching
                    pattern = rf'(GET|POST)\s+.*{ext}(\?|\s|$)'
                    if re.search(pattern, payload_str, re.IGNORECASE):
                        # Double check it's not a legitimate download from CDN
                        if 'cdn.' not in payload_str and 'download.' not in payload_str:
                            return {
                                'message': f"Suspicious file download request with extension: {ext}",
                                'signature': "Malicious file extension",
                                'severity': 'MEDIUM',
                                'confidence': 90
                            }
        except Exception:
            pass

        return None


class DarkwebDetector(BaseDetector):
    """Detector for darkweb access attempts"""

    def __init__(self, config):
        super().__init__(config)
        self.attack_type = "Darkweb Access"

    def detect(self, packet) -> Optional[Tuple[str, Dict]]:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = self._extract_payload(packet)
            if payload:
                # Check against darkweb signatures
                patterns = self.signature_db.get_patterns("darkweb")
                match = self._match_regex_patterns(payload, patterns)
                if match:
                    return (self.attack_type, match)

        return None
