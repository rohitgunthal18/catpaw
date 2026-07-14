"""Network behavior analysis for RepoSentinel.

Detects hardcoded IP addresses, suspicious ports, known malicious domains,
and generic C2 communication patterns.
"""

import ipaddress
import re
from typing import List, Tuple

from reposentinel.database.severity import Finding


class NetworkAnalyzer:
    """Analyzes network behavior in source code."""

    # Regex for IPs, URLs, domains
    IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    URL_PATTERN = re.compile(r'https?://[^\s\"\'<>]+', re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

    # Ports often used by malware (not an exhaustive list, but high signal)
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        5555: "Android ADB / Malware",
        8888: "C2 / Proxy",
        1337: "Elite (Malware)",
        31337: "Back Orifice / Elite",
        6666: "IRC / Botnet",
        6667: "IRC / Botnet",
        9001: "Tor / Malware C2",
        4443: "Alternative HTTPS / C2"
    }

    KNOWN_SAFE_DOMAINS = {
        'github.com', 'raw.githubusercontent.com', 'pypi.org', 'npmjs.com',
        'google.com', 'googleapis.com', 'stackoverflow.com', 'python.org',
        'mozilla.org', 'microsoft.com', 'amazonaws.com', 'cloudflare.com',
        'readthedocs.io', 'readthedocs.org', 'travis-ci.org', 'circleci.com',
        'docker.com', 'apache.org', 'w3.org', 'github.io', 'npm.pkg.github.com'
    }

    def scan_file(self, file_path: str, content: str, lines: List[str],
                  language: str) -> Tuple[List[Finding], List[str]]:
        """Analyze network behavior in code.

        Args:
            file_path: Path to the file.
            content: Full file content.
            lines: List of lines.
            language: Detected programming language.

        Returns:
            Tuple of (findings list, list of network indicators like IPs/domains).
        """
        findings = []
        indicators = set()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(('#', '//', '/*', '*')):
                continue

            # 1. Check for IP addresses
            for ip_match in self.IP_PATTERN.finditer(line_stripped):
                ip_str = ip_match.group(0)
                indicators.add(f"IP: {ip_str}")
                
                if not self._is_private_ip(ip_str):
                    findings.append(Finding(
                        rule_id="NET-PUBLIC-IP",
                        name="Hardcoded Public IP",
                        category="network",
                        subcategory="hardcoded_ip",
                        severity="medium",
                        weight=45,
                        description=f"Hardcoded public IP address: {ip_str}",
                        user_message=f"🟡 Hardcoded internet IP address ({ip_str}) — scripts shouldn't usually hardcode IPs",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_stripped[:150],
                        matched_pattern=ip_str,
                        mitre_attack="T1071",
                    ))

            # 2. Check for suspicious ports
            # Look for port-like patterns (e.g., :4444, port=4444)
            for port, desc in self.SUSPICIOUS_PORTS.items():
                port_str = str(port)
                if re.search(r'\b' + port_str + r'\b', line_stripped):
                    # Reduce false positives by checking context
                    if any(kw in line_stripped.lower() for kw in ['port', ':', 'connect', 'bind', 'listen']):
                        indicators.add(f"Port: {port}")
                        findings.append(Finding(
                            rule_id="NET-SUSP-PORT",
                            name=f"Suspicious Port ({port})",
                            category="network",
                            subcategory="suspicious_port",
                            severity="high",
                            weight=65,
                            description=f"Uses suspicious port {port} ({desc})",
                            user_message=f"🟠 Uses network port {port} — often used by malware ({desc})",
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line_stripped[:150],
                            matched_pattern=port_str,
                            mitre_attack="T1071",
                        ))

            # 3. Check for URLs with suspicious domains
            for url_match in self.URL_PATTERN.finditer(line_stripped):
                url = url_match.group(0)
                try:
                    # Very basic URL parsing
                    domain = url.split('://')[1].split('/')[0].split(':')[0].lower()
                    indicators.add(f"Domain: {domain}")
                    
                    if self._is_suspicious_domain(domain):
                        findings.append(Finding(
                            rule_id="NET-SUSP-DOMAIN",
                            name="Suspicious Domain",
                            category="network",
                            subcategory="suspicious_domain",
                            severity="medium",
                            weight=50,
                            description=f"Connects to unknown/suspicious domain: {domain}",
                            user_message=f"🟡 Connects to domain: {domain} — verify this is a trusted service",
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line_stripped[:150],
                            matched_pattern=domain,
                            mitre_attack="T1071",
                        ))
                except IndexError:
                    pass

        return findings, sorted(list(indicators))

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private (RFC 1918) or localhost."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local
        except ValueError:
            return False  # Not a valid IP, treat as public/unknown to be safe

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious (not in safe list, uses IP, etc.)."""
        # If it's an IP address, we handled it in the IP check
        if self.IP_PATTERN.match(domain):
            return False
            
        # Strip subdomains for known safe check (e.g., api.github.com -> github.com)
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = f"{parts[-2]}.{parts[-1]}"
            if base_domain in self.KNOWN_SAFE_DOMAINS:
                return False
                
        # Known safe exact match
        if domain in self.KNOWN_SAFE_DOMAINS:
            return False
            
        # Free dynamic DNS providers (often abused)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
            
        # Known dynamic DNS services
        dynamic_dns = ['duckdns.org', 'no-ip.com', 'dyndns.org', 'ddns.net']
        if any(domain.endswith(ddns) for ddns in dynamic_dns):
            return True

        # Treat unknown domains as potentially suspicious for info
        return True
