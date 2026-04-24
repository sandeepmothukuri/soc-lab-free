#!/usr/bin/env python3
"""
alert-correlator.py — Cross-tool alert correlation for SOC Lab
Reads Wazuh alerts and correlates events across OpenVAS, pfSense,
PMG, and Lynis to surface compound attack scenarios.

Think of this as a simplified SOAR (Security Orchestration, Automation
and Response) engine — the kind of logic Splunk ES or IBM QRadar provides.

Usage:
    python3 alert-correlator.py --wazuh-api https://192.168.10.10:55000 \
        --wazuh-user admin --wazuh-pass YOUR_PASS
"""

import argparse
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)


class WazuhAPI:
    """Thin wrapper around the Wazuh REST API."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()
        self.session.verify = False

    def authenticate(self) -> bool:
        try:
            resp = self.session.get(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                timeout=10
            )
            self.token = resp.json()['data']['token']
            self.session.headers['Authorization'] = f"Bearer {self.token}"
            log.info(f"Authenticated to Wazuh API at {self.base_url}")
            return True
        except Exception as e:
            log.error(f"Auth failed: {e}")
            return False

    def get_alerts(self, limit: int = 500, offset: int = 0, query: str = None) -> List[Dict]:
        """Get recent alerts from Wazuh OpenSearch."""
        try:
            params = {"limit": limit, "offset": offset, "sort": "-timestamp"}
            if query:
                params["q"] = query

            # Use the Wazuh API alerts endpoint
            resp = self.session.get(
                f"{self.base_url}/security/events",
                params=params,
                timeout=30
            )
            data = resp.json()
            return data.get('data', {}).get('affected_items', [])
        except Exception as e:
            log.error(f"Failed to get alerts: {e}")
            return []


class CorrelationEngine:
    """
    Correlates alerts across multiple security tools to detect
    compound attack scenarios.
    """

    def __init__(self, wazuh: WazuhAPI):
        self.wazuh = wazuh
        self.ip_timeline: Dict[str, List[Dict]] = defaultdict(list)  # IP → events
        self.seen_correlations = set()

    def analyze_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Build per-IP timelines and run correlation rules."""

        # Group by source IP
        for alert in alerts:
            src_ip = (alert.get('data', {}).get('srcip') or
                      alert.get('agent', {}).get('ip') or
                      'unknown')
            self.ip_timeline[src_ip].append({
                "timestamp": alert.get('timestamp', ''),
                "rule_id": alert.get('rule', {}).get('id', ''),
                "rule_level": alert.get('rule', {}).get('level', 0),
                "rule_desc": alert.get('rule', {}).get('description', ''),
                "groups": alert.get('rule', {}).get('groups', []),
                "agent": alert.get('agent', {}).get('name', ''),
            })

        correlations = []

        # Run all correlation scenarios
        for src_ip, events in self.ip_timeline.items():
            if src_ip == 'unknown':
                continue

            correlations += self._check_brute_then_success(src_ip, events)
            correlations += self._check_scan_then_exploit(src_ip, events)
            correlations += self._check_phish_then_network(src_ip, events)
            correlations += self._check_vuln_then_attack(src_ip, events)
            correlations += self._check_lateral_chain(src_ip, events)

        return correlations

    def _check_brute_then_success(self, src_ip: str, events: List[Dict]) -> List[Dict]:
        """
        Scenario: SSH brute force → Successful login from same IP
        MITRE: T1110 (Brute Force) → T1021 (Remote Services)
        """
        correlations = []

        has_brute = any(
            evt['rule_id'] in ('5763', '5764', '100010') or
            'brute_force' in evt.get('groups', [])
            for evt in events
        )
        has_success = any(
            evt['rule_id'] in ('5715', '5716') and
            'authentication_success' in evt.get('groups', [])
            for evt in events
        )

        if has_brute and has_success:
            key = f"brute_success_{src_ip}"
            if key not in self.seen_correlations:
                self.seen_correlations.add(key)
                correlations.append({
                    "correlation_type": "BRUTE_FORCE_THEN_SUCCESS",
                    "severity": "CRITICAL",
                    "wazuh_level": 15,
                    "src_ip": src_ip,
                    "description": f"Brute force followed by successful SSH login from {src_ip}",
                    "mitre": "T1110 → T1021.004",
                    "recommended_action": "Isolate source IP, investigate session, check for persistence",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return correlations

    def _check_scan_then_exploit(self, src_ip: str, events: List[Dict]) -> List[Dict]:
        """
        Scenario: Port scan detected → Web/service attack from same IP
        MITRE: T1046 (Network Scan) → T1190 (Exploit Public-Facing App)
        """
        correlations = []

        has_scan = any(
            'recon' in evt.get('groups', []) or
            evt['rule_id'] in ('100001', '100002')
            for evt in events
        )
        has_exploit = any(
            evt['rule_level'] >= 10 and
            any(g in evt.get('groups', []) for g in ['web', 'attack', 'exploit'])
            for evt in events
        )

        if has_scan and has_exploit:
            key = f"scan_exploit_{src_ip}"
            if key not in self.seen_correlations:
                self.seen_correlations.add(key)
                correlations.append({
                    "correlation_type": "SCAN_THEN_EXPLOIT",
                    "severity": "HIGH",
                    "wazuh_level": 12,
                    "src_ip": src_ip,
                    "description": f"Reconnaissance scan followed by exploitation attempt from {src_ip}",
                    "mitre": "T1046 → T1190",
                    "recommended_action": "Block source IP at pfSense, review web server logs",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return correlations

    def _check_phish_then_network(self, src_ip: str, events: List[Dict]) -> List[Dict]:
        """
        Scenario: Phishing email blocked → Same source IP active in network
        MITRE: T1566 (Phishing) → T1041 (Exfiltration)
        """
        correlations = []

        has_mail_block = any(
            evt['rule_id'] in ('100080', '100081') or
            'phishing' in evt.get('groups', [])
            for evt in events
        )
        has_network_activity = any(
            evt['rule_level'] >= 8 and
            any(g in evt.get('groups', []) for g in ['recon', 'exfiltration', 'c2'])
            for evt in events
        )

        if has_mail_block and has_network_activity:
            key = f"phish_network_{src_ip}"
            if key not in self.seen_correlations:
                self.seen_correlations.add(key)
                correlations.append({
                    "correlation_type": "PHISHING_THEN_NETWORK",
                    "severity": "HIGH",
                    "wazuh_level": 12,
                    "src_ip": src_ip,
                    "description": f"Email from {src_ip} blocked as phishing, same IP now active in network",
                    "mitre": "T1566 → T1041",
                    "recommended_action": "Block IP, investigate if any email recipients clicked links",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return correlations

    def _check_vuln_then_attack(self, src_ip: str, events: List[Dict]) -> List[Dict]:
        """
        Scenario: OpenVAS found Critical vuln on host → Attack traffic to that host's service
        This catches 'vulnerability exists AND is being actively exploited' scenarios.
        """
        correlations = []

        has_critical_vuln = any(
            evt['rule_id'] in ('100070',) or
            'openvas' in evt.get('groups', [])
            for evt in events
        )
        has_high_alert = any(evt['rule_level'] >= 10 for evt in events)

        if has_critical_vuln and has_high_alert:
            key = f"vuln_attack_{src_ip}"
            if key not in self.seen_correlations:
                self.seen_correlations.add(key)
                correlations.append({
                    "correlation_type": "KNOWN_VULN_UNDER_ATTACK",
                    "severity": "CRITICAL",
                    "wazuh_level": 15,
                    "src_ip": src_ip,
                    "description": f"Critical vulnerability detected by OpenVAS on {src_ip} and high-severity alerts firing",
                    "mitre": "T1190",
                    "recommended_action": "URGENT: Patch or isolate affected host immediately",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return correlations

    def _check_lateral_chain(self, src_ip: str, events: List[Dict]) -> List[Dict]:
        """
        Scenario: Successful login from one internal host to multiple others
        MITRE: T1021 (Remote Services) lateral movement
        """
        correlations = []
        lateral_events = [
            e for e in events if
            e['rule_id'] in ('100030', '100031') or
            'lateral_movement' in e.get('groups', [])
        ]

        if len(lateral_events) >= 3:
            agents = set(e['agent'] for e in lateral_events)
            if len(agents) >= 2:
                key = f"lateral_{src_ip}"
                if key not in self.seen_correlations:
                    self.seen_correlations.add(key)
                    correlations.append({
                        "correlation_type": "LATERAL_MOVEMENT_CHAIN",
                        "severity": "CRITICAL",
                        "wazuh_level": 15,
                        "src_ip": src_ip,
                        "description": f"Lateral movement detected: {src_ip} connected to {len(agents)} hosts ({', '.join(agents)})",
                        "mitre": "T1021.004",
                        "recommended_action": "Isolate source, review all sessions from this IP, check for persistence",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

        return correlations


def format_correlation_alert(correlation: Dict) -> str:
    """Format a correlation finding for display."""
    return (
        f"\n{'='*60}\n"
        f"[{correlation['severity']}] {correlation['correlation_type']}\n"
        f"  Source IP:   {correlation['src_ip']}\n"
        f"  Description: {correlation['description']}\n"
        f"  MITRE:       {correlation['mitre']}\n"
        f"  Action:      {correlation['recommended_action']}\n"
        f"  Time:        {correlation['timestamp']}\n"
        f"{'='*60}"
    )


def main():
    parser = argparse.ArgumentParser(description="SOC Lab Alert Correlator")
    parser.add_argument('--wazuh-api', default='https://192.168.10.10:55000')
    parser.add_argument('--wazuh-user', default='admin')
    parser.add_argument('--wazuh-pass', required=True)
    parser.add_argument('--interval', type=int, default=60, help='Poll interval (seconds)')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    args = parser.parse_args()

    wazuh = WazuhAPI(args.wazuh_api, args.wazuh_user, args.wazuh_pass)

    if not wazuh.authenticate():
        log.error("Cannot authenticate to Wazuh API. Check credentials.")
        sys.exit(1)

    engine = CorrelationEngine(wazuh)
    log.info("Alert Correlator started — watching for compound attack scenarios...")

    while True:
        log.info("Polling Wazuh for recent alerts...")
        alerts = wazuh.get_alerts(limit=500)

        if alerts:
            log.info(f"Analyzing {len(alerts)} alerts...")
            correlations = engine.analyze_alerts(alerts)

            if correlations:
                log.warning(f"\n*** {len(correlations)} CORRELATION(S) DETECTED ***")
                for c in correlations:
                    print(format_correlation_alert(c))

                # Log to file
                with open('/var/log/soc-correlations.jsonl', 'a') as f:
                    for c in correlations:
                        f.write(json.dumps(c) + '\n')
            else:
                log.info("No compound attack patterns detected")
        else:
            log.warning("No alerts returned from Wazuh API")

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == '__main__':
    main()
