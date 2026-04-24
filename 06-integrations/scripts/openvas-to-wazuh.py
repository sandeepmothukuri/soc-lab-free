#!/usr/bin/env python3
"""
openvas-to-wazuh.py — Integration: OpenVAS → Wazuh SIEM
Polls OpenVAS GMP API for completed scan results and forwards
vulnerability findings to Wazuh as structured syslog events.

Usage:
    python3 openvas-to-wazuh.py --help
    python3 openvas-to-wazuh.py --openvas-host 192.168.10.20 \
        --wazuh-host 192.168.10.10 --watch

Replaces: Tenable.sc → Splunk connector
"""

import argparse
import json
import logging
import socket
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Optional

# pip3 install python-gvm
try:
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeResultTransform
except ImportError:
    print("ERROR: python-gvm not installed. Run: pip3 install python-gvm")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

# CVSS → Wazuh severity mapping
SEVERITY_MAP = {
    (9.0, 10.0): {"level": 14, "label": "CRITICAL"},
    (7.0, 8.9):  {"level": 12, "label": "HIGH"},
    (4.0, 6.9):  {"level": 8,  "label": "MEDIUM"},
    (0.1, 3.9):  {"level": 5,  "label": "LOW"},
    (0.0, 0.0):  {"level": 3,  "label": "INFO"},
}

def get_wazuh_level(cvss: float) -> Dict:
    """Map CVSS score to Wazuh alert level and label."""
    for (low, high), info in SEVERITY_MAP.items():
        if low <= cvss <= high:
            return info
    return {"level": 3, "label": "INFO"}


def send_to_wazuh(host: str, port: int, message: str) -> bool:
    """Send a syslog-formatted message to Wazuh via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        syslog_msg = f"<134>{timestamp} openvas-scanner openvas: {message}"
        sock.sendto(syslog_msg.encode('utf-8'), (host, port))
        sock.close()
        return True
    except Exception as e:
        log.error(f"Failed to send to Wazuh: {e}")
        return False


def parse_result(result_el: ET.Element, scan_host: str) -> Optional[Dict]:
    """Parse a single OpenVAS result element into a structured dict."""
    try:
        nvt = result_el.find('nvt')
        host_el = result_el.find('host')

        name = result_el.findtext('name', 'Unknown')
        severity_str = result_el.findtext('severity', '0.0')
        severity = float(severity_str) if severity_str else 0.0

        host_ip = host_el.text.strip() if host_el is not None else 'unknown'
        port = result_el.findtext('port', 'unknown')
        description = result_el.findtext('description', '')[:500]  # truncate

        # Extract CVE IDs
        cves = []
        if nvt is not None:
            for ref in nvt.findall('.//ref[@type="cve"]'):
                cve_id = ref.get('id', '')
                if cve_id:
                    cves.append(cve_id)

        nvt_oid = nvt.get('oid', '') if nvt is not None else ''
        nvt_name = nvt.findtext('name', name) if nvt is not None else name

        severity_info = get_wazuh_level(severity)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "openvas",
            "scan_host": scan_host,
            "target_ip": host_ip,
            "port": port,
            "nvt_oid": nvt_oid,
            "nvt_name": nvt_name,
            "cvss_score": severity,
            "severity": severity_info["label"],
            "wazuh_level": severity_info["level"],
            "cves": cves,
            "cve": cves[0] if cves else "N/A",
            "description": description.replace('\n', ' ').strip(),
        }
    except Exception as e:
        log.warning(f"Failed to parse result: {e}")
        return None


def get_completed_reports(gmp) -> List[str]:
    """Get list of IDs for reports from completed tasks."""
    report_ids = []
    try:
        tasks_response = gmp.get_tasks(filter_string="status=Done")
        for task in tasks_response.findall('task'):
            last_report = task.find('last_report/report')
            if last_report is not None:
                report_id = last_report.get('id')
                if report_id:
                    report_ids.append(report_id)
    except Exception as e:
        log.error(f"Failed to get tasks: {e}")
    return report_ids


def process_report(gmp, report_id: str, wazuh_host: str, wazuh_port: int,
                   min_severity: float = 4.0) -> int:
    """Fetch a report and send all findings above min_severity to Wazuh."""
    sent = 0
    try:
        log.info(f"Fetching report {report_id}...")

        # Get report with filter for severity
        report_response = gmp.get_report(
            report_id=report_id,
            filter_string=f"severity>{min_severity - 0.1} rows=1000 apply_overrides=0",
            ignore_pagination=True,
            details=True
        )

        results = report_response.findall('.//result')
        log.info(f"  Found {len(results)} vulnerabilities (CVSS >= {min_severity})")

        for result_el in results:
            finding = parse_result(result_el, wazuh_host)
            if not finding:
                continue

            msg = json.dumps(finding)
            if send_to_wazuh(wazuh_host, wazuh_port, msg):
                sent += 1
                log.debug(f"  Sent: [{finding['severity']}] {finding['nvt_name']} on {finding['target_ip']}")

        log.info(f"  Sent {sent} findings to Wazuh")

    except Exception as e:
        log.error(f"Failed to process report {report_id}: {e}")

    return sent


def main():
    parser = argparse.ArgumentParser(
        description="OpenVAS → Wazuh Integration Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-shot pull
  python3 openvas-to-wazuh.py --openvas-host 192.168.10.20 --wazuh-host 192.168.10.10

  # Watch mode (every 5 minutes)
  python3 openvas-to-wazuh.py --openvas-host 192.168.10.20 \\
      --wazuh-host 192.168.10.10 --watch --interval 300

  # Only Critical and High (CVSS 7.0+)
  python3 openvas-to-wazuh.py --openvas-host 192.168.10.20 \\
      --wazuh-host 192.168.10.10 --min-severity 7.0
        """
    )
    parser.add_argument('--openvas-host', default='192.168.10.20', help='OpenVAS/Greenbone host IP')
    parser.add_argument('--openvas-port', type=int, default=9390, help='GVM port (default: 9390)')
    parser.add_argument('--openvas-user', default='admin', help='OpenVAS username')
    parser.add_argument('--openvas-pass', required=True, help='OpenVAS password')
    parser.add_argument('--wazuh-host', default='192.168.10.10', help='Wazuh server IP')
    parser.add_argument('--wazuh-port', type=int, default=514, help='Wazuh syslog port (default: 514)')
    parser.add_argument('--min-severity', type=float, default=4.0, help='Minimum CVSS score to send (default: 4.0)')
    parser.add_argument('--watch', action='store_true', help='Run continuously, poll for new reports')
    parser.add_argument('--interval', type=int, default=300, help='Poll interval in seconds (watch mode)')
    args = parser.parse_args()

    processed_reports = set()

    log.info(f"OpenVAS → Wazuh Integration")
    log.info(f"  OpenVAS: {args.openvas_host}:{args.openvas_port}")
    log.info(f"  Wazuh:   {args.wazuh_host}:{args.wazuh_port}")
    log.info(f"  Min severity: CVSS {args.min_severity}")

    while True:
        try:
            connection = TLSConnection(
                hostname=args.openvas_host,
                port=args.openvas_port
            )

            with Gmp(connection=connection, transform=EtreeResultTransform()) as gmp:
                gmp.authenticate(args.openvas_user, args.openvas_pass)
                log.info("Connected to OpenVAS/GVM")

                report_ids = get_completed_reports(gmp)
                new_reports = [r for r in report_ids if r not in processed_reports]

                if new_reports:
                    log.info(f"Found {len(new_reports)} new completed report(s)")
                    for report_id in new_reports:
                        total = process_report(
                            gmp, report_id,
                            args.wazuh_host, args.wazuh_port,
                            args.min_severity
                        )
                        processed_reports.add(report_id)
                        log.info(f"Report {report_id}: {total} events sent to Wazuh")
                else:
                    log.info("No new completed reports found")

        except Exception as e:
            log.error(f"Connection error: {e}")

        if not args.watch:
            break

        log.info(f"Sleeping {args.interval}s until next poll...")
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
