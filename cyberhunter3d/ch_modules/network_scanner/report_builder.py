# CyberHunter 3D - Network Scan Report Builder

import logging
import json
import os

logger = logging.getLogger(__name__)

def build_network_report(parsed_nmap_data: dict, open_ports_data: dict,
                         scan_id: str, target_input_source: str, scan_profile: str) -> dict:
    """
    Builds a unified network scan report from various inputs.
    For now, it primarily structures the parsed Nmap data.
    Open ports data from Naabu/Masscan might be used for cross-referencing or initial listing.

    Args:
        parsed_nmap_data (dict): Data parsed from Nmap XML output.
                                 Keyed by host (IP/hostname).
        open_ports_data (dict): Data from fast port scanners (e.g., Naabu).
                                Keyed by host, value is list of ports.
        scan_id (str): The unique ID for the current scan job.
        target_input_source (str): Description of the input targets (e.g., file path).
        scan_profile (str): The scan profile used.

    Returns:
        dict: A structured JSON report of network findings.
    """
    logger.info(f"[{scan_id}] Building network report. Profile: {scan_profile}")

    report = {
        "scan_id": scan_id,
        "target_source": target_input_source,
        "scan_profile": scan_profile,
        "summary": {
            "total_hosts_scanned_nmap": len(parsed_nmap_data),
            "total_hosts_with_open_ports_naabu": len(open_ports_data),
            # More summaries can be added here (e.g., total open ports)
        },
        "hosts": [] # List of host objects
    }

    # Iterate through Nmap results as the primary source of detailed info
    for host_identifier, nmap_host_details in parsed_nmap_data.items():
        host_entry = {
            "identifier": host_identifier, # This could be hostname or IP from Nmap's perspective
            "ip_address": nmap_host_details.get("ip_address", host_identifier if '.' in host_identifier else None), # Best guess for IP
            "hostnames": nmap_host_details.get("hostnames", []),
            "os_details": nmap_host_details.get("os_detection", {}),
            "ports": nmap_host_details.get("ports", []) # Nmap already provides rich port info
        }

        # Optionally, cross-reference with Naabu data if needed for simple open port list
        # if host_identifier in open_ports_data and not host_entry["ports"]:
        #    host_entry["ports"] = [{"portid": p, "state": "open", "note": "From fast scan"} for p in open_ports_data[host_identifier]]

        report["hosts"].append(host_entry)

    # If some hosts were found by Naabu but not detailed by Nmap (e.g. Nmap failed or skipped them)
    # you might want to add them with just port info.
    for host_identifier, naabu_ports in open_ports_data.items():
        if host_identifier not in parsed_nmap_data:
            # This host was in Naabu's output but not Nmap's detailed scan
            report["hosts"].append({
                "identifier": host_identifier,
                "ip_address": host_identifier if '.' in host_identifier else None, # Basic assumption
                "hostnames": [], # Naabu typically doesn't provide hostnames directly with ports
                "os_details": {},
                "ports": [{"portid": p, "protocol": "tcp", "state": "open", "service_name": "unknown (from fast scan)"} for p in naabu_ports],
                "notes": "Host identified by fast port scan; Nmap details not available."
            })

    logger.info(f"[{scan_id}] Network report built with {len(report['hosts'])} hosts.")
    return report

if __name__ == '__main__':
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    mock_scan_id_report = f"report_test_{uuid.uuid4()}"

    # Mock data similar to what parsers/scanners would produce
    mock_parsed_nmap = {
        "host1.example.com": {
            "ip_address": "192.168.1.10",
            "hostnames": ["host1.example.com", "server1.internal"],
            "os_detection": {"name": "Linux 5.x", "accuracy": "90"},
            "ports": [
                {"portid": "80", "protocol": "tcp", "state": "open", "service_name": "http", "product": "Apache"},
                {"portid": "443", "protocol": "tcp", "state": "open", "service_name": "https", "product": "Nginx"}
            ]
        },
        "192.168.1.20": {
            "ip_address": "192.168.1.20",
            "hostnames": [],
            "os_detection": {},
            "ports": [
                {"portid": "22", "protocol": "tcp", "state": "open", "service_name": "ssh", "product": "OpenSSH"}
            ]
        }
    }
    mock_naabu_open_ports = {
        "host1.example.com": [80, 443, 8080], # 8080 found by Naabu but not in Nmap mock
        "192.168.1.20": [22],
        "newhost.example.com": [53, 111] # Found by Naabu, not in Nmap
    }

    report = build_network_report(
        parsed_nmap_data=mock_parsed_nmap,
        open_ports_data=mock_naabu_open_ports,
        scan_id=mock_scan_id_report,
        target_input_source="dummy_targets.txt",
        scan_profile="default_test"
    )

    logger.info("Generated Network Report:")
    logger.info(json.dumps(report, indent=2))

    # Verify some aspects
    assert len(report["hosts"]) == 3 # host1, 192.168.1.20, newhost

    host1_report = next((h for h in report["hosts"] if h["identifier"] == "host1.example.com"), None)
    assert host1_report is not None
    assert len(host1_report["ports"]) == 2 # Nmap data for ports is used primarily

    newhost_report = next((h for h in report["hosts"] if h["identifier"] == "newhost.example.com"), None)
    assert newhost_report is not None
    assert len(newhost_report["ports"]) == 2
    assert newhost_report["ports"][0]["service_name"] == "unknown (from fast scan)"

    logger.info("Report builder basic test successful.")
import uuid # Add this if not already at the top, for mock_scan_id_report
