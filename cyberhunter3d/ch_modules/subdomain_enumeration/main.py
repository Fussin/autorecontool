# CyberHunter 3D - Subdomain Enumeration Main Logic

import subprocess
import os
import httpx
import asyncio
import tempfile
import re
import json
from urllib.parse import urlparse, parse_qs
import logging # Added for better logging

# --- Setup Logger ---
logger = logging.getLogger(__name__)
if not logger.handlers:
    # Basic configuration if not already configured by a higher-level module (e.g., API)
    # In a real app, this would likely be configured globally.
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


# --- Subdomain Enumeration Tool Wrappers ---
def _run_tool(command: list[str], tool_name: str, target_domain: str) -> set[str]:
    """Helper function to run a command-line tool and capture its output."""
    logger.info(f"Running {tool_name} for: {target_domain}")
    found_items = set()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(timeout=300)  # 5-minute timeout per tool

        if process.returncode == 0:
            for line in stdout.splitlines():
                item = line.strip()
                if item and ('.' in item):
                    item = re.sub(r'^https?://', '', item) # Normalize by removing scheme if present
                    found_items.add(item)
            logger.info(f"{tool_name} found {len(found_items)} items for {target_domain}.")
        else:
            logger.error(f"{tool_name} failed for {target_domain}. RC: {process.returncode}")
            logger.error(f"{tool_name} stderr: {stderr[:500]}...")
            if "command not found" in stderr.lower() or "no such file or directory" in stderr.lower():
                logger.error(f"{tool_name} command not found. Ensure it's installed and in PATH.")
    except FileNotFoundError:
        logger.error(f"{tool_name} command not found. Ensure it's installed and in PATH.")
    except subprocess.TimeoutExpired:
        logger.error(f"{tool_name} timed out for {target_domain}.")
        if process and process.poll() is None:
            process.kill()
            process.communicate()
    except Exception as e:
        logger.error(f"An exception occurred while running {tool_name} for {target_domain}: {e}", exc_info=True)
    return found_items

def run_subfinder(target_domain: str) -> set[str]:
    return _run_tool(["subfinder", "-d", target_domain, "-silent"], "Subfinder", target_domain)

def run_sublist3r(target_domain: str, temp_dir: str) -> set[str]:
    temp_output_file = os.path.join(temp_dir, f"sublist3r_{target_domain}.txt")
    command = ["sublist3r", "-d", target_domain, "-o", temp_output_file]
    _run_tool(command, "Sublist3r", target_domain)
    subdomains = set()
    if os.path.exists(temp_output_file):
        try:
            with open(temp_output_file, "r") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and '.' in subdomain:
                         subdomains.add(subdomain)
            logger.info(f"Sublist3r (from file) found {len(subdomains)} subdomains for {target_domain}.")
        except Exception as e:
            logger.error(f"Could not read Sublist3r output file {temp_output_file}: {e}", exc_info=True)
        finally:
            try:
                os.remove(temp_output_file)
            except OSError:
                pass
    else:
        logger.info(f"Sublist3r did not create an output file or failed: {temp_output_file}")
    return subdomains

def run_amass(target_domain: str) -> set[str]:
    # Amass intel can be slow, consider passive mode for speed: amass enum -passive -d target_domain
    return _run_tool(["amass", "intel", "-d", target_domain, "-whois", "-ip"], "Amass", target_domain)

def run_assetfinder(target_domain: str) -> set[str]:
    return _run_tool(["assetfinder", "--subs-only", target_domain], "Assetfinder", target_domain)

def run_waybackurls(target: str) -> set[str]:
    return _run_tool(["waybackurls", target], "Waybackurls", target)

def run_katana(target: str) -> set[str]:
    return _run_tool(["katana", "-u", target, "-silent", "-jc", "-nc", "-aff", "-kf", "all", "-c", "5"], "Katana", target) # Added concurrency

def run_gau(target_domain_or_subdomain: str) -> set[str]:
    return _run_tool(["gau", "--threads", "5", target_domain_or_subdomain], "GAU", target_domain_or_subdomain)

def run_hakrawler(target_domain_or_subdomain: str) -> set[str]:
    return _run_tool(["hakrawler", "-url", target_domain_or_subdomain, "-depth", "2", "-plain"], "Hakrawler", target_domain_or_subdomain)

def extract_parameters_from_urls(urls_file_path: str, output_file_params: str):
    logger.info(f"Starting parameter extraction from: {urls_file_path}")
    if not os.path.exists(urls_file_path) or os.path.getsize(urls_file_path) == 0:
        logger.info(f"URL file '{urls_file_path}' is empty or not found. Skipping parameter extraction.")
        with open(output_file_params, "w") as f:
            f.write("# URL file for parameter extraction was empty or not found.\n")
        return
    unique_params = set()
    try:
        with open(urls_file_path, "r") as f_urls:
            for line_num, line in enumerate(f_urls):
                url = line.strip()
                if not url: continue
                try:
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    for param_name in query_params.keys():
                        unique_params.add(param_name)
                except Exception as e:
                    logger.warning(f"Could not parse URL or extract params from '{url}' (line {line_num+1}): {e}")
        with open(output_file_params, "w") as f_out:
            if unique_params:
                for param in sorted(list(unique_params)):
                    f_out.write(param + "\n")
                logger.info(f"Extracted {len(unique_params)} unique parameters to: {output_file_params}")
            else:
                f_out.write("# No query parameters found in the provided URLs.\n")
                logger.info(f"No query parameters found in URLs from {urls_file_path}.")
    except Exception as e:
        logger.error(f"Failed during parameter extraction process: {e}", exc_info=True)
        with open(output_file_params, "w") as f_out:
            f_out.write(f"# Error during parameter extraction: {e}\n")

def run_subzy_takeover_check(live_subdomains_file: str, output_file_subzy: str, target_domain_for_log: str) -> bool:
    logger.info(f"Running Subzy for subdomain takeover check on file: {live_subdomains_file}")
    if not os.path.exists(live_subdomains_file) or os.path.getsize(live_subdomains_file) == 0:
        logger.info(f"Subzy: Live subdomains file '{live_subdomains_file}' is empty or not found. Skipping takeover check.")
        with open(output_file_subzy, "w") as f:
            f.write("# No live subdomains to check for takeover.\n")
        return True
    command = ["subzy", "run", "--targets", live_subdomains_file, "--output", output_file_subzy, "--hide_fails"]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=600) # 10 min timeout
        if process.returncode == 0:
            logger.info(f"Subzy completed successfully for {target_domain_for_log}.")
            if os.path.exists(output_file_subzy) and os.path.getsize(output_file_subzy) > 0:
                 logger.info(f"[VULN_POTENTIAL] Subzy found potential takeovers for {target_domain_for_log}. Results in: {output_file_subzy}")
            else:
                 logger.info(f"Subzy found no potential takeovers for {target_domain_for_log}.")
                 if not os.path.exists(output_file_subzy): # Ensure file exists even if empty
                     with open(output_file_subzy, "w") as f: f.write("# No takeover vulnerabilities found by Subzy.\n")
            return True
        else:
            logger.error(f"Subzy failed for {target_domain_for_log}. RC: {process.returncode}")
            logger.error(f"Subzy stdout: {stdout[:500]}")
            logger.error(f"Subzy stderr: {stderr[:500]}")
            with open(output_file_subzy, "w") as f: f.write(f"# Subzy execution failed. Stderr: {stderr[:200]}\n") # Write error to file
            return False
    except FileNotFoundError:
        logger.error(f"Subzy command not found. Ensure it's installed and in PATH.")
        with open(output_file_subzy, "w") as f: f.write("# Subzy command not found.\n")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Subzy timed out for {target_domain_for_log}.")
        if process and process.poll() is None: process.kill(); process.communicate()
        with open(output_file_subzy, "w") as f: f.write("# Subzy timed out.\n")
        return False
    except Exception as e:
        logger.error(f"An exception occurred while running Subzy for {target_domain_for_log}: {e}", exc_info=True)
        with open(output_file_subzy, "w") as f: f.write(f"# Exception during Subzy run: {e}\n")
        return False

async def _check_item_liveness(item_to_check: str, client: httpx.AsyncClient, is_url: bool) -> tuple[str, bool, int | None]:
    urls_to_probe = []
    if is_url:
        urls_to_probe.append(item_to_check)
    else:
        subdomain = item_to_check
        ports_to_check = ["", ":8000", ":8080"] # Standard ports, can be expanded
        schemes = ["https", "http"]
        for port_suffix in ports_to_check:
            for scheme in schemes:
                # Avoid redundant http://subdomain (no port) if https://subdomain (no port) is already checked or vice versa
                if (scheme == "http" and port_suffix == "") or (scheme == "https" and port_suffix == ""):
                    urls_to_probe.append(f"{scheme}://{subdomain}")
                elif port_suffix: # Only add ports for non-standard cases
                     urls_to_probe.append(f"{scheme}://{subdomain}{port_suffix}")

    unique_probes = sorted(list(set(urls_to_probe))) # Ensure unique probes

    for url_probe in unique_probes:
        try:
            # logger.debug(f"Probing liveness for: {url_probe}")
            response = await client.get(url_probe, timeout=7, follow_redirects=True) # Increased timeout slightly
            # For subdomains, any 2xx, 3xx, 401, 403 is usually "live enough" to warrant further checks
            if not is_url and (200 <= response.status_code < 400 or response.status_code in [401, 403]):
                return item_to_check, True, response.status_code
            # For URLs, we are more interested in whether it's generally accessible (2xx, 3xx) or a client/server error
            if is_url: # Any response means the URL was processed
                return item_to_check, True, response.status_code
        except httpx.RequestError as exc:
            # logger.debug(f"RequestError for {url_probe}: {exc}")
            pass # Common errors like connection refused, SSL errors, etc.
        except Exception as exc_gen:
            # logger.debug(f"Generic Exception for {url_probe}: {exc_gen}")
            pass
    return item_to_check, False, None # If all probes fail

async def get_liveness_async(items: set[str], is_url_check: bool = False) -> list[tuple[str, bool, int | None]]:
    live_results = []
    # Adjusted limits for potentially many items
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=10)
    async with httpx.AsyncClient(limits=limits, verify=False) as client: # verify=False for self-signed certs etc.
        tasks = [_check_item_liveness(item, client, is_url_check) for item in items]
        results = await asyncio.gather(*tasks)
        for item, is_alive, status_code in results:
            live_results.append((item, is_alive, status_code))
    return live_results

# Added scan_id parameter
def run_recon_workflow(target_domain: str, scan_id: str, output_path: str = "./scan_results") -> dict:
    logger.info(f"[{target_domain} - {scan_id}] Starting comprehensive recon workflow")
    domain_output_path = os.path.join(output_path, target_domain)
    os.makedirs(domain_output_path, exist_ok=True)
    logger.info(f"[{target_domain} - {scan_id}] Output will be saved in: {domain_output_path}")

    base_output_dir = domain_output_path # For clarity when passing to sub-modules

    # Define all output file paths at the beginning
    all_subdomains_file = os.path.join(base_output_dir, "Subdomain.txt")
    subdomains_alive_file = os.path.join(base_output_dir, "subdomains_alive.txt")
    subdomains_dead_file = os.path.join(base_output_dir, "subdomains_dead.txt")
    way_kat_file = os.path.join(base_output_dir, "Way_kat.txt")
    urls_alive_file = os.path.join(base_output_dir, "alive_domain.txt")
    urls_dead_file = os.path.join(base_output_dir, "dead_domain.txt")
    dns_resolutions_file = os.path.join(base_output_dir, "subdomain_dns_resolutions.json")
    subdomain_takeover_file = os.path.join(base_output_dir, "subdomain_takeover_vulnerable.txt")
    interesting_params_file = os.path.join(base_output_dir, "interesting_params.txt")

    # Vulnerability module output files (as per PARSER_MAPPING in aggregator)
    xss_results_file = os.path.join(base_output_dir, "xss_vulnerabilities.json")
    sqli_results_file = os.path.join(base_output_dir, "sqli_vulnerabilities.json")
    lfi_results_file = os.path.join(base_output_dir, "lfi_vulnerabilities.json") # or lfi_findings.json
    cors_results_file = os.path.join(base_output_dir, "cors_vulnerabilities.json") # or cors_misconfig.json
    sensitive_data_findings_file = os.path.join(base_output_dir, "sensitive_data_findings.json")
    ssrf_results_file = os.path.join(base_output_dir, "ssrf_vulnerabilities.json")
    xxe_results_file = os.path.join(base_output_dir, "xxe_vulnerabilities.json")
    rce_results_file = os.path.join(base_output_dir, "rce_vulnerabilities.json")
    aggregated_vulnerabilities_file = os.path.join(base_output_dir, "aggregated_vulnerabilities.json")
    network_scan_results_file_path = os.path.join(base_output_dir, "network_scan_results.json") # Define path


    wildcard_file = os.path.join(base_output_dir, "wildcard_domains.txt") # Currently not actively generated, placeholder
    metadata_file = os.path.join(base_output_dir, "subdomain_technologies.json") # Placeholder for tech stack

    results_summary = { # Initialize results summary for API
        "target_domain": target_domain,
        "all_subdomains_file": all_subdomains_file, "dns_resolutions_file": dns_resolutions_file,
        "subdomains_alive_file": subdomains_alive_file, "subdomains_dead_file": subdomains_dead_file,
        "takeover_vulnerable_file": subdomain_takeover_file, "way_kat_file": way_kat_file,
        "interesting_params_file": interesting_params_file, "urls_alive_file": urls_alive_file,
        "urls_dead_file": urls_dead_file,
        "sensitive_data_findings_file": sensitive_data_findings_file,
        "xss_results_file": xss_results_file, "sqli_results_file": sqli_results_file,
        "lfi_results_file": lfi_results_file, "cors_results_file": cors_results_file,
        "ssrf_results_file": ssrf_results_file, "xxe_results_file": xxe_results_file,
        "rce_results_file": rce_results_file,
        "aggregated_vulnerabilities_file": aggregated_vulnerabilities_file,
        "network_scan_results_file": network_scan_results_file_path, # Added for network scanner
        "wildcard_domains_file": wildcard_file, "metadata_file": metadata_file
    }
    logger.info(f"[{target_domain} - {scan_id}] Initial results_summary keys: {list(results_summary.keys())}")


    logger.info(f"[{target_domain} - {scan_id}] --- Running Subdomain Enumeration Tools ---")
    all_discovered_subdomains = set()
    with tempfile.TemporaryDirectory() as temp_dir: # Ensure temp_dir is used by tools needing it
        all_discovered_subdomains.update(run_subfinder(target_domain))
        all_discovered_subdomains.update(run_sublist3r(target_domain, temp_dir)) # Pass temp_dir
        all_discovered_subdomains.update(run_amass(target_domain))
        all_discovered_subdomains.update(run_assetfinder(target_domain))

    def create_placeholders_for_early_exit(reason_message: str, current_results_summary: dict):
        # Ensure all expected files are touched or created with placeholder content
        # This helps prevent "file not found" when API tries to list results.
        logger.warning(f"[{target_domain} - {scan_id}] Early exit from workflow: {reason_message}")

        # Update status in summary
        current_results_summary["status"] = f"completed_early_exit:_{reason_message.lower().replace(' ', '_').replace('.', '')}"

        # Define expected JSON output files and their placeholder content
        json_placeholder_content = {"notes": f"Scanning skipped: {reason_message}", "vulnerabilities": []}
        expected_json_files = [
            dns_resolutions_file, xss_results_file, sqli_results_file, lfi_results_file,
            cors_results_file, sensitive_data_findings_file, ssrf_results_file,
            xxe_results_file, rce_results_file,
            metadata_file, # metadata is also JSON
            results_summary.get("network_scan_results_file") # Add network scan results file path from summary
            # aggregated_vulnerabilities_file handled separately below
        ]
         # Filter out None values in case a file path wasn't set in results_summary yet (shouldn't happen for network_scan_results_file here)
        expected_json_files = [f for f in expected_json_files if f]

        for f_path in expected_json_files:
            if not os.path.exists(f_path):
                try:
                    content_to_write = json_placeholder_content # Default placeholder
                    if f_path == dns_resolutions_file or f_path == metadata_file:
                        content_to_write = {} # Empty dict for these
                    elif f_path == results_summary.get("network_scan_results_file"):
                        content_to_write = {
                            "scan_id": scan_id, # Add scan_id
                            "status": f"skipped_{reason_message.lower().replace(' ', '_').replace('.', '')}",
                            "notes": f"Network scan skipped: {reason_message}",
                            "hosts": []
                        }

                    with open(f_path, 'w') as f: json.dump(content_to_write, f, indent=2)
                except Exception as e:
                     logger.error(f"Could not create placeholder JSON file {f_path}: {e}")

        # Specifically for aggregated_vulnerabilities_file, it should be an empty list on early exit
        # Ensure aggregated_vulnerabilities_file path is correctly obtained from results_summary
        agg_file_path = results_summary.get("aggregated_vulnerabilities_file")
        if agg_file_path and not os.path.exists(agg_file_path):
            try:
                with open(agg_file_path, 'w') as f: json.dump([], f, indent=2)
            except Exception as e:
                logger.error(f"Could not create placeholder aggregated_vulnerabilities_file: {e}")

        # Define expected text output files and their placeholder content
        text_placeholder_content = f"# Scanning skipped: {reason_message}\n"
        expected_text_files = [
            subdomain_takeover_file, interesting_params_file, all_subdomains_file,
            subdomains_alive_file, subdomains_dead_file, way_kat_file,
            urls_alive_file, urls_dead_file, wildcard_file
        ]
        for f_path in expected_text_files:
            if not os.path.exists(f_path):
                try:
                    with open(f_path, 'w') as f: f.write(text_placeholder_content)
                except Exception as e:
                     logger.error(f"Could not create placeholder text file {f_path}: {e}")
        return current_results_summary


    if not all_discovered_subdomains:
        logger.warning(f"[{target_domain} - {scan_id}] No subdomains found by any tool.")
        final_summary_on_early_exit = create_placeholders_for_early_exit("No subdomains found by any tool", results_summary)
        logger.info(f"[{target_domain} - {scan_id}] Early exit. Results summary keys: {list(final_summary_on_early_exit.keys())}")
        return final_summary_on_early_exit

    sorted_subdomains = sorted(list(all_discovered_subdomains))
    with open(all_subdomains_file, "w") as f:
        for sub in sorted_subdomains: f.write(sub + "\n")
    logger.info(f"[{target_domain} - {scan_id}] Consolidated {len(sorted_subdomains)} unique subdomains to {all_subdomains_file}")

    logger.info(f"[{target_domain} - {scan_id}] --- Performing DNS Resolution for Discovered Subdomains ---")
    dns_data = {}
    import socket # Keep import local if only used here
    for sub_idx, subdomain_to_resolve in enumerate(sorted_subdomains):
        if sub_idx > 0 and sub_idx % 100 == 0: logger.info(f"[DNS - {scan_id}] Resolved {sub_idx}/{len(sorted_subdomains)} subdomains...")
        try:
            # Using gethostbyname_ex for potentially multiple IPs, though getaddrinfo is more modern
            _, _, ipaddrlist = socket.gethostbyname_ex(subdomain_to_resolve)
            dns_data[subdomain_to_resolve] = ipaddrlist if ipaddrlist else ["NXDOMAIN or No A/AAAA record"]
        except socket.gaierror: dns_data[subdomain_to_resolve] = ["ResolutionFailed_GAIError"]
        except Exception as e: dns_data[subdomain_to_resolve] = [f"Error: {str(e)}"]; logger.error(f"[DNS ERROR - {scan_id}] for {subdomain_to_resolve}: {e}")
    with open(dns_resolutions_file, "w") as f_dns: json.dump(dns_data, f_dns, indent=2)
    logger.info(f"[{target_domain} - {scan_id}] DNS resolution data saved to {dns_resolutions_file}")

    logger.info(f"[{target_domain} - {scan_id}] --- Checking Subdomain Liveness ---")
    subdomain_liveness_results = asyncio.run(get_liveness_async(all_discovered_subdomains, is_url_check=False))
    live_subs_list, dead_subs_list = [], []
    for sub, is_alive, _ in subdomain_liveness_results: (live_subs_list if is_alive else dead_subs_list).append(sub)
    with open(subdomains_alive_file, "w") as f:
        for sub in sorted(live_subs_list): f.write(sub + "\n")
    logger.info(f"[{target_domain} - {scan_id}] Found {len(live_subs_list)} live subdomains. Saved to {subdomains_alive_file}")
    with open(subdomains_dead_file, "w") as f:
        for sub in sorted(dead_subs_list): f.write(sub + "\n")
    logger.info(f"[{target_domain} - {scan_id}] Found {len(dead_subs_list)} dead subdomains. Saved to {subdomains_dead_file}")

    logger.info(f"[{target_domain} - {scan_id}] --- Running Subdomain Takeover Check (Subzy) ---")
    run_subzy_takeover_check(subdomains_alive_file, subdomain_takeover_file, target_domain)

    if not live_subs_list:
        logger.warning(f"[{target_domain} - {scan_id}] No live subdomains found. Subsequent URL-based steps will be skipped.")
        return create_placeholders_for_early_exit("No live subdomains found", results_summary)

    logger.info(f"[{target_domain} - {scan_id}] --- Running URL Discovery Tools ---")
    all_discovered_urls = set()
    # Limit URL discovery to a subset of live subdomains if too many, to manage time.
    # For now, processing all.
    for live_sub in live_subs_list:
        logger.info(f"Discovering URLs for live subdomain: {live_sub} [{scan_id}]")
        all_discovered_urls.update(run_waybackurls(live_sub))
        all_discovered_urls.update(run_katana(live_sub))
        all_discovered_urls.update(run_gau(live_sub))
        all_discovered_urls.update(run_hakrawler(live_sub))

    cleaned_urls, final_urls_for_waykat = set(), set()
    for url in all_discovered_urls: # Normalize and clean URLs
        # Ensure scheme, handle potential // issues from tools
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}" # Default to https
        cleaned_urls.add(url)

    excluded_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map', '.jsonld'}
    for url in cleaned_urls: # Filter out common non-content types
        try:
            if not any(urlparse(url).path.lower().endswith(ext) for ext in excluded_extensions):
                final_urls_for_waykat.add(url)
        except: continue # Skip malformed URLs
    sorted_urls = sorted(list(final_urls_for_waykat))
    with open(way_kat_file, "w") as f:
        for url_item in sorted_urls: f.write(url_item + "\n")
    logger.info(f"[{target_domain} - {scan_id}] Discovered {len(sorted_urls)} unique URLs (after filtering). Saved to {way_kat_file}")

    if not sorted_urls:
        logger.warning(f"[{target_domain} - {scan_id}] No URLs found by any discovery tool or all were filtered. Subsequent URL-based steps will be skipped.")
        return create_placeholders_for_early_exit("No URLs discovered or all filtered", results_summary)

    logger.info(f"[{target_domain} - {scan_id}] --- Extracting Parameters from Discovered URLs ---")
    extract_parameters_from_urls(way_kat_file, interesting_params_file)

    logger.info(f"[{target_domain} - {scan_id}] --- Filtering URLs (Checking Liveness & Status Codes) ---")
    url_liveness_results = asyncio.run(get_liveness_async(final_urls_for_waykat, is_url_check=True))
    live_urls_list, dead_urls_list = [], [] # live = 2xx/3xx, dead = 4xx/5xx or request failed
    for url, request_succeeded, status_code in url_liveness_results:
        if request_succeeded and status_code is not None:
            if 200 <= status_code < 400: live_urls_list.append(url)
            elif 400 <= status_code < 600: dead_urls_list.append(f"{url} [{status_code}]")
            # else: consider what to do with other codes, for now they are implicitly 'dead' for scanning
        else: dead_urls_list.append(f"{url} [Request Failed/No Response]")
    with open(urls_alive_file, "w") as f:
        for url_item in sorted(live_urls_list): f.write(url_item + "\n")
    logger.info(f"[{target_domain} - {scan_id}] Found {len(live_urls_list)} live URLs (200s/30xs). Saved to {urls_alive_file}")
    with open(urls_dead_file, "w") as f:
        for url_status in sorted(dead_urls_list): f.write(url_status + "\n")
    logger.info(f"[{target_domain} - {scan_id}] Found {len(dead_urls_list)} dead/error URLs. Saved to {urls_dead_file}")

    # --- Vulnerability Scanning Modules ---
    # Ensure imports are correct based on file structure relative to THIS file
    # These modules are in ../<module_name>/main.py
    from ..xss_hunter.main import hunt_xss
    from ..sqli_scanner.main import scan_for_sqli
    from ..lfi_hunter.main import hunt_for_lfi
    from ..cors_hunter.main import hunt_for_cors_issues
    from ..sensitive_data_hunter.main import hunt_for_sensitive_data
    from ..ssrf_hunter.main import hunt_for_ssrf
    from ..xxe_hunter.main import hunt_for_xxe
    from ..rce_hunter.main import hunt_for_rce
    from ..network_scanner.main import run_network_scan # Added for Phase 19

    # Import the aggregator.
    try:
        from ch_modules.vulnerability_aggregator.main import aggregate_and_deduplicate_vulnerabilities
    except ModuleNotFoundError:
        logger.error(f"[{target_domain} - {scan_id}] Could not import vulnerability_aggregator. Ensure 'ch_modules' (aggregator's parent) is in PYTHONPATH or structure is correct.")
        aggregate_and_deduplicate_vulnerabilities = None


    scan_input_valid = os.path.exists(urls_alive_file) and os.path.getsize(urls_alive_file) > 0

    module_runners = [
        ("XSS Hunter", hunt_xss, [urls_alive_file if scan_input_valid else "", base_output_dir], xss_results_file, "xss_results_file"),
        ("SQLi Scanner", scan_for_sqli, [urls_alive_file if scan_input_valid else "", interesting_params_file, base_output_dir], sqli_results_file, "sqli_results_file"),
        ("LFI Hunter", hunt_for_lfi, [urls_alive_file if scan_input_valid else "", interesting_params_file, base_output_dir], lfi_results_file, "lfi_results_file"),
        ("CORS Hunter", hunt_for_cors_issues, [urls_alive_file if scan_input_valid else "", urlparse(f"http://{target_domain}").netloc, base_output_dir], cors_results_file, "cors_results_file"),
        ("Sensitive Data Hunter", hunt_for_sensitive_data, [
            urls_alive_file if (os.path.exists(urls_alive_file) and os.path.getsize(urls_alive_file) > 0) else "",
            subdomains_alive_file if (os.path.exists(subdomains_alive_file) and os.path.getsize(subdomains_alive_file) > 0) else "",
            base_output_dir
        ], sensitive_data_findings_file, "sensitive_data_results_file"), # Note key diff
        ("SSRF Hunter", hunt_for_ssrf, [urls_alive_file if scan_input_valid else "", interesting_params_file, base_output_dir], ssrf_results_file, "ssrf_results_file"),
        ("XXE Hunter", hunt_for_xxe, [urls_alive_file if scan_input_valid else "", base_output_dir], xxe_results_file, "xxe_results_file"),
        ("RCE Hunter", hunt_for_rce, [urls_alive_file if scan_input_valid else "", interesting_params_file, base_output_dir], rce_results_file, "rce_results_file"),
    ]

    for name, func, args, default_out_file, result_key in module_runners:
        is_sde = name == "Sensitive Data Hunter"
        current_input_valid = (os.path.exists(args[0]) and os.path.getsize(args[0]) > 0) if not is_sde else \
                              ((os.path.exists(args[0]) and os.path.getsize(args[0]) > 0) or \
                               (os.path.exists(args[1]) and os.path.getsize(args[1]) > 0))

        logger.info(f"--- Running {name} (Placeholder) ---" if current_input_valid else f"[INFO] Skipping {name}: No valid input.")
        if not current_input_valid: # Create placeholder if skipped
             if not os.path.exists(default_out_file):
                with open(default_out_file, "w") as f: json.dump({"notes": f"{name} skipped: No valid input.", "vulnerabilities":[]}, f, indent=2)
             continue
        try:
            scan_results = func(*args) # Call the module's main function
            # Update results_summary with the actual output file path from the module if it differs
            # The key in scan_results (e.g. "xss_results_file") should match default_out_file's purpose
            actual_output_file = scan_results.get(result_key, default_out_file)
            results_summary[os.path.basename(default_out_file).replace("_vulnerabilities.json","").replace("_findings.json","") + "_results_file"] = actual_output_file
            logger.info(f"[{target_domain} - {scan_id}] {name} placeholder finished. Results: {actual_output_file}")
        except Exception as e:
            logger.error(f"[{target_domain} - {scan_id}] {name} call failed: {e}", exc_info=True)
            if not os.path.exists(default_out_file): # Ensure placeholder on error
                with open(default_out_file, "w") as f: json.dump({"notes": f"{name} scan error: {e}", "vulnerabilities":[]}, f, indent=2)
            results_summary[os.path.basename(default_out_file).replace("_vulnerabilities.json","").replace("_findings.json","") + "_results_file"] = default_out_file # Point to placeholder

    # PHASE 19: Network Scanning
    # Depends on live subdomains, not necessarily live URLs from wayback/katana
    network_scan_input_valid = os.path.exists(subdomains_alive_file) and os.path.getsize(subdomains_alive_file) > 0
    network_scan_results_file_path = os.path.join(base_output_dir, "network_scan_results.json") # Define expected path
    results_summary["network_scan_results_file"] = network_scan_results_file_path # Add to summary early

    if network_scan_input_valid:
        logger.info(f"[{target_domain} - {scan_id}] Starting Network Scanning...")
        try:
            net_scan_output = run_network_scan(
                targets_file_live_subs=subdomains_alive_file,
                base_output_dir=base_output_dir, # Network scanner will create its own subfolder 'network_scan'
                scan_id=scan_id,
                scan_profile="default" # Or make this configurable later
            )
            # The run_network_scan function returns a dict like {"network_scan_results_file": "/path/to/file.json"}
            # Update the results_summary with the actual path returned, though it should match network_scan_results_file_path
            if net_scan_output.get("network_scan_results_file"):
                results_summary["network_scan_results_file"] = net_scan_output["network_scan_results_file"]
                logger.info(f"[{target_domain} - {scan_id}] Network Scanning completed. Results: {net_scan_output['network_scan_results_file']}")
            else:
                logger.error(f"[{target_domain} - {scan_id}] Network Scanning finished but no results file path returned.")
                if not os.path.exists(network_scan_results_file_path):
                    with open(network_scan_results_file_path, 'w') as f: json.dump({"notes": "Network scan error or no output.", "hosts":[]}, f, indent=2)
        except Exception as e:
            logger.error(f"[{target_domain} - {scan_id}] Exception during Network Scanning: {e}", exc_info=True)
            if not os.path.exists(network_scan_results_file_path):
                with open(network_scan_results_file_path, 'w') as f: json.dump({"notes": f"Network scan exception: {e}", "hosts":[]}, f, indent=2)
    else:
        logger.warning(f"[{target_domain} - {scan_id}] Skipping Network Scanning: No live subdomains found.")
        if not os.path.exists(network_scan_results_file_path):
            with open(network_scan_results_file_path, 'w') as f: json.dump({"notes": "Network scan skipped: No live subdomains.", "hosts":[]}, f, indent=2)


    # PHASE 18: Vulnerability Aggregation and Deduplication (comes after all individual finding generators)
    if aggregate_and_deduplicate_vulnerabilities:
        logger.info(f"[{target_domain} - {scan_id}] Starting Vulnerability Aggregation...")
        try:
            agg_output_file = aggregate_and_deduplicate_vulnerabilities(base_output_dir, scan_id)
            if agg_output_file:
                results_summary["aggregated_vulnerabilities_file"] = agg_output_file
                logger.info(f"[{target_domain} - {scan_id}] Vulnerability Aggregation completed. Results: {agg_output_file}")
            else:
                logger.error(f"[{target_domain} - {scan_id}] Vulnerability Aggregation failed or produced no output file.")
                results_summary["aggregation_error"] = "Aggregation failed or no output."
                if not os.path.exists(aggregated_vulnerabilities_file): # Create placeholder
                     with open(aggregated_vulnerabilities_file, "w") as f: json.dump([], f, indent=2) # Aggregated should be a list
                results_summary["aggregated_vulnerabilities_file"] = aggregated_vulnerabilities_file


        except Exception as e:
            logger.error(f"[{target_domain} - {scan_id}] Exception during Vulnerability Aggregation: {e}", exc_info=True)
            results_summary["aggregation_error"] = str(e)
            if not os.path.exists(aggregated_vulnerabilities_file): # Create placeholder
                with open(aggregated_vulnerabilities_file, "w") as f: json.dump([], f, indent=2) # Aggregated should be a list
            results_summary["aggregated_vulnerabilities_file"] = aggregated_vulnerabilities_file
    else:
        logger.warning(f"[{target_domain} - {scan_id}] Vulnerability aggregator not available. Skipping aggregation.")
        if not os.path.exists(aggregated_vulnerabilities_file): # Create placeholder
            with open(aggregated_vulnerabilities_file, "w") as f: json.dump([], f, indent=2) # Aggregated should be a list
        results_summary["aggregated_vulnerabilities_file"] = aggregated_vulnerabilities_file


    # Ensure final placeholder files for any non-generated optional files
    for f_path_final in [wildcard_file]:
        if not os.path.exists(f_path_final): open(f_path_final, 'w').write("# Not generated in this scan.\n")
    if not os.path.exists(metadata_file): # Tech stack
        with open(metadata_file, "w") as f: json.dump({}, f) # Empty JSON object

    results_summary["status"] = "completed_full_scan_flow" # Final status
    logger.info(f"\n[{target_domain} - {scan_id}] SUCCESS: Comprehensive recon and vulnerability scan workflow completed.")
    return results_summary


if __name__ == '__main__':
    # This basic __main__ is for direct testing of this script.
    # The API (main_api.py) will call run_recon_workflow differently.
    if len(os.sys.argv) > 1:
        test_domain = os.sys.argv[1]
        test_scan_id = f"cli_test_{test_domain.replace('.', '_')}"
        output_dir_arg = os.sys.argv[2] if len(os.sys.argv) > 2 else "./temp_scan_results_comprehensive"
    else:
        test_domain = "testphp.vulnweb.com"
        # test_domain = "example.com" # A domain less likely to have actual vulns for faster placeholder runs
        test_scan_id = f"cli_test_{test_domain.replace('.', '_')}"
        output_dir_arg = os.path.abspath("./temp_scan_results_comprehensive")

    # Adjust PYTHONPATH for direct script execution if ch_modules (aggregator's parent) is not directly importable
    # This is a common workaround for running scripts that are part of a larger package directly.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_core_dir = os.path.dirname(os.path.dirname(script_dir)) # Up to 'cyberhunter3d/'
    project_root_dir = os.path.dirname(project_core_dir) # Up to the actual project root that contains 'ch_modules' for aggregator

    if project_root_dir not in os.sys.path:
        logger.info(f"Adding {project_root_dir} to sys.path for aggregator import.")
        os.sys.path.insert(0, project_root_dir)
    if project_core_dir not in os.sys.path: # For relative imports like ..xss_hunter
        logger.info(f"Adding {project_core_dir} to sys.path for relative module imports.")
        os.sys.path.insert(0, project_core_dir)


    logger.info(f"--- Running Comprehensive Recon Workflow for '{test_domain}' (Scan ID: {test_scan_id}) ---")
    logger.info(f"--- Output will be in: {output_dir_arg}/{test_domain} ---")

    workflow_output = run_recon_workflow(test_domain, test_scan_id, output_path=output_dir_arg)

    logger.info("\n--- Workflow Execution Summary ---")
    for key, val in workflow_output.items(): logger.info(f"  {key}: {val}")

    logger.info("\n--- Example commands to check some output files: ---")
    for key, val in workflow_output.items():
        if isinstance(val, str) and key.endswith("_file") and os.path.exists(val):
            logger.info(f"  cat \"{val}\"")
        elif isinstance(val, str) and key.endswith("_file"):
            logger.warning(f"  Output file listed but not found: {val}")
