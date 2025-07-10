# CyberHunter 3D - Subdomain Enumeration Main Logic

import subprocess
import os
import httpx
import asyncio
import tempfile
import re
import json # Added for DNS resolution output
from urllib.parse import urlparse, parse_qs # Added for URL cleaning and parameter extraction

# --- Subdomain Enumeration Tool Wrappers ---
# ... (all _run_tool, run_subfinder, run_sublist3r, etc. functions remain unchanged) ...
def _run_tool(command: list[str], tool_name: str, target_domain: str) -> set[str]:
    """Helper function to run a command-line tool and capture its output."""
    print(f"[INFO] Running {tool_name} for: {target_domain}")
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
                    item = re.sub(r'^https?://', '', item)
                    found_items.add(item)
            print(f"[INFO] {tool_name} found {len(found_items)} items for {target_domain}.")
        else:
            print(f"[ERROR] {tool_name} failed for {target_domain}. RC: {process.returncode}")
            print(f"[ERROR] {tool_name} stderr: {stderr[:500]}...")
            if "command not found" in stderr.lower() or "no such file or directory" in stderr.lower():
                print(f"[ERROR] {tool_name} command not found. Ensure it's installed and in PATH.")
    except FileNotFoundError:
        print(f"[ERROR] {tool_name} command not found. Ensure it's installed and in PATH.")
    except subprocess.TimeoutExpired:
        print(f"[ERROR] {tool_name} timed out for {target_domain}.")
        if process and process.poll() is None:
            process.kill()
            process.communicate()
    except Exception as e:
        print(f"[ERROR] An exception occurred while running {tool_name} for {target_domain}: {e}")
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
            print(f"[INFO] Sublist3r (from file) found {len(subdomains)} subdomains for {target_domain}.")
        except Exception as e:
            print(f"[ERROR] Could not read Sublist3r output file {temp_output_file}: {e}")
        finally:
            try:
                os.remove(temp_output_file)
            except OSError:
                pass
    else:
        print(f"[INFO] Sublist3r did not create an output file or failed: {temp_output_file}")
    return subdomains

def run_amass(target_domain: str) -> set[str]:
    return _run_tool(["amass", "intel", "-d", target_domain, "-whois", "-ip"], "Amass", target_domain)

def run_assetfinder(target_domain: str) -> set[str]:
    return _run_tool(["assetfinder", "--subs-only", target_domain], "Assetfinder", target_domain)

def run_waybackurls(target: str) -> set[str]:
    return _run_tool(["waybackurls", target], "Waybackurls", target)

def run_katana(target: str) -> set[str]:
    return _run_tool(["katana", "-u", target, "-silent", "-jc", "-nc", "-aff", "-kf", "all"], "Katana", target)

def run_gau(target_domain_or_subdomain: str) -> set[str]:
    return _run_tool(["gau", "--threads", "5", target_domain_or_subdomain], "GAU", target_domain_or_subdomain)

def run_hakrawler(target_domain_or_subdomain: str) -> set[str]:
    return _run_tool(["hakrawler", "-url", target_domain_or_subdomain, "-depth", "2", "-plain"], "Hakrawler", target_domain_or_subdomain)

def extract_parameters_from_urls(urls_file_path: str, output_file_params: str):
    print(f"[INFO] Starting parameter extraction from: {urls_file_path}")
    if not os.path.exists(urls_file_path) or os.path.getsize(urls_file_path) == 0:
        print(f"[INFO] URL file '{urls_file_path}' is empty or not found. Skipping parameter extraction.")
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
                    print(f"[WARN] Could not parse URL or extract params from '{url}' (line {line_num+1}): {e}")
        with open(output_file_params, "w") as f_out:
            if unique_params:
                for param in sorted(list(unique_params)):
                    f_out.write(param + "\n")
                print(f"[INFO] Extracted {len(unique_params)} unique parameters to: {output_file_params}")
            else:
                f_out.write("# No query parameters found in the provided URLs.\n")
                print(f"[INFO] No query parameters found in URLs from {urls_file_path}.")
    except Exception as e:
        print(f"[ERROR] Failed during parameter extraction process: {e}")
        with open(output_file_params, "w") as f_out:
            f_out.write(f"# Error during parameter extraction: {e}\n")

def run_subzy_takeover_check(live_subdomains_file: str, output_file_subzy: str, target_domain_for_log: str) -> bool:
    print(f"[INFO] Running Subzy for subdomain takeover check on file: {live_subdomains_file}")
    if not os.path.exists(live_subdomains_file) or os.path.getsize(live_subdomains_file) == 0:
        print(f"[INFO] Subzy: Live subdomains file '{live_subdomains_file}' is empty or not found. Skipping takeover check.")
        with open(output_file_subzy, "w") as f:
            f.write("# No live subdomains to check for takeover.\n")
        return True
    command = ["subzy", "run", "--targets", live_subdomains_file, "--output", output_file_subzy, "--hide_fails"]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=600)
        if process.returncode == 0:
            print(f"[INFO] Subzy completed successfully for {target_domain_for_log}.")
            if os.path.exists(output_file_subzy) and os.path.getsize(output_file_subzy) > 0:
                 print(f"[VULN_POTENTIAL] Subzy found potential takeovers for {target_domain_for_log}. Results in: {output_file_subzy}")
            else:
                 print(f"[INFO] Subzy found no potential takeovers for {target_domain_for_log}.")
                 if not os.path.exists(output_file_subzy):
                     with open(output_file_subzy, "w") as f: f.write("# No takeover vulnerabilities found by Subzy.\n")
            return True
        else:
            print(f"[ERROR] Subzy failed for {target_domain_for_log}. RC: {process.returncode}")
            print(f"[ERROR] Subzy stdout: {stdout[:500]}")
            print(f"[ERROR] Subzy stderr: {stderr[:500]}")
            with open(output_file_subzy, "w") as f: f.write(f"# Subzy execution failed. Stderr: {stderr[:200]}\n")
            return False
    except FileNotFoundError:
        print(f"[ERROR] Subzy command not found. Ensure it's installed and in PATH.")
        with open(output_file_subzy, "w") as f: f.write("# Subzy command not found.\n")
        return False
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Subzy timed out for {target_domain_for_log}.")
        if process and process.poll() is None: process.kill(); process.communicate()
        with open(output_file_subzy, "w") as f: f.write("# Subzy timed out.\n")
        return False
    except Exception as e:
        print(f"[ERROR] An exception occurred while running Subzy for {target_domain_for_log}: {e}")
        with open(output_file_subzy, "w") as f: f.write(f"# Exception during Subzy run: {e}\n")
        return False

async def _check_item_liveness(item_to_check: str, client: httpx.AsyncClient, is_url: bool) -> tuple[str, bool, int | None]:
    urls_to_probe = []
    if is_url:
        urls_to_probe.append(item_to_check)
    else:
        subdomain = item_to_check
        ports_to_check = ["", ":8000", ":8080"]
        schemes = ["https", "http"]
        for port_suffix in ports_to_check:
            for scheme in schemes:
                if (scheme == "http" and port_suffix == "") or (scheme == "https" and port_suffix == ""):
                    urls_to_probe.append(f"{scheme}://{subdomain}")
                elif port_suffix:
                     urls_to_probe.append(f"{scheme}://{subdomain}{port_suffix}")
    for url_probe in urls_to_probe:
        try:
            response = await client.get(url_probe, timeout=7, follow_redirects=True)
            if not is_url and (200 <= response.status_code < 400 or response.status_code in [401, 403]):
                return item_to_check, True, response.status_code
            if is_url:
                return item_to_check, True, response.status_code
        except httpx.RequestError: pass
        except Exception: pass
    return item_to_check, False, None

async def get_liveness_async(items: set[str], is_url_check: bool = False) -> list[tuple[str, bool, int | None]]:
    live_results = []
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=10)
    async with httpx.AsyncClient(limits=limits, verify=False) as client:
        tasks = [_check_item_liveness(item, client, is_url_check) for item in items]
        results = await asyncio.gather(*tasks)
        for item, is_alive, status_code in results:
            live_results.append((item, is_alive, status_code))
    return live_results

def run_recon_workflow(target_domain: str, output_path: str = "./scan_results") -> dict:
    print(f"[INFO] Starting comprehensive recon workflow for: {target_domain}")
    domain_output_path = os.path.join(output_path, target_domain)
    os.makedirs(domain_output_path, exist_ok=True)
    print(f"[INFO] Output will be saved in: {domain_output_path}")

    # Define all output file paths at the beginning
    all_subdomains_file = os.path.join(domain_output_path, "Subdomain.txt")
    subdomains_alive_file = os.path.join(domain_output_path, "subdomains_alive.txt")
    subdomains_dead_file = os.path.join(domain_output_path, "subdomains_dead.txt")
    way_kat_file = os.path.join(domain_output_path, "Way_kat.txt")
    urls_alive_file = os.path.join(domain_output_path, "alive_domain.txt")
    urls_dead_file = os.path.join(domain_output_path, "dead_domain.txt")
    dns_resolutions_file = os.path.join(domain_output_path, "subdomain_dns_resolutions.json")
    subdomain_takeover_file = os.path.join(domain_output_path, "subdomain_takeover_vulnerable.txt")
    interesting_params_file = os.path.join(domain_output_path, "interesting_params.txt")
    xss_results_file = os.path.join(domain_output_path, "xss_vulnerabilities.json")
    sqli_results_file = os.path.join(domain_output_path, "sqli_vulnerabilities.json")
    lfi_results_file = os.path.join(domain_output_path, "lfi_vulnerabilities.json")
    cors_results_file = os.path.join(domain_output_path, "cors_vulnerabilities.json")
    sensitive_data_findings_file = os.path.join(domain_output_path, "sensitive_data_findings.json")
    ssrf_results_file = os.path.join(domain_output_path, "ssrf_vulnerabilities.json")
    xxe_results_file = os.path.join(domain_output_path, "xxe_vulnerabilities.json")
    rce_results_file = os.path.join(domain_output_path, "rce_vulnerabilities.json")

    wildcard_file = os.path.join(domain_output_path, "wildcard_domains.txt")
    metadata_file = os.path.join(domain_output_path, "subdomain_technologies.json")

    print("\n--- Running Subdomain Enumeration Tools ---")
    all_discovered_subdomains = set()
    with tempfile.TemporaryDirectory() as temp_dir:
        all_discovered_subdomains.update(run_subfinder(target_domain))
        all_discovered_subdomains.update(run_sublist3r(target_domain, temp_dir))
        all_discovered_subdomains.update(run_amass(target_domain))
        all_discovered_subdomains.update(run_assetfinder(target_domain))

    def create_placeholders_for_early_exit(reason_message: str):
        files_with_json_content_map = {
            dns_resolutions_file: {},
            xss_results_file: {"notes": f"XSS hunting skipped: {reason_message}", "vulnerabilities": []},
            sqli_results_file: {"notes": f"SQLi scanning skipped: {reason_message}", "vulnerabilities": []},
            lfi_results_file: {"notes": f"LFI hunting skipped: {reason_message}", "vulnerabilities": []},
            cors_results_file: {"notes": f"CORS scanning skipped: {reason_message}", "vulnerabilities": []},
            sensitive_data_findings_file: {"notes": f"Sensitive Data Exposure hunting skipped: {reason_message}", "vulnerabilities": []},
            ssrf_results_file: {"notes": f"SSRF scanning skipped: {reason_message}", "vulnerabilities": []},
            xxe_results_file: {"notes": f"XXE scanning skipped: {reason_message}", "vulnerabilities": []},
            rce_results_file: {"notes": f"RCE scanning skipped: {reason_message}", "vulnerabilities": []}
        }
        files_with_text_content_map = {
            subdomain_takeover_file: f"# Subdomain takeover check skipped: {reason_message}\n",
            interesting_params_file: f"# Parameter extraction skipped: {reason_message}\n",
        }
        list_based_files = [all_subdomains_file, subdomains_alive_file, subdomains_dead_file, way_kat_file, urls_alive_file, urls_dead_file, wildcard_file]

        all_placeholder_files_to_touch = list(files_with_json_content_map.keys()) + \
                                         list(files_with_text_content_map.keys()) + \
                                         list_based_files + [metadata_file]

        for f_path in all_placeholder_files_to_touch:
            if not os.path.exists(f_path):
                try:
                    if f_path in files_with_json_content_map:
                        with open(f_path, 'w') as f: json.dump(files_with_json_content_map[f_path], f, indent=4)
                    elif f_path in files_with_text_content_map:
                        with open(f_path, 'w') as f: f.write(files_with_text_content_map[f_path])
                    elif f_path == metadata_file:
                         with open(f_path, "w") as f: f.write("{}")
                    else:
                        open(f_path, 'w').close()
                except Exception as e:
                     print(f"[ERROR] Could not create placeholder file {f_path}: {e}")

    if not all_discovered_subdomains:
        print(f"[WARNING] No subdomains found by any tool for {target_domain}.")
        create_placeholders_for_early_exit("No subdomains found.")
        return {
            "target_domain": target_domain, "status": "completed_no_subdomains_found_by_any_tool",
            "all_subdomains_file": all_subdomains_file, "dns_resolutions_file": dns_resolutions_file,
            "subdomains_alive_file": subdomains_alive_file, "subdomains_dead_file": subdomains_dead_file,
            "takeover_vulnerable_file": subdomain_takeover_file, "way_kat_file": way_kat_file,
            "interesting_params_file": interesting_params_file, "urls_alive_file": urls_alive_file,
            "urls_dead_file": urls_dead_file, "sensitive_data_findings_file": sensitive_data_findings_file,
            "xss_results_file": xss_results_file, "sqli_results_file": sqli_results_file,
            "lfi_results_file": lfi_results_file, "cors_results_file": cors_results_file,
            "ssrf_results_file": ssrf_results_file, "xxe_results_file": xxe_results_file,
            "rce_results_file": rce_results_file,
            "wildcard_domains_file": wildcard_file, "metadata_file": metadata_file
        }

    sorted_subdomains = sorted(list(all_discovered_subdomains))
    with open(all_subdomains_file, "w") as f:
        for sub in sorted_subdomains: f.write(sub + "\n")
    print(f"[INFO] Consolidated {len(sorted_subdomains)} unique subdomains to {all_subdomains_file}")

    print("\n--- Performing DNS Resolution for Discovered Subdomains ---")
    dns_data = {}
    import socket
    for sub_idx, subdomain_to_resolve in enumerate(sorted_subdomains):
        if sub_idx > 0 and sub_idx % 100 == 0: print(f"[DNS] Resolved {sub_idx}/{len(sorted_subdomains)} subdomains...")
        try:
            _, _, ipaddrlist = socket.gethostbyname_ex(subdomain_to_resolve)
            dns_data[subdomain_to_resolve] = ipaddrlist if ipaddrlist else ["NXDOMAIN or No A/AAAA record"]
        except socket.gaierror: dns_data[subdomain_to_resolve] = ["ResolutionFailed"]
        except Exception as e: dns_data[subdomain_to_resolve] = [f"Error: {str(e)}"]; print(f"[DNS ERROR] for {subdomain_to_resolve}: {e}")
    with open(dns_resolutions_file, "w") as f_dns: json.dump(dns_data, f_dns, indent=4)
    print(f"[INFO] DNS resolution data saved to {dns_resolutions_file}")

    print("\n--- Checking Subdomain Liveness ---")
    subdomain_liveness_results = asyncio.run(get_liveness_async(all_discovered_subdomains, is_url_check=False))
    live_subs_list, dead_subs_list = [], []
    for sub, is_alive, _ in subdomain_liveness_results: (live_subs_list if is_alive else dead_subs_list).append(sub)
    with open(subdomains_alive_file, "w") as f:
        for sub in sorted(live_subs_list): f.write(sub + "\n")
    print(f"[INFO] Found {len(live_subs_list)} live subdomains. Saved to {subdomains_alive_file}")
    with open(subdomains_dead_file, "w") as f:
        for sub in sorted(dead_subs_list): f.write(sub + "\n")
    print(f"[INFO] Found {len(dead_subs_list)} dead subdomains. Saved to {subdomains_dead_file}")

    print("\n--- Running Subdomain Takeover Check (Subzy) ---")
    run_subzy_takeover_check(subdomains_alive_file, subdomain_takeover_file, target_domain)

    if not live_subs_list:
        print("[WARNING] No live subdomains found. Subsequent URL-based steps will be skipped.")
        create_placeholders_for_early_exit("No live subdomains.")
        return {
            "target_domain": target_domain, "status": "completed_no_live_subdomains",
            "all_subdomains_file": all_subdomains_file, "dns_resolutions_file": dns_resolutions_file,
            "subdomains_alive_file": subdomains_alive_file, "subdomains_dead_file": subdomains_dead_file,
            "takeover_vulnerable_file": subdomain_takeover_file, "way_kat_file": way_kat_file,
            "interesting_params_file": interesting_params_file, "urls_alive_file": urls_alive_file,
            "urls_dead_file": urls_dead_file, "sensitive_data_findings_file": sensitive_data_findings_file,
            "xss_results_file": xss_results_file, "sqli_results_file": sqli_results_file,
            "lfi_results_file": lfi_results_file, "cors_results_file": cors_results_file,
            "ssrf_results_file": ssrf_results_file, "xxe_results_file": xxe_results_file,
            "rce_results_file": rce_results_file,
            "wildcard_domains_file": wildcard_file, "metadata_file": metadata_file
        }

    print("\n--- Running URL Discovery Tools ---")
    all_discovered_urls = set()
    for live_sub in live_subs_list:
        print(f"[INFO] Discovering URLs for live subdomain: {live_sub}")
        all_discovered_urls.update(run_waybackurls(live_sub))
        all_discovered_urls.update(run_katana(live_sub))
        all_discovered_urls.update(run_gau(live_sub))
        all_discovered_urls.update(run_hakrawler(live_sub))

    cleaned_urls, final_urls_for_waykat = set(), set()
    for url in all_discovered_urls:
        cleaned_urls.add(f"https://{url}" if not url.startswith(('http://', 'https://')) else url)
    excluded_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map', '.jsonld'}
    for url in cleaned_urls:
        try:
            if not any(urlparse(url).path.lower().endswith(ext) for ext in excluded_extensions): final_urls_for_waykat.add(url)
        except: continue
    sorted_urls = sorted(list(final_urls_for_waykat))
    with open(way_kat_file, "w") as f:
        for url_item in sorted_urls: f.write(url_item + "\n")
    print(f"[INFO] Discovered {len(sorted_urls)} unique URLs (after filtering). Saved to {way_kat_file}")

    if not sorted_urls:
        print("[WARNING] No URLs found by any discovery tool or all were filtered. Subsequent URL-based steps will be skipped.")
        create_placeholders_for_early_exit("No URLs discovered/all filtered.")
        return {
            "target_domain": target_domain, "status": "completed_no_urls_discovered",
             "all_subdomains_file": all_subdomains_file, "dns_resolutions_file": dns_resolutions_file,
            "subdomains_alive_file": subdomains_alive_file, "subdomains_dead_file": subdomains_dead_file,
            "takeover_vulnerable_file": subdomain_takeover_file, "way_kat_file": way_kat_file,
            "interesting_params_file": interesting_params_file, "urls_alive_file": urls_alive_file,
            "urls_dead_file": urls_dead_file, "sensitive_data_findings_file": sensitive_data_findings_file,
            "xss_results_file": xss_results_file, "sqli_results_file": sqli_results_file,
            "lfi_results_file": lfi_results_file, "cors_results_file": cors_results_file,
            "ssrf_results_file": ssrf_results_file, "xxe_results_file": xxe_results_file,
            "rce_results_file": rce_results_file,
            "wildcard_domains_file": wildcard_file, "metadata_file": metadata_file
        }

    print("\n--- Extracting Parameters from Discovered URLs ---")
    extract_parameters_from_urls(way_kat_file, interesting_params_file)

    print("\n--- Filtering URLs (Checking Liveness & Status Codes) ---")
    url_liveness_results = asyncio.run(get_liveness_async(final_urls_for_waykat, is_url_check=True))
    live_urls_list, dead_urls_list = [], []
    for url, request_succeeded, status_code in url_liveness_results:
        if request_succeeded and status_code is not None:
            if 200 <= status_code < 400: live_urls_list.append(url)
            elif 400 <= status_code < 600: dead_urls_list.append(f"{url} [{status_code}]")
        else: dead_urls_list.append(f"{url} [Request Failed]")
    with open(urls_alive_file, "w") as f:
        for url_item in sorted(live_urls_list): f.write(url_item + "\n")
    print(f"[INFO] Found {len(live_urls_list)} live URLs (200s/30xs). Saved to {urls_alive_file}")
    with open(urls_dead_file, "w") as f:
        for url_status in sorted(dead_urls_list): f.write(url_status + "\n")
    print(f"[INFO] Found {len(dead_urls_list)} dead/error URLs. Saved to {urls_dead_file}")

    # --- Placeholder Vulnerability Scanners ---
    scan_input_valid = os.path.exists(urls_alive_file) and os.path.getsize(urls_alive_file) > 0

    # XSS Hunter
    print("\n--- Running XSS Hunter (Placeholder) ---" if scan_input_valid else "[INFO] Skipping XSS Hunter: No live URLs.")
    try:
        from ..xss_hunter.main import hunt_xss
        xss_scan_results = hunt_xss(urls_alive_file if scan_input_valid else "", domain_output_path)
        xss_results_file = xss_scan_results.get("xss_results_file", xss_results_file)
    except Exception as e:
        print(f"[ERROR] XSS Hunter call failed: {e}")
        if not os.path.exists(xss_results_file):
            with open(xss_results_file,"w") as f: json.dump({"notes": f"XSS scan error: {e}", "vulnerabilities":[]}, f, indent=4)

    # SQLi Scanner
    print("\n--- Running SQLi Scanner (Placeholder) ---" if scan_input_valid else "[INFO] Skipping SQLi Scanner: No live URLs.")
    try:
        from ..sqli_scanner.main import scan_for_sqli
        sqli_scan_results = scan_for_sqli(urls_alive_file if scan_input_valid else "", interesting_params_file, domain_output_path)
        sqli_results_file = sqli_scan_results.get("sqli_results_file", sqli_results_file)
    except Exception as e:
        print(f"[ERROR] SQLi Scanner call failed: {e}")
        if not os.path.exists(sqli_results_file):
             with open(sqli_results_file,"w") as f: json.dump({"notes": f"SQLi scan error: {e}", "vulnerabilities":[]},f, indent=4)

    # LFI Hunter
    print("\n--- Running LFI Hunter (Placeholder) ---" if scan_input_valid else "[INFO] Skipping LFI Hunter: No live URLs.")
    try:
        from ..lfi_hunter.main import hunt_for_lfi
        lfi_scan_results = hunt_for_lfi(urls_alive_file if scan_input_valid else "", interesting_params_file, domain_output_path)
        lfi_results_file = lfi_scan_results.get("lfi_results_file", lfi_results_file)
    except Exception as e:
        print(f"[ERROR] LFI Hunter call failed: {e}")
        if not os.path.exists(lfi_results_file):
            with open(lfi_results_file,"w") as f: json.dump({"notes": f"LFI scan error: {e}", "vulnerabilities":[]},f, indent=4)

    # CORS Hunter
    print("\n--- Running CORS Hunter (Placeholder) ---" if scan_input_valid else "[INFO] Skipping CORS Hunter: No live URLs.")
    try:
        from ..cors_hunter.main import hunt_for_cors_issues
        main_root_domain = urlparse(f"http://{target_domain}").netloc
        cors_scan_results = hunt_for_cors_issues(urls_alive_file if scan_input_valid else "", main_root_domain, domain_output_path)
        cors_results_file = cors_scan_results.get("cors_results_file", cors_results_file)
    except Exception as e:
        print(f"[ERROR] CORS Hunter call failed: {e}")
        if not os.path.exists(cors_results_file):
            with open(cors_results_file,"w") as f: json.dump({"notes": f"CORS scan error: {e}", "vulnerabilities":[]},f, indent=4)

    # Sensitive Data Exposure Hunter
    sde_input_valid = (os.path.exists(urls_alive_file) and os.path.getsize(urls_alive_file) > 0) or \
                      (os.path.exists(subdomains_alive_file) and os.path.getsize(subdomains_alive_file) > 0)
    print("\n--- Running Sensitive Data Exposure Hunter (Placeholder) ---" if sde_input_valid else "[INFO] Skipping SDE Hunter: No live URLs or subdomains.")
    try:
        from ..sensitive_data_hunter.main import hunt_for_sensitive_data
        sde_scan_results = hunt_for_sensitive_data(
            urls_alive_file if (os.path.exists(urls_alive_file) and os.path.getsize(urls_alive_file) > 0) else "",
            subdomains_alive_file if (os.path.exists(subdomains_alive_file) and os.path.getsize(subdomains_alive_file) > 0) else "",
            domain_output_path
        )
        sensitive_data_findings_file = sde_scan_results.get("sensitive_data_results_file", sensitive_data_findings_file)
    except Exception as e:
        print(f"[ERROR] SDE Hunter call failed: {e}")
        if not os.path.exists(sensitive_data_findings_file):
            with open(sensitive_data_findings_file,"w") as f_sde_err:
                json.dump({"notes": f"SDE scan error: {e}", "vulnerabilities":[]}, f_sde_err, indent=4)

    # SSRF Hunter
    print("\n--- Running SSRF Hunter (Placeholder) ---" if scan_input_valid else "[INFO] Skipping SSRF Hunter: No live URLs.")
    try:
        from ..ssrf_hunter.main import hunt_for_ssrf
        ssrf_scan_results = hunt_for_ssrf(urls_alive_file if scan_input_valid else "", interesting_params_file, domain_output_path)
        ssrf_results_file = ssrf_scan_results.get("ssrf_results_file", ssrf_results_file)
    except Exception as e:
        print(f"[ERROR] SSRF Hunter call failed: {e}")
        if not os.path.exists(ssrf_results_file):
            with open(ssrf_results_file, "w") as f: json.dump({"notes": f"SSRF scan error: {e}", "vulnerabilities": []}, f, indent=4)

    # XXE Hunter
    print("\n--- Running XXE Hunter (Placeholder) ---" if scan_input_valid else "[INFO] Skipping XXE Hunter: No live URLs.")
    try:
        from ..xxe_hunter.main import hunt_for_xxe
        xxe_scan_results = hunt_for_xxe(urls_alive_file if scan_input_valid else "", domain_output_path)
        xxe_results_file = xxe_scan_results.get("xxe_results_file", xxe_results_file)
    except Exception as e:
        print(f"[ERROR] XXE Hunter call failed: {e}")
        if not os.path.exists(xxe_results_file):
            with open(xxe_results_file,"w") as f: json.dump({"notes": f"XXE scan error: {e}", "vulnerabilities":[]}, f, indent=4)

    # RCE Hunter
    print("\n--- Running RCE Hunter (Placeholder) ---" if scan_input_valid else "[INFO] Skipping RCE Hunter: No live URLs.")
    try:
        from ..rce_hunter.main import hunt_for_rce
        rce_scan_results = hunt_for_rce(urls_alive_file if scan_input_valid else "", interesting_params_file, domain_output_path)
        rce_results_file = rce_scan_results.get("rce_results_file", rce_results_file)
    except Exception as e:
        print(f"[ERROR] RCE Hunter call failed: {e}")
        if not os.path.exists(rce_results_file):
            with open(rce_results_file, "w") as f: json.dump({"notes": f"RCE scan error: {e}", "vulnerabilities":[]}, f, indent=4)


    for f_path_final in [wildcard_file]:
        if not os.path.exists(f_path_final): open(f_path_final, 'w').close()
    if not os.path.exists(metadata_file):
        with open(metadata_file, "w") as f: f.write("{}")

    final_results = {
        "target_domain": target_domain, "status": "completed_full_recon_flow",
        "all_subdomains_file": all_subdomains_file, "dns_resolutions_file": dns_resolutions_file,
        "subdomains_alive_file": subdomains_alive_file, "subdomains_dead_file": subdomains_dead_file,
        "takeover_vulnerable_file": subdomain_takeover_file, "way_kat_file": way_kat_file,
        "interesting_params_file": interesting_params_file, "urls_alive_file": urls_alive_file,
        "urls_dead_file": urls_dead_file, "sensitive_data_findings_file": sensitive_data_findings_file,
        "xss_results_file": xss_results_file, "sqli_results_file": sqli_results_file,
        "lfi_results_file": lfi_results_file, "cors_results_file": cors_results_file,
        "ssrf_results_file": ssrf_results_file, "xxe_results_file": xxe_results_file,
        "rce_results_file": rce_results_file,
        "wildcard_domains_file": wildcard_file, "metadata_file": metadata_file,
    }
    print(f"\n[SUCCESS] Comprehensive recon workflow completed for: {target_domain}")
    return final_results

if __name__ == '__main__':
    test_domain = "testphp.vulnweb.com"
    output_dir = os.path.abspath("./temp_scan_results_comprehensive")
    print(f"--- Running Comprehensive Recon Workflow for '{test_domain}' ---")
    print(f"--- Output will be in: {output_dir}/{test_domain} ---")
    workflow_output = run_recon_workflow(test_domain, output_path=output_dir)
    print("\n--- Workflow Execution Summary ---")
    for key, val in workflow_output.items(): print(f"  {key}: {val}")
    print("\n--- Example commands to check some output files: ---")
    for key, val in workflow_output.items():
        if isinstance(val, str) and key.endswith("_file"): print(f"  cat \"{val}\"")
