# CyberHunter 3D - Subdomain Enumeration Main Logic

import subprocess
import os
import httpx
import asyncio
import tempfile
import re
import json # Added for DNS resolution output

# --- Subdomain Enumeration Tool Wrappers ---

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
                # Basic validation for subdomains/URLs (can be improved)
                if item and ('.' in item): # Simple check, might need refinement
                    # Normalize: remove http/https prefixes for subdomain tools if any accidentally add them
                    item = re.sub(r'^https?://', '', item)
                    found_items.add(item)
            print(f"[INFO] {tool_name} found {len(found_items)} items for {target_domain}.")
        else:
            print(f"[ERROR] {tool_name} failed for {target_domain}. RC: {process.returncode}")
            print(f"[ERROR] {tool_name} stderr: {stderr[:500]}...") # Log first 500 chars
            if "command not found" in stderr.lower() or "no such file or directory" in stderr.lower():
                print(f"[ERROR] {tool_name} command not found. Ensure it's installed and in PATH.")
    except FileNotFoundError:
        print(f"[ERROR] {tool_name} command not found. Ensure it's installed and in PATH.")
    except subprocess.TimeoutExpired:
        print(f"[ERROR] {tool_name} timed out for {target_domain}.")
        if process and process.poll() is None: # Check if process still running
            process.kill()
            process.communicate() # Clean up
    except Exception as e:
        print(f"[ERROR] An exception occurred while running {tool_name} for {target_domain}: {e}")
    return found_items

def run_subfinder(target_domain: str) -> set[str]:
    return _run_tool(["subfinder", "-d", target_domain, "-silent"], "Subfinder", target_domain)

def run_sublist3r(target_domain: str, temp_dir: str) -> set[str]:
    # Sublist3r needs an output file, then we read from it.
    temp_output_file = os.path.join(temp_dir, f"sublist3r_{target_domain}.txt")
    command = ["sublist3r", "-d", target_domain, "-o", temp_output_file]
    # Run it first to generate the file
    _run_tool(command, "Sublist3r", target_domain) # This call's return is not used directly for subdomains

    # Now read the output file if it was created
    subdomains = set()
    if os.path.exists(temp_output_file):
        try:
            with open(temp_output_file, "r") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and '.' in subdomain: # Basic validation
                         subdomains.add(subdomain)
            print(f"[INFO] Sublist3r (from file) found {len(subdomains)} subdomains for {target_domain}.")
        except Exception as e:
            print(f"[ERROR] Could not read Sublist3r output file {temp_output_file}: {e}")
        finally:
            # Clean up the temporary file
            try:
                os.remove(temp_output_file)
            except OSError:
                pass # Ignore if removal fails
    else:
        print(f"[INFO] Sublist3r did not create an output file or failed: {temp_output_file}")
    return subdomains


def run_amass(target_domain: str) -> set[str]:
    # Basic Amass intel command for passive enumeration
    return _run_tool(["amass", "intel", "-d", target_domain, "-whois", "-ip"], "Amass", target_domain)

def run_assetfinder(target_domain: str) -> set[str]:
    return _run_tool(["assetfinder", "--subs-only", target_domain], "Assetfinder", target_domain)

# --- URL Discovery Tool Wrappers ---

def run_waybackurls(target: str) -> set[str]: # Target can be a domain or subdomain
    return _run_tool(["waybackurls", target], "Waybackurls", target)

def run_katana(target: str) -> set[str]: # Target can be a domain or subdomain
    # -silent -jc for JS parsing, -nc for no colors
    return _run_tool(["katana", "-u", target, "-silent", "-jc", "-nc", "-aff", "-kf", "all"], "Katana", target)


# --- Liveness Checking (for subdomains and URLs) ---

async def _check_item_liveness(item_to_check: str, client: httpx.AsyncClient, is_url: bool) -> tuple[str, bool, int | None]:
    """
    Checks if a subdomain or URL is alive.
    Returns item, is_alive (bool), status_code (int or None).
    """
    urls_to_probe = []
    if is_url:
        urls_to_probe.append(item_to_check) # If it's a full URL, check it as is
    else: # it's a subdomain, construct URLs with different schemes and common ports
        subdomain = item_to_check
        ports_to_check = ["", ":8000", ":8080"] # Empty string for default ports (80, 443)
        schemes = ["https", "http"]

        for port_suffix in ports_to_check:
            for scheme in schemes:
                # Avoid adding :80 for http and :443 for https as httpx handles these defaults
                if (scheme == "http" and port_suffix == "") or \
                   (scheme == "https" and port_suffix == ""):
                    urls_to_probe.append(f"{scheme}://{subdomain}")
                elif port_suffix: # Only add port if it's specified (e.g., :8000, :8080)
                     urls_to_probe.append(f"{scheme}://{subdomain}{port_suffix}")

        # Ensure unique URLs if some combinations resolve to the same (e.g. http://domain:80)
        # Though with current logic, it's mostly distinct.
        # print(f"[DEBUG] Probing for {subdomain}: {urls_to_probe}")


    for url_probe in urls_to_probe:
        try:
            # print(f"[DEBUG] Checking liveness for: {url_probe}")
            response = await client.get(url_probe, timeout=7, follow_redirects=True) # Reduced timeout for more probes

            # For subdomains (is_url=False): any 2xx, 3xx, 401, 403 on any probed port is "alive"
            if not is_url and (200 <= response.status_code < 400 or response.status_code in [401, 403]):
                # print(f"[DEBUG] {item_to_check} (as {url_probe}) is alive, status: {response.status_code}")
                return item_to_check, True, response.status_code # Return with the first success

            # For URLs (is_url=True): we care about the specific status code for filtering
            if is_url:
                return item_to_check, True, response.status_code # True means request succeeded
        except httpx.RequestError:
            # print(f"[DEBUG] RequestError for {url_probe}")
            pass
        except Exception as e:
            # print(f"[DEBUG] Generic error for {url_probe}: {e}")
            pass # Catch any other unexpected errors
    return item_to_check, False, None


async def get_liveness_async(items: set[str], is_url_check: bool = False) -> list[tuple[str, bool, int | None]]:
    """
    Asynchronously checks a list of subdomains or URLs for liveness.
    Returns a list of tuples: (item, is_alive, status_code).
    For subdomains (is_url_check=False), is_alive means reachable on HTTP/S.
    For URLs (is_url_check=True), is_alive means the request completed, status_code is key.
    """
    live_results = []
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=10) # Reduced from 100/20 to be gentler
    async with httpx.AsyncClient(limits=limits, verify=False) as client:
        tasks = [_check_item_liveness(item, client, is_url_check) for item in items]
        results = await asyncio.gather(*tasks)
        for item, is_alive, status_code in results:
            live_results.append((item, is_alive, status_code))
    return live_results

# --- Main Orchestration ---

def run_recon_workflow(target_domain: str, output_path: str = "./scan_results") -> dict:
    print(f"[INFO] Starting comprehensive recon workflow for: {target_domain}")
    domain_output_path = os.path.join(output_path, target_domain)
    os.makedirs(domain_output_path, exist_ok=True)
    print(f"[INFO] Output will be saved in: {domain_output_path}")

    # File path definitions
    all_subdomains_file = os.path.join(domain_output_path, "Subdomain.txt")
    subdomains_alive_file = os.path.join(domain_output_path, "subdomains_alive.txt") # Live subdomains
    subdomains_dead_file = os.path.join(domain_output_path, "subdomains_dead.txt")   # Dead subdomains
    way_kat_file = os.path.join(domain_output_path, "Way_kat.txt")
    urls_alive_file = os.path.join(domain_output_path, "alive_domain.txt") # Live URLs (200s, 30xs)
    urls_dead_file = os.path.join(domain_output_path, "dead_domain.txt")   # Dead URLs (40xs, 50xs)

    # Placeholders for files not yet fully implemented in this phase
    takeover_file = os.path.join(domain_output_path, "subdomain_takeover.txt")
    wildcard_file = os.path.join(domain_output_path, "wildcard_domains.txt")
    metadata_file = os.path.join(domain_output_path, "subdomain_technologies.json")

    # --- Phase 1: Subdomain Enumeration ---
    print("\n--- Running Subdomain Enumeration Tools ---")
    all_discovered_subdomains = set()
    with tempfile.TemporaryDirectory() as temp_dir: # For tools like sublist3r that need temp files
        all_discovered_subdomains.update(run_subfinder(target_domain))
        all_discovered_subdomains.update(run_sublist3r(target_domain, temp_dir))
        all_discovered_subdomains.update(run_amass(target_domain))
        all_discovered_subdomains.update(run_assetfinder(target_domain))

    # Initialize sensitive_exposure_file path early for all return paths
    sensitive_exposure_file = os.path.join(domain_output_path, "sensitive_exposure.txt")
    # Initialize dns_resolutions_file path early as well
    dns_resolutions_file = os.path.join(domain_output_path, "subdomain_dns_resolutions.json")


    if not all_discovered_subdomains:
        print(f"[WARNING] No subdomains found by any tool for {target_domain}.")
        # Create all expected files as empty
        for f_path in [all_subdomains_file, dns_resolutions_file, subdomains_alive_file, subdomains_dead_file, way_kat_file, urls_alive_file, urls_dead_file, takeover_file, wildcard_file, sensitive_exposure_file]:
            open(f_path, 'w').close()
        with open(metadata_file, "w") as f: f.write("{}") # metadata also empty
        return {
            "target_domain": target_domain, "status": "completed_no_subdomains_found_by_any_tool",
            "all_subdomains_file": all_subdomains_file,
            "dns_resolutions_file": dns_resolutions_file, # Ensure it's in all return paths
            "subdomains_alive_file": subdomains_alive_file,
            "subdomains_dead_file": subdomains_dead_file, "way_kat_file": way_kat_file,
            "urls_alive_file": urls_alive_file, "urls_dead_file": urls_dead_file,
            "sensitive_exposure_file": sensitive_exposure_file,
            "takeover_vulnerable_file": takeover_file, "wildcard_domains_file": wildcard_file,
            "metadata_file": metadata_file
        }

    sorted_subdomains = sorted(list(all_discovered_subdomains))
    with open(all_subdomains_file, "w") as f:
        for sub in sorted_subdomains:
            f.write(sub + "\n")
    print(f"[INFO] Consolidated {len(sorted_subdomains)} unique subdomains to {all_subdomains_file}")

    # --- Phase 1b: DNS Resolution (Optional - can be done before or after liveness) ---
    print("\n--- Performing DNS Resolution for Discovered Subdomains ---")
    dns_resolutions_file = os.path.join(domain_output_path, "subdomain_dns_resolutions.json")
    dns_data = {}
    # Using a simple synchronous approach for DNS resolution for now.
    # For very large lists, async DNS resolution (e.g., with aiodns) would be better.
    import socket
    for sub_idx, subdomain_to_resolve in enumerate(sorted_subdomains):
        if sub_idx > 0 and sub_idx % 100 == 0: # Log progress
            print(f"[DNS] Resolved {sub_idx}/{len(sorted_subdomains)} subdomains...")
        try:
            # gethostbyname_ex can return multiple IPs (canonical name, aliases, ipaddrlist)
            # We are interested in ipaddrlist
            _, _, ipaddrlist = socket.gethostbyname_ex(subdomain_to_resolve)
            if ipaddrlist:
                dns_data[subdomain_to_resolve] = ipaddrlist
            else:
                dns_data[subdomain_to_resolve] = ["NXDOMAIN or No A/AAAA record"] # Or some other indicator
        except socket.gaierror: # getaddrinfo error (e.g., NXDOMAIN)
            dns_data[subdomain_to_resolve] = ["ResolutionFailed"]
        except Exception as e:
            dns_data[subdomain_to_resolve] = [f"Error: {str(e)}"]
            print(f"[DNS ERROR] for {subdomain_to_resolve}: {e}")

    with open(dns_resolutions_file, "w") as f_dns:
        json.dump(dns_data, f_dns, indent=4)
    print(f"[INFO] DNS resolution data saved to {dns_resolutions_file}")


    # --- Phase 1c: Subdomain Liveness ---
    print("\n--- Checking Subdomain Liveness ---")
    subdomain_liveness_results = asyncio.run(get_liveness_async(all_discovered_subdomains, is_url_check=False))

    live_subs_list = []
    dead_subs_list = []
    for sub, is_alive, _ in subdomain_liveness_results:
        if is_alive:
            live_subs_list.append(sub)
        else:
            dead_subs_list.append(sub)

    with open(subdomains_alive_file, "w") as f:
        for sub in sorted(live_subs_list): f.write(sub + "\n")
    print(f"[INFO] Found {len(live_subs_list)} live subdomains. Saved to {subdomains_alive_file}")
    with open(subdomains_dead_file, "w") as f:
        for sub in sorted(dead_subs_list): f.write(sub + "\n")
    print(f"[INFO] Found {len(dead_subs_list)} dead subdomains. Saved to {subdomains_dead_file}")

    if not live_subs_list:
        print("[WARNING] No live subdomains found. URL discovery and filtering will be skipped.")
        # Create empty files for URL stages
        for f_path in [way_kat_file, urls_alive_file, urls_dead_file, sensitive_exposure_file]: open(f_path, 'w').close()
        with open(takeover_file, "w") as f: pass
        with open(wildcard_file, "w") as f: pass
        with open(metadata_file, "w") as f: f.write("{}")
        return {
            "target_domain": target_domain, "status": "completed_no_live_subdomains",
            "all_subdomains_file": all_subdomains_file,
            "dns_resolutions_file": dns_resolutions_file, # Ensure it's in all return paths
            "subdomains_alive_file": subdomains_alive_file,
            "subdomains_dead_file": subdomains_dead_file, "way_kat_file": way_kat_file,
            "urls_alive_file": urls_alive_file, "urls_dead_file": urls_dead_file,
            "sensitive_exposure_file": sensitive_exposure_file,
            "takeover_vulnerable_file": takeover_file, "wildcard_domains_file": wildcard_file,
            "metadata_file": metadata_file
        }

    # --- Phase 2: URL Discovery (Waybackurls, Katana) ---
    print("\n--- Running URL Discovery Tools (Waybackurls, Katana) ---")
    all_discovered_urls = set()
    # Process only live subdomains for URL discovery
    # Can run these in parallel per subdomain if performance becomes an issue later
    for live_sub in live_subs_list:
        all_discovered_urls.update(run_waybackurls(live_sub))
        all_discovered_urls.update(run_katana(live_sub))
        # Small sleep to avoid overwhelming services if any tool hits APIs rapidly
        # asyncio.run(asyncio.sleep(0.1)) # If this part were async

    sorted_urls = sorted(list(all_discovered_urls))
    with open(way_kat_file, "w") as f:
        for url in sorted_urls:
            f.write(url + "\n")
    print(f"[INFO] Discovered {len(sorted_urls)} unique URLs. Saved to {way_kat_file}")

    if not sorted_urls:
        print("[WARNING] No URLs found by Waybackurls or Katana.")
        # Create empty files for URL filtering stage
        for f_path in [urls_alive_file, urls_dead_file, sensitive_exposure_file]: open(f_path, 'w').close()
        with open(takeover_file, "w") as f: pass
        with open(wildcard_file, "w") as f: pass
        with open(metadata_file, "w") as f: f.write("{}")
        return {
            "target_domain": target_domain, "status": "completed_no_urls_discovered",
            "all_subdomains_file": all_subdomains_file,
            "dns_resolutions_file": dns_resolutions_file, # Ensure it's in all return paths
            "subdomains_alive_file": subdomains_alive_file,
            "subdomains_dead_file": subdomains_dead_file, "way_kat_file": way_kat_file,
            "urls_alive_file": urls_alive_file, "urls_dead_file": urls_dead_file,
            "sensitive_exposure_file": sensitive_exposure_file,
            "takeover_vulnerable_file": takeover_file, "wildcard_domains_file": wildcard_file,
            "metadata_file": metadata_file
        }

    # --- Phase 3: URL Filtering ---
    print("\n--- Filtering URLs (Checking Liveness & Status Codes) ---")
    url_liveness_results = asyncio.run(get_liveness_async(all_discovered_urls, is_url_check=True))

    live_urls_list = [] # 200s, 30xs
    dead_urls_list = []   # 40xs, 50xs (and others that failed)

    for url, request_succeeded, status_code in url_liveness_results:
        if request_succeeded and status_code is not None:
            if 200 <= status_code < 400: # 200 OK and 30x redirects
                live_urls_list.append(url)
            elif 400 <= status_code < 600: # 40x client errors, 50x server errors
                dead_urls_list.append(f"{url} [{status_code}]") # Append status for context
            # else: consider other status codes (1xx, etc.) as neither explicitly alive nor dead for these lists
        else: # Request failed entirely
            dead_urls_list.append(f"{url} [Request Failed]")

    with open(urls_alive_file, "w") as f:
        for url in sorted(live_urls_list): f.write(url + "\n")
    print(f"[INFO] Found {len(live_urls_list)} live URLs (200s/30xs). Saved to {urls_alive_file}")

    with open(urls_dead_file, "w") as f:
        for url_status in sorted(dead_urls_list): f.write(url_status + "\n")
    print(f"[INFO] Found {len(dead_urls_list)} dead/error URLs (40xs/50xs/failed). Saved to {urls_dead_file}")

    # --- Phase 4: Sensitive Data Discovery ---
    # Initialize sensitive_exposure_file path for the results dict even if discovery is skipped
    sensitive_exposure_file = os.path.join(domain_output_path, "sensitive_exposure.txt")
    if not live_urls_list:
        print("[INFO] No live URLs found after filtering. Skipping sensitive data discovery.")
        with open(sensitive_exposure_file, "w") as f: f.write("# No live URLs to scan for sensitive data.\n")
    else:
        print("\n--- Running Sensitive Data Discovery ---")
        try:
            # Dynamically import here to avoid circular dependency issues if modules call each other
            # and to keep it optional if the module isn't present.
            from ..sensitive_data_discovery.main import find_sensitive_data
            sdd_results = find_sensitive_data(
                target_urls_file=urls_alive_file, # Use the live URLs from this workflow
                output_dir=domain_output_path     # Save in the same target-specific directory
            )
            if sdd_results.get("sensitive_exposure_file"):
                sensitive_exposure_file = sdd_results["sensitive_exposure_file"] # Update with actual path if returned
            print(f"Sensitive data discovery status: {sdd_results.get('status')}")
        except ImportError:
            print("[WARN] Sensitive data discovery module not found or could not be imported. Skipping.")
            with open(sensitive_exposure_file, "w") as f: f.write("# Sensitive data discovery module not available.\n")
        except Exception as e:
            print(f"[ERROR] Error during sensitive data discovery: {e}")
            with open(sensitive_exposure_file, "w") as f: f.write(f"# Error during sensitive data discovery: {e}\n")


    # Create other placeholder output files
    with open(takeover_file, "w") as f: pass
    with open(wildcard_file, "w") as f: pass
    with open(metadata_file, "w") as f: f.write("{}")

    final_results = {
        "target_domain": target_domain,
        "status": "completed_full_recon_flow", # This status might need to be more dynamic based on stages completed
        "all_subdomains_file": all_subdomains_file,
        "dns_resolutions_file": dns_resolutions_file, # Added DNS resolution file
        "subdomains_alive_file": subdomains_alive_file,
        "subdomains_dead_file": subdomains_dead_file,
        "way_kat_file": way_kat_file,
        "urls_alive_file": urls_alive_file,
        "urls_dead_file": urls_dead_file,
        "sensitive_exposure_file": sensitive_exposure_file,
        "takeover_vulnerable_file": takeover_file,
        "wildcard_domains_file": wildcard_file,
        "metadata_file": metadata_file,
    }
    print(f"\n[SUCCESS] Comprehensive recon workflow completed for: {target_domain}")
    return final_results


if __name__ == '__main__':
    # Test the full workflow
    # Ensure all tools (Subfinder, Sublist3r, Amass, Assetfinder, Waybackurls, Katana) are in PATH.
    # And httpx, sublist3r are pip installed.

    # Import for direct testing if sensitive data discovery is also tested here
    try:
        from ..sensitive_data_discovery.main import find_sensitive_data
        SENSITIVE_DISCOVERY_IMPORTED = True
    except ImportError:
        print("[WARN] Could not import sensitive_data_discovery module for direct combined testing.")
        SENSITIVE_DISCOVERY_IMPORTED = False

    # test_domain = "example.com" # Limited results, good for quick test
    # test_domain = "projectdiscovery.io" # More substantial results
    test_domain = "testphp.vulnweb.com" # Another good test case, known for some exposures

    output_dir = os.path.abspath("./temp_scan_results_comprehensive")

    print(f"--- Running Comprehensive Recon Workflow for '{test_domain}' ---")
    print(f"--- Output will be in: {output_dir}/{test_domain} ---")

    # Execute the main workflow function (renamed from enumerate_subdomains)
    workflow_output = run_recon_workflow(test_domain, output_path=output_dir)

    # --- Example of running sensitive data discovery after recon ---
    # This part would typically be orchestrated by a higher-level component or the API handler,
    # but for direct script testing, we can call it here if the recon was successful.
    if SENSITIVE_DISCOVERY_IMPORTED and workflow_output.get("status") not in [
            "completed_no_subdomains_found_by_any_tool",
            "completed_no_live_subdomains",
            "completed_no_urls_discovered"] and workflow_output.get("urls_alive_file"):

        print(f"\n--- Additionally Running Sensitive Data Discovery ---")
        target_specific_output_dir = os.path.join(output_dir, test_domain)
        urls_to_scan_for_sensitive_data = workflow_output["urls_alive_file"]

        if os.path.exists(urls_to_scan_for_sensitive_data) and os.path.getsize(urls_to_scan_for_sensitive_data) > 0:
            sensitive_results = find_sensitive_data(
                target_urls_file=urls_to_scan_for_sensitive_data,
                output_dir=target_specific_output_dir # Save in the same target-specific directory
            )
            print(f"Sensitive data discovery results: {sensitive_results}")
            # Add sensitive discovery results to the main workflow output for the summary
            if sensitive_results.get("sensitive_exposure_file"):
                workflow_output["sensitive_exposure_file"] = sensitive_results["sensitive_exposure_file"]
        else:
            print("[INFO] Skipping sensitive data discovery as no live URLs file was found or it's empty.")
            workflow_output["sensitive_exposure_file"] = os.path.join(target_specific_output_dir, "sensitive_exposure.txt") # expected path even if empty
            if not os.path.exists(workflow_output["sensitive_exposure_file"]):
                 with open(workflow_output["sensitive_exposure_file"], "w") as f: f.write("# No live URLs to scan for sensitive data.\n")


    print("\n--- Workflow Execution Summary (including sensitive discovery if run) ---")
    for key, val in workflow_output.items():
        print(f"  {key}: {val}")

    print("\n--- Example commands to check some output files: ---")
    print(f"  cat \"{workflow_output.get('all_subdomains_file', 'N/A')}\" | wc -l")
    print(f"  cat \"{workflow_output.get('subdomains_alive_file', 'N/A')}\" | wc -l")
    print(f"  cat \"{workflow_output.get('way_kat_file', 'N/A')}\" | wc -l")
    print(f"  head \"{workflow_output.get('urls_alive_file', 'N/A')}\"")
    print(f"  head \"{workflow_output.get('urls_dead_file', 'N/A')}\"")
