# CyberHunter 3D - Subdomain Enumeration Main Logic

import subprocess
import os
import httpx
import asyncio # For async httpx calls

def run_subfinder(target_domain: str) -> set[str]:
    """
    Runs Subfinder to discover subdomains for the given target domain.

    Args:
        target_domain (str): The domain to enumerate.

    Returns:
        set[str]: A set of unique subdomains found by Subfinder.
                  Returns an empty set if Subfinder fails or is not found.
    """
    print(f"[INFO] Running Subfinder for: {target_domain}")
    found_subdomains = set()
    try:
        # Command: subfinder -d <target_domain> -silent
        process = subprocess.Popen(
            ["subfinder", "-d", target_domain, "-silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(timeout=300)  # 5-minute timeout

        if process.returncode == 0:
            for line in stdout.splitlines():
                subdomain = line.strip()
                if subdomain:
                    found_subdomains.add(subdomain)
            print(f"[INFO] Subfinder found {len(found_subdomains)} subdomains for {target_domain}.")
        else:
            print(f"[ERROR] Subfinder failed for {target_domain}. Return code: {process.returncode}")
            print(f"[ERROR] Subfinder stderr: {stderr}")
            if "command not found" in stderr.lower() or "no such file or directory" in stderr.lower():
                print("[ERROR] Subfinder command not found. Please ensure it is installed and in your PATH.")
    except FileNotFoundError:
        print("[ERROR] Subfinder command not found. Please ensure it is installed and in your PATH.")
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Subfinder timed out for {target_domain}.")
        if process:
            process.kill()
            stdout, stderr = process.communicate() #
    except Exception as e:
        print(f"[ERROR] An exception occurred while running Subfinder for {target_domain}: {e}")

    return found_subdomains

async def check_liveness(subdomain: str, client: httpx.AsyncClient) -> tuple[str, bool]:
    """
    Checks if a subdomain is alive by trying HTTP and HTTPS.

    Args:
        subdomain (str): The subdomain to check.
        client (httpx.AsyncClient): An httpx async client.

    Returns:
        tuple[str, bool]: The subdomain and a boolean indicating if it's alive.
    """
    urls_to_check = [f"https://{subdomain}", f"http://{subdomain}"]
    for url in urls_to_check:
        try:
            response = await client.get(url, timeout=10) # 10-second timeout per request
            # Consider any 2xx, 3xx, or even 401/403 as "alive" for this purpose
            if 200 <= response.status_code < 500 and response.status_code != 404:
                # print(f"[DEBUG] {subdomain} is alive (status: {response.status_code} on {url})")
                return subdomain, True
        except httpx.RequestError as e:
            # print(f"[DEBUG] httpx.RequestError for {url}: {type(e).__name__}")
            pass # Common errors: ConnectError, ReadTimeout, etc.
        except Exception as e:
            # print(f"[DEBUG] Unexpected error for {url}: {e}")
            pass # Catch any other unexpected errors during the request
    # print(f"[DEBUG] {subdomain} appears dead after checking HTTP/HTTPS.")
    return subdomain, False

async def get_live_subdomains(subdomains: set[str]) -> tuple[list[str], list[str]]:
    """
    Asynchronously checks a list of subdomains for liveness.

    Args:
        subdomains (set[str]): A set of subdomains to check.

    Returns:
        tuple[list[str], list[str]]: A tuple containing two lists:
                                     - alive_subdomains
                                     - dead_subdomains
    """
    alive_ones = []
    dead_ones = []
    # Adjust limits as needed, consider system resources and typical target sizes
    # Default httpx limits are usually fine (e.g., 100 connections)
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=True) as client: # verify=False for self-signed certs, follow_redirects for accuracy
        tasks = [check_liveness(sub, client) for sub in subdomains]
        results = await asyncio.gather(*tasks) # Use asyncio.gather for concurrent execution
        for subdomain, is_alive in results:
            if is_alive:
                alive_ones.append(subdomain)
            else:
                dead_ones.append(subdomain)
    return sorted(list(set(alive_ones))), sorted(list(set(dead_ones)))


def enumerate_subdomains(target_domain: str, output_path: str = "./scan_results") -> dict:
    """
    Performs subdomain enumeration using Subfinder and checks liveness using httpx.

    Args:
        target_domain (str): The domain to enumerate subdomains for (e.g., "example.com").
        output_path (str): The base path to store output files.

    Returns:
        dict: A dictionary containing paths to the generated output files and status.
    """
    print(f"[INFO] Starting functional subdomain enumeration for: {target_domain}")

    domain_output_path = os.path.join(output_path, target_domain)
    os.makedirs(domain_output_path, exist_ok=True)
    print(f"[INFO] Output will be saved in: {domain_output_path}")

    all_subdomains_file = os.path.join(domain_output_path, "Subdomain.txt")
    alive_subdomains_file = os.path.join(domain_output_path, "subdomains_alive.txt")
    dead_subdomains_file = os.path.join(domain_output_path, "subdomains_dead.txt")

    # Placeholder file paths for outputs not yet implemented
    takeover_file = os.path.join(domain_output_path, "subdomain_takeover.txt")
    wildcard_file = os.path.join(domain_output_path, "wildcard_domains.txt")
    metadata_file = os.path.join(domain_output_path, "subdomain_technologies.json")

    # Step 1: Run Subfinder
    discovered_subdomains = run_subfinder(target_domain)

    if not discovered_subdomains:
        print(f"[WARNING] No subdomains found by Subfinder for {target_domain} or Subfinder failed.")
        # Create empty files to signify completion but no data
        with open(all_subdomains_file, "w") as f: pass
        with open(alive_subdomains_file, "w") as f: pass
        with open(dead_subdomains_file, "w") as f: pass
        with open(takeover_file, "w") as f: pass # Create placeholder
        with open(wildcard_file, "w") as f: pass # Create placeholder
        with open(metadata_file, "w") as f: f.write("{}") # Create placeholder
        return {
            "target_domain": target_domain,
            "all_subdomains_file": all_subdomains_file,
            "alive_subdomains_file": alive_subdomains_file,
            "dead_subdomains_file": dead_subdomains_file,
            "takeover_vulnerable_file": takeover_file,
            "wildcard_domains_file": wildcard_file,
            "metadata_file": metadata_file,
            "status": "completed_no_subdomains_found" if not discovered_subdomains else "completed_subfinder_failed"
        }

    sorted_discovered_subdomains = sorted(list(discovered_subdomains))
    with open(all_subdomains_file, "w") as f:
        for sub in sorted_discovered_subdomains:
            f.write(sub + "\n")
    print(f"[INFO] All {len(sorted_discovered_subdomains)} discovered subdomains written to {all_subdomains_file}")

    # Step 2: Check Liveness using httpx (asynchronously)
    print(f"[INFO] Checking liveness for {len(discovered_subdomains)} subdomains...")
    # Run the async function for liveness checks
    alive_subdomains, dead_subdomains = asyncio.run(get_live_subdomains(discovered_subdomains))

    with open(alive_subdomains_file, "w") as f:
        for sub in alive_subdomains:
            f.write(sub + "\n")
    print(f"[INFO] {len(alive_subdomains)} alive subdomains written to {alive_subdomains_file}")

    with open(dead_subdomains_file, "w") as f:
        for sub in dead_subdomains:
            f.write(sub + "\n")
    print(f"[INFO] {len(dead_subdomains)} dead subdomains written to {dead_subdomains_file}")

    # Create other placeholder output files for now
    with open(takeover_file, "w") as f: pass # Placeholder
    with open(wildcard_file, "w") as f: pass # Placeholder
    with open(metadata_file, "w") as f: f.write("{}") # Placeholder JSON

    results = {
        "target_domain": target_domain,
        "all_subdomains_file": all_subdomains_file,
        "alive_subdomains_file": alive_subdomains_file,
        "dead_subdomains_file": dead_subdomains_file,
        "takeover_vulnerable_file": takeover_file, # Placeholder path
        "wildcard_domains_file": wildcard_file,    # Placeholder path
        "metadata_file": metadata_file,            # Placeholder path
        "status": "completed_functional"
    }

    print(f"[INFO] Subdomain enumeration and liveness check completed for: {target_domain}")
    return results

if __name__ == '__main__':
    # Example usage (for direct testing of this module)
    # Ensure Subfinder is in PATH for this to work.
    # If Subfinder is not found, the script will report an error and produce empty files.
    domain_to_scan = "example.com" # Replace with a domain you want to test (e.g., "projectdiscovery.io")
    # domain_to_scan = "google.com" # For a more extensive test
    scan_output_directory = os.path.abspath("./temp_scan_results_functional")

    print(f"Running functional subdomain enumeration for '{domain_to_scan}'...")
    print(f"Output will be in: {scan_output_directory}/{domain_to_scan}")

    # Ensure httpx is installed: pip install httpx
    # Ensure Subfinder is installed and in PATH.
    # Example: GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

    output_details = enumerate_subdomains(domain_to_scan, output_path=scan_output_directory)

    print("\nFunctional Subdomain Enumeration Results:")
    for key, path_or_value in output_details.items():
        print(f"  {key}: {path_or_value}")

    print("\nTo check results:")
    print(f"  cat \"{output_details.get('all_subdomains_file', 'N/A')}\"")
    print(f"  cat \"{output_details.get('alive_subdomains_file', 'N/A')}\"")
    print(f"  cat \"{output_details.get('dead_subdomains_file', 'N/A')}\"")
