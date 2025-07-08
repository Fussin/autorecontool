# CyberHunter 3D - Sensitive Data Discovery Main Logic

import httpx
import asyncio
import os
from urllib.parse import urlparse, urljoin

# A list of common sensitive file extensions, paths, or path fragments.
# This list can be expanded significantly.
COMMON_SENSITIVE_PATTERNS = [
    ".env", ".env.local", ".env.dev", ".env.prod", ".env.example",
    ".aws/credentials", "credentials", "credentials.xml", "credential",
    ".git/config", ".svn/entries", ".DS_Store",
    "config.json", "settings.json", "localsettings.py", "configuration.php",
    "wp-config.php", "web.config",
    "backup.sql", "dump.sql", "database.sql", "db.sql",
    "backup.tar.gz", "backup.zip", "site.zip", "archive.zip",
    ".log", "error.log", "debug.log", "access.log",
    "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/id_dsa",
    "server-status", # Apache server status
    "phpinfo.php",
    "docker-compose.yml", "docker-compose.yaml",
    "Makefile",
    "README.md", # Sometimes contains info
    "swagger.json", "openapi.json", "api-docs.json", # API specs
    "CVS/Entries", "CVS/Root",
    "/.git/", "/.svn/", "/.hg/", # VCS directories themselves
    # Common admin paths (less about files, more about directories)
    "/admin/", "/administrator/", "/backup/", "/config/", "/db_admin/",
    "/phpmyadmin/", "/PMA/",
    # Some common backup file naming patterns (prefix/suffix)
    "_backup", "-backup", ".bak", ".old", ".orig", "~", ".swp",
    "copy_of_", "old_",
]

# Files that often contain secrets if found in source code (for future use with source analysis)
# SOURCE_CODE_SENSITIVE_FILES = ["settings.py", "config.py", "credentials.py", "db.py"]


async def check_url_for_pattern(base_url: str, pattern: str, client: httpx.AsyncClient) -> str | None:
    """
    Checks if a URL formed by base_url + pattern exists and returns 200 OK.
    Handles both relative paths and absolute paths patterns.
    """
    # Normalize base_url to ensure it has a scheme and ends with a slash if it's a directory-like URL
    parsed_base = urlparse(base_url)
    if not parsed_base.path.endswith('/') and '.' not in os.path.basename(parsed_base.path):
        base_url_norm = base_url + "/" # Assume it's a directory if no extension and no trailing slash
    else:
        base_url_norm = base_url

    # If pattern starts with '/', it's an absolute path from the domain root
    if pattern.startswith('/'):
        domain_root = f"{parsed_base.scheme}://{parsed_base.netloc}"
        sensitive_url = urljoin(domain_root, pattern.lstrip('/'))
    # If pattern is a common backup suffix/prefix, try attaching it to the filename/path
    elif pattern.startswith(("_", "-")) or pattern.endswith((".bak", ".old", ".orig", "~", ".swp")):
         # Try attaching to the last path component
        path_component = parsed_base.path.rsplit('/', 1)[-1]
        if path_component: # if there is a path component
            if pattern.startswith(("_", "-")): # prefix like _backup
                sensitive_url = urljoin(base_url_norm, pattern + path_component)
            else: # suffix like .bak
                sensitive_url = urljoin(base_url_norm, path_component + pattern)
        else: # No path component, try on the domain itself (less likely for these)
            sensitive_url = urljoin(base_url_norm, pattern) # e.g. example.com.bak
    else: # Standard relative path or file extension
        sensitive_url = urljoin(base_url_norm, pattern)

    try:
        # print(f"[DEBUG] Checking sensitive URL: {sensitive_url} (from base: {base_url}, pattern: {pattern})")
        response = await client.get(sensitive_url, timeout=7, follow_redirects=False) # Shorter timeout, no redirects for sensitive files
        if response.status_code == 200:
            # Basic content check to avoid listing common "not found" pages that return 200
            # This is very rudimentary and can be improved.
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type and ("not found" in response.text.lower() or "404" in response.text.lower()):
                if len(response.text) < 1024 : # Small HTML pages might be custom 404s
                    return None
            print(f"[SENSITIVE] Potential sensitive data at: {sensitive_url} (Status: {response.status_code})")
            return sensitive_url
        # Consider other status codes? e.g., 403 on a .git/config might still be interesting
    except httpx.RequestError:
        pass # Ignore connection errors, timeouts, etc.
    except Exception as e:
        # print(f"[DEBUG] Error checking {sensitive_url}: {e}")
        pass
    return None


async def find_sensitive_data_for_base_url(base_url: str, client: httpx.AsyncClient) -> list[str]:
    """
    Checks a single base URL against all predefined sensitive patterns.
    """
    found_exposures = []
    tasks = [check_url_for_pattern(base_url, pattern, client) for pattern in COMMON_SENSITIVE_PATTERNS]
    results = await asyncio.gather(*tasks)
    for result_url in results:
        if result_url:
            found_exposures.append(result_url)
    return found_exposures


def find_sensitive_data(target_urls_file: str, output_dir: str) -> dict:
    """
    Reads a list of URLs and checks each for common sensitive file exposures.

    Args:
        target_urls_file (str): Path to a file containing a list of live URLs (e.g., alive_domain.txt).
        output_dir (str): The directory to save the output `sensitive_exposure.txt` file.
                          This should be the specific target's output directory.

    Returns:
        dict: A dictionary containing the path to the `sensitive_exposure.txt` file.
    """
    print(f"[INFO] Starting sensitive data discovery from URLs in: {target_urls_file}")
    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, "sensitive_exposure.txt")

    base_urls_to_check = []
    try:
        with open(target_urls_file, "r") as f:
            for line in f:
                url = line.strip()
                if url and (url.startswith("http://") or url.startswith("https://")):
                    base_urls_to_check.append(url)
    except FileNotFoundError:
        print(f"[ERROR] Target URLs file not found: {target_urls_file}")
        with open(output_file_path, "w") as f: # Create empty file
            f.write("# Target URLs file not found.\n")
        return {"sensitive_exposure_file": output_file_path, "status": "error_target_file_not_found"}

    if not base_urls_to_check:
        print("[INFO] No base URLs to check for sensitive data.")
        with open(output_file_path, "w") as f: # Create empty file
            f.write("# No base URLs provided or file was empty.\n")
        return {"sensitive_exposure_file": output_file_path, "status": "no_urls_to_check"}

    all_found_exposures = set()

    async def run_checks():
        limits = httpx.Limits(max_connections=30, max_keepalive_connections=10) # Be gentler
        async with httpx.AsyncClient(limits=limits, verify=False, timeout=10) as client:
            # Process URLs in batches if the list is very large to avoid creating too many asyncio tasks at once
            batch_size = 100
            for i in range(0, len(base_urls_to_check), batch_size):
                batch = base_urls_to_check[i:i+batch_size]
                print(f"[INFO] Processing batch {i//batch_size + 1} for sensitive data discovery ({len(batch)} URLs)...")
                tasks = [find_sensitive_data_for_base_url(url, client) for url in batch]
                results_for_batch = await asyncio.gather(*tasks)
                for exposures_for_url in results_for_batch:
                    for exposed_url in exposures_for_url:
                        all_found_exposures.add(exposed_url)

    asyncio.run(run_checks())

    with open(output_file_path, "w") as f:
        if all_found_exposures:
            for url in sorted(list(all_found_exposures)):
                f.write(url + "\n")
            print(f"[INFO] Found {len(all_found_exposures)} potential sensitive exposures. Results saved to: {output_file_path}")
        else:
            f.write("# No sensitive exposures found matching common patterns.\n")
            print("[INFO] No sensitive exposures found matching common patterns.")

    return {"sensitive_exposure_file": output_file_path, "status": "completed"}


if __name__ == '__main__':
    # Example Usage:
    # Create a dummy alive_domain.txt for testing
    dummy_urls_file = "./temp_alive_urls.txt"
    # scan_output_dir_sdd = "./temp_scan_results_sdd_output" # This should be target specific dir
    # Example: if target is example.com, then scan_output_dir_sdd = "./temp_scan_results_comprehensive/example.com"

    # For this test, let's assume the output dir is already created by the main recon script
    # and we are just adding the sensitive_exposure.txt into it.
    # So, output_dir should point to the target's specific output folder.

    # Let's simulate a target and its output directory
    test_target_domain = "example.com" # Replace with a domain you have permission to test, or a test server
    base_output_path = os.path.abspath("./temp_sdd_test_run")
    target_specific_output_dir = os.path.join(base_output_path, test_target_domain)
    os.makedirs(target_specific_output_dir, exist_ok=True)

    dummy_urls_file_path = os.path.join(target_specific_output_dir, "dummy_alive_urls_for_sdd.txt")

    with open(dummy_urls_file_path, "w") as f:
        f.write(f"http://{test_target_domain}\n")
        f.write(f"https://{test_target_domain}\n")
        f.write(f"http://testphp.vulnweb.com/\n") # A site known for some exposures
        f.write(f"http://testphp.vulnweb.com/admin/\n")


    print(f"Running sensitive data discovery using: {dummy_urls_file_path}")
    print(f"Output will be in: {target_specific_output_dir}")

    results = find_sensitive_data(dummy_urls_file_path, target_specific_output_dir)
    print("\nSensitive Data Discovery Results:")
    print(results)
    if results.get("sensitive_exposure_file"):
        print(f"\nContents of {results['sensitive_exposure_file']}:")
        try:
            with open(results['sensitive_exposure_file'], "r") as f_out:
                print(f_out.read())
        except FileNotFoundError:
            print("Output file not found.")

    # Clean up dummy file
    # os.remove(dummy_urls_file_path)
    print(f"\nNote: Test files are in {target_specific_output_dir}. You might want to clean it up manually.")

```
