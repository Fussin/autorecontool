# CyberHunter 3D - SQLi Scanner Main Logic (Placeholder)

import os
import json

def scan_for_sqli(target_urls_file: str, params_file: str, output_dir: str) -> dict:
    """
    Placeholder function for SQL Injection (SQLi) scanning.
    This function will simulate running SQLi detection tools.

    Args:
        target_urls_file (str): Path to a file containing live URLs (e.g., urls_alive_file).
        params_file (str): Path to a file containing interesting parameters (e.g., interesting_params.txt).
        output_dir (str): Directory to save 'sqli_vulnerabilities.json'.

    Returns:
        dict: Dictionary with path to 'sqli_vulnerabilities.json' and status.
    """
    print(f"[INFO] [SQLi Scanner] Starting SQLi scanning (placeholder) for URLs in: {target_urls_file}")
    if params_file and os.path.exists(params_file):
        print(f"[INFO] [SQLi Scanner] Will consider parameters from: {params_file}")

    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, "sqli_vulnerabilities.json")

    urls_to_scan = []
    try:
        if os.path.exists(target_urls_file) and os.path.getsize(target_urls_file) > 0:
            with open(target_urls_file, "r") as f:
                for line in f:
                    url = line.strip()
                    if url:
                        urls_to_scan.append(url)
        else:
            print(f"[INFO] [SQLi Scanner] Target URLs file '{target_urls_file}' is empty or not found. Skipping SQLi checks.")
            results_data = {
                "notes": "SQLi scanning skipped: Target URLs file was empty or not found.",
                "vulnerabilities": []
            }
            with open(output_file_path, "w") as f_out:
                json.dump(results_data, f_out, indent=4)
            return {"sqli_results_file": output_file_path, "status": "skipped_no_urls"}

    except Exception as e:
        print(f"[ERROR] [SQLi Scanner] Failed to read target URLs file '{target_urls_file}': {e}")
        results_data = {
            "notes": f"SQLi scanning failed: Could not read target URLs file. Error: {e}",
            "vulnerabilities": []
        }
        with open(output_file_path, "w") as f_out:
            json.dump(results_data, f_out, indent=4)
        return {"sqli_results_file": output_file_path, "status": "error_reading_targets"}

    if not urls_to_scan:
        print("[INFO] [SQLi Scanner] No URLs to scan after reading file. Skipping actual SQLi checks.")
        results_data = {
            "notes": "SQLi scanning skipped: No URLs were available for scanning.",
            "vulnerabilities": []
        }
        with open(output_file_path, "w") as f_out:
            json.dump(results_data, f_out, indent=4)
        return {"sqli_results_file": output_file_path, "status": "skipped_no_urls_in_file"}

    print(f"[INFO] [SQLi Scanner] Would process {len(urls_to_scan)} URLs for SQLi vulnerabilities.")

import subprocess # For running SQLMap
import tempfile   # For SQLMap output directories
from urllib.parse import urlparse, parse_qs # To identify URLs with parameters
import re # For parsing SQLMap output

# --- SQLMap Execution Logic ---

def run_sqlmap_on_url(target_url: str, base_output_dir: str, sqlmap_command: str = "sqlmap") -> dict | None:
    """
    Runs SQLMap against a single URL and provides a summary.
    Relies on heuristic parsing of SQLMap's stdout for vulnerability confirmation.
    """
    print(f"[INFO] [SQLi Scanner] Preparing to run SQLMap on: {target_url}")
    vulnerability_details = None

    # Create a unique temporary output directory for this SQLMap run's session files
    # This helps keep SQLMap's numerous files organized and allows associating them with a specific test.
    # These directories could be cleaned up later or archived.
    parsed_url = urlparse(target_url)
    url_filename_safe = re.sub(r'[^\w\-_\.]', '_', parsed_url.netloc + parsed_url.path) # Create a safe filename component
    if len(url_filename_safe) > 100: # Truncate if too long
        url_filename_safe = url_filename_safe[:100]

    # Place SQLMap output within the main target's output directory for better organization
    sqlmap_session_parent_dir = os.path.join(base_output_dir, "sqlmap_sessions")
    os.makedirs(sqlmap_session_parent_dir, exist_ok=True)

    # Unique directory for this specific URL test
    # Using a simpler temp dir for now, as sqlmap uses --output-dir for its internal files
    # and we are not directly parsing its files in this phase.
    # The actual output dir for sqlmap will be temporary.

    # We will parse stdout rather than specific files for this initial integration.
    # SQLMap's own output directory can be temporary and cleaned up.

    temp_sqlmap_output_dir = tempfile.mkdtemp(prefix="sqlmap_out_", dir=sqlmap_session_parent_dir)
    print(f"[DEBUG] [SQLi Scanner] SQLMap temp output dir for {target_url}: {temp_sqlmap_output_dir}")

    # Basic SQLMap command flags
    # Level 1, Risk 1 for faster initial tests. Can be increased.
    # Technique EBU: Error-based, Boolean-based, Union-based. Time-based (T) is very slow.
    command = [
        sqlmap_command,
        "-u", target_url,
        "--batch",  # Run non-interactively
        "--random-agent",
        "--level=1", # Start with level 1 (can increase up to 5)
        "--risk=1",  # Start with risk 1 (can increase up to 3)
        "--technique=EBU", # Error, Boolean, Union. Add T for Time-based if needed (slower)
        "--dbms",      # Attempt to identify DBMS
        "--banner",    # Attempt to get banner
        "--is-dba",    # Check if DBA
        "--output-dir", temp_sqlmap_output_dir, # For SQLMap's session files
        "--flush-session", # Clears session for this target before starting
        # "--forms", # To test forms, if URL is not just GET params (more advanced)
        # "--crawl=1", # Basic crawl if URL is a base path (can be noisy/slow)
    ]

    try:
        print(f"[INFO] [SQLi Scanner] Executing SQLMap: {' '.join(command)}")
        # Increased timeout for SQLMap as it can be lengthy
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=temp_sqlmap_output_dir)
        stdout, stderr = process.communicate(timeout=900)  # 15-minute timeout per URL

        if process.returncode == 0: # SQLMap often exits 0 even if no vulns, check output
            print(f"[INFO] [SQLi Scanner] SQLMap finished for {target_url}. Analyzing output...")
            # Heuristic check for vulnerabilities in stdout
            # SQLMap's output indicating vulnerability often includes:
            # "parameter '...' is vulnerable"
            # "identified the following injection point(s)"
            # "GET parameter '...' is vulnerable"
            # "POST parameter '...' is vulnerable"
            # "Cookie parameter '...' is vulnerable"
            # "it was determined that the back-end DBMS is..." (often precedes vuln details)

            vuln_found = False
            implicated_param = "unknown"
            dbms_info = "unknown"

            if "is vulnerable" in stdout.lower() or "injection point(s)" in stdout.lower():
                vuln_found = True
                # Try to find parameter if mentioned
                param_match = re.search(r"parameter '([^']+)' is vulnerable", stdout, re.IGNORECASE)
                if param_match:
                    implicated_param = param_match.group(1)

            dbms_match = re.search(r"back-end DBMS is ([\w\s\.]+)\.", stdout, re.IGNORECASE)
            if dbms_match:
                dbms_info = dbms_match.group(1).strip()

            if vuln_found:
                print(f"[VULN_FOUND] [SQLi Scanner] Potential SQLi found by SQLMap at {target_url}")
                vulnerability_details = {
                    "url": target_url,
                    "parameter_implicated": implicated_param,
                    "type_of_sqli": "Generic SQLi (via SQLMap - check logs)",
                    "dbms_fingerprint": dbms_info,
                    "notes": "SQLMap reported potential vulnerability. Further investigation of SQLMap logs required.",
                    "sqlmap_output_dir_relative": os.path.relpath(temp_sqlmap_output_dir, base_output_dir) # Relative path for reporting
                }
            else:
                print(f"[INFO] [SQLi Scanner] SQLMap did not report obvious vulnerabilities in stdout for {target_url}.")
        else:
            print(f"[ERROR] [SQLi Scanner] SQLMap exited with code {process.returncode} for {target_url}.")
            print(f"[ERROR] [SQLi Scanner] SQLMap stderr: {stderr[:500]}...")
            # If SQLMap itself errors, we might not have a vuln, but it's an execution issue.
            # Still, good to log the attempt.
            # No vulnerability_details created here.

    except FileNotFoundError:
        print(f"[ERROR] [SQLi Scanner] SQLMap command ('{sqlmap_command}') not found. Please ensure it is installed and in your PATH.")
        # This error will apply to all subsequent calls in this scan, so we might want to stop early.
        # For now, it will just fail for each URL.
        raise # Re-raise to be caught by the main try-except in scan_for_sqli
    except subprocess.TimeoutExpired:
        print(f"[ERROR] [SQLi Scanner] SQLMap timed out for {target_url}.")
        if process and process.poll() is None:
            process.kill()
            process.communicate()
    except Exception as e:
        print(f"[ERROR] [SQLi Scanner] An exception occurred while running SQLMap for {target_url}: {e}")

    # We are not deleting temp_sqlmap_output_dir here;
    # its path is in vulnerability_details if a vuln is found, for manual review.
    # A cleanup strategy for these dirs would be needed for long-term use.

    return vulnerability_details


def scan_for_sqli(target_urls_file: str, params_file: str, output_dir: str) -> dict:
    """
    Performs SQL Injection (SQLi) scanning using SQLMap.
    """
    print(f"[INFO] [SQLi Scanner] Starting SQLi scanning with SQLMap for URLs in: {target_urls_file}")
    if params_file and os.path.exists(params_file): # params_file currently not actively used to select params for SQLMap
        print(f"[INFO] [SQLi Scanner] Parameter file found (currently for informational logging): {params_file}")

    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, "sqli_vulnerabilities.json")
    sqlmap_command_to_try = "sqlmap" # Could be configurable: sqlmap, sqlmap.py, python sqlmap.py

    urls_to_scan = []
    # ... (rest of the file reading logic from previous version remains the same) ...
    try:
        if os.path.exists(target_urls_file) and os.path.getsize(target_urls_file) > 0:
            with open(target_urls_file, "r") as f:
                for line in f:
                    url = line.strip()
                    if url and "?" in url: # Prioritize URLs with query parameters for SQLMap
                        urls_to_scan.append(url)
            if not urls_to_scan:
                 print(f"[INFO] [SQLi Scanner] No URLs with query parameters found in '{target_urls_file}'. SQLMap will not be run unless enhanced to check forms/other points.")
        else:
            print(f"[INFO] [SQLi Scanner] Target URLs file '{target_urls_file}' is empty or not found. Skipping SQLi checks.")
            # ... (early exit JSON writing from previous version) ...
            results_data = {
                "notes": "SQLi scanning skipped: Target URLs file was empty or not found, or no URLs with parameters.",
                "vulnerabilities": []
            }
            with open(output_file_path, "w") as f_out: json.dump(results_data, f_out, indent=4)
            return {"sqli_results_file": output_file_path, "status": "skipped_no_parameterized_urls"}

    except Exception as e: # File reading error
        # ... (early exit JSON writing from previous version) ...
        print(f"[ERROR] [SQLi Scanner] Failed to read target URLs file '{target_urls_file}': {e}")
        results_data = {"notes": f"SQLi scanning failed: Could not read target URLs file. Error: {e}", "vulnerabilities": []}
        with open(output_file_path, "w") as f_out: json.dump(results_data, f_out, indent=4)
        return {"sqli_results_file": output_file_path, "status": "error_reading_targets"}


    if not urls_to_scan: # Should be caught by the specific check above, but as a safeguard
        print("[INFO] [SQLi Scanner] No suitable URLs to scan after reading file. Skipping SQLMap execution.")
        # ... (early exit JSON writing from previous version) ...
        results_data = {"notes": "SQLi scanning skipped: No suitable URLs for scanning.", "vulnerabilities": []}
        with open(output_file_path, "w") as f_out: json.dump(results_data, f_out, indent=4)
        return {"sqli_results_file": output_file_path, "status": "skipped_no_suitable_urls"}

    print(f"[INFO] [SQLi Scanner] Will attempt to run SQLMap on {len(urls_to_scan)} URLs with parameters.")

    found_vulnerabilities = []
    sqlmap_executable_found = True # Assume found until first error

    for url in urls_to_scan:
        if not sqlmap_executable_found:
            print("[INFO] [SQLi Scanner] SQLMap not found, skipping remaining URLs for SQLMap scan.")
            break
        try:
            # Pass `output_dir` which is the target-specific base (e.g., instance/scan_outputs/example.com)
            # run_sqlmap_on_url will create a sub-folder `sqlmap_sessions` within it.
            vuln = run_sqlmap_on_url(url, output_dir, sqlmap_command_to_try)
            if vuln:
                found_vulnerabilities.append(vuln)
        except FileNotFoundError: # Raised from run_sqlmap_on_url if sqlmap command is not found
            sqlmap_executable_found = False # Set flag to stop trying
            # No specific vuln to add, but the overall notes will reflect this.
        except Exception as e: # Catch any other unexpected error from the wrapper
            print(f"[ERROR] [SQLi Scanner] Unexpected error processing URL {url} with SQLMap wrapper: {e}")


    notes_message = "SQLMap execution attempted."
    if not sqlmap_executable_found:
        notes_message = f"SQLMap execution failed: command '{sqlmap_command_to_try}' not found. Please ensure SQLMap is installed and in PATH."
    elif not found_vulnerabilities and urls_to_scan:
        notes_message = "SQLMap execution completed. No obvious vulnerabilities found in stdout analysis for processed URLs."
    elif found_vulnerabilities:
        notes_message = f"SQLMap execution completed. Found {len(found_vulnerabilities)} potential SQLi point(s). Review SQLMap output directories for details."


    results_data = {
        "notes": notes_message,
        "vulnerabilities": found_vulnerabilities
    }

    try:
        with open(output_file_path, "w") as f_out:
            json.dump(results_data, f_out, indent=4)
        print(f"[INFO] [SQLi Scanner] SQLMap scan results saved to: {output_file_path}")
        return {"sqli_results_file": output_file_path, "status": "completed_sqlmap_run"}
    except Exception as e:
        print(f"[ERROR] [SQLi Scanner] Failed to write SQLMap scan results: {e}")
        return {"sqli_results_file": output_file_path, "status": "error_writing_results"}


if __name__ == '__main__':
    # Example Usage:
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    base_test_output_path = os.path.join(current_script_dir, "..", "..", "temp_outputs_for_testing")

    test_target_domain = "example-sqli-test.com"
    target_specific_output_dir = os.path.join(base_test_output_path, test_target_domain)
    os.makedirs(target_specific_output_dir, exist_ok=True)

    dummy_urls_file = os.path.join(target_specific_output_dir, "urls_alive_file_for_sqli.txt")
    with open(dummy_urls_file, "w") as f:
        f.write("http://testphp.vulnweb.com/listproducts.php?cat=1\n") # Known to have SQLi
        f.write("http://testphp.vulnweb.com/artists.php?artist=1\n")
        f.write("http://example.com/search?query=test\n")

    dummy_params_file = os.path.join(target_specific_output_dir, "interesting_params_for_sqli.txt")
    with open(dummy_params_file, "w") as f:
        f.write("cat\n")
        f.write("artist\n")
        f.write("query\n")
        f.write("id\n")


    print(f"Running SQLi Scanner (placeholder) using: {dummy_urls_file} and {dummy_params_file}")
    print(f"Output will be in: {target_specific_output_dir}")

    results = scan_for_sqli(dummy_urls_file, dummy_params_file, target_specific_output_dir)
    print("\nSQLi Scanner (Placeholder) Results:")
    print(json.dumps(results, indent=4))

    if results.get("sqli_results_file"):
        print(f"\nContents of {results['sqli_results_file']}:")
        try:
            with open(results['sqli_results_file'], "r") as f_out:
                print(f_out.read())
        except FileNotFoundError:
            print("Output file not found.")

    print(f"\nNote: Test files are in {target_specific_output_dir}.")
```
