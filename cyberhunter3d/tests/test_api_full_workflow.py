import unittest
import time
import subprocess
import os
import requests # To make HTTP requests to the API
import json
import sys

# Ensure the main project directory 'cyberhunter3d' is in PYTHONPATH
# to allow imports like 'from ch_api.main_api import app' if running tests from root
# For direct script execution or from 'tests' dir, this helps locate 'cyberhunter3d' package.
current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root_dir_tests = os.path.dirname(current_script_dir) # This is 'cyberhunter3d'
project_root_for_ch_modules = os.path.dirname(project_root_dir_tests) # Up one more level to include 'ch_modules'

if project_root_dir_tests not in sys.path:
    sys.path.insert(0, project_root_dir_tests)
if project_root_for_ch_modules not in sys.path: # For the aggregator and its parsers
    sys.path.insert(0, project_root_for_ch_modules)


class TestApiFullWorkflow(unittest.TestCase):
    FLASK_API_URL = "http://127.0.0.1:5000" # Assuming default Flask port
    flask_process = None
    test_target = "testphp.vulnweb.com" # A good target for testing the full flow, generates some recon data
    # test_target = "example.com" # Simpler target if above is too slow or problematic

    @classmethod
    def setUpClass(cls):
        # Start the Flask API server as a subprocess
        # Ensure that main_api.py is executable or called via python -m
        api_main_path = os.path.join(project_root_dir_tests, "ch_api", "main_api.py")

        # Log file in /tmp for easier access if tests run in restricted environments
        cls.flask_log_path = "/tmp/flask_api_full_workflow.log"
        try: # Ensure old log is cleared or file is writable
            if os.path.exists(cls.flask_log_path):
                os.remove(cls.flask_log_path)
            cls.flask_log_file = open(cls.flask_log_path, "w")
        except Exception as e:
            print(f"Warning: Could not create or clear log file {cls.flask_log_path}: {e}")
            cls.flask_log_file = sys.stdout # Fallback to stdout if file fails


        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        # project_root_for_ch_modules is /app/
        new_pythonpath = f"{project_root_for_ch_modules}{os.pathsep}{existing_pythonpath}"
        env["PYTHONPATH"] = new_pythonpath

        env["FLASK_ENV"] = "development"
        # Ensure instance path and output base dir exist for the test, relative to project_root_dir_tests (cyberhunter3d/)
        instance_dir = os.path.join(project_root_dir_tests, "instance")
        scan_outputs_dir = os.path.join(instance_dir, "test_scan_outputs")
        os.makedirs(instance_dir, exist_ok=True)
        os.makedirs(scan_outputs_dir, exist_ok=True)

        # The app itself will use its configured instance_path to create these,
        # but the test needs to know where to expect them if it were to override.
        # For now, we let the app use its default derived paths inside its instance_path.
        # env["DATABASE_URL"] = "sqlite:///" + os.path.join(instance_dir, "test_workflow_app.db")
        # env["SCAN_OUTPUT_BASE_DIR_CONFIG"] = scan_outputs_dir


        # Command to run Flask.
        # api_main_path is cyberhunter3d/ch_api/main_api.py
        # We will run it from project_root_for_ch_modules (/app)
        # Use python -m to run the main_api as a module within its package context
        command_to_run = [sys.executable, "-m", "cyberhunter3d.ch_api.main_api"]

        cls.flask_process = subprocess.Popen(
            command_to_run, # Example: python -m cyberhunter3d.ch_api.main_api
            stdout=cls.flask_log_file,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=project_root_for_ch_modules # Set CWD to /app
        )

        print(f"Flask API server starting for full workflow test (PID: {cls.flask_process.pid})... Log: {cls.flask_log_path}")

        time.sleep(10)

        server_ready = False
        for _ in range(5): # Try to connect a few times
            try:
                # Use a health endpoint if available, otherwise a known good one or dummy
                health_url = f"{cls.FLASK_API_URL}/health" # main_api.py has /health
                response = requests.get(health_url, timeout=3)
                if response.status_code == 200:
                    server_ready = True
                    break
            except requests.ConnectionError:
                print("Flask server not ready yet, retrying...")
                time.sleep(3)

        if not server_ready:
            print(f"Flask server did not start or become healthy. Check log: {cls.flask_log_path}")
            # Print log content to aid debugging
            if cls.flask_log_file != sys.stdout : cls.flask_log_file.close() # Close it first
            try:
                with open(cls.flask_log_path, "r") as f_log_display:
                    print("\n--- Flask API Log (from test_api_full_workflow.py) ---")
                    print(f_log_display.read())
                    print("--- End Flask API Log ---")
            except Exception as e_log:
                print(f"Could not read flask log {cls.flask_log_path}: {e_log}")

            cls.tearDownClass()
            raise Exception("Flask server failed to start for tests.")
        print("Flask server appears to be running and healthy.")


    @classmethod
    def tearDownClass(cls):
        if cls.flask_process:
            print(f"\nStopping Flask API server (PID: {cls.flask_process.pid})...")
            cls.flask_process.terminate()
            try:
                cls.flask_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("Flask server did not terminate gracefully, killing...")
                cls.flask_process.kill()
                cls.flask_process.wait() # Wait for kill to complete
            print("Flask API server stopped.")

        if hasattr(cls, 'flask_log_file') and cls.flask_log_file != sys.stdout and not cls.flask_log_file.closed:
            cls.flask_log_file.close()

        # Optional: remove log file after tests if desired
        # if os.path.exists(cls.flask_log_path):
        #     os.remove(cls.flask_log_path)


    def test_full_scan_workflow_and_aggregation(self):
        print(f"\n--- Testing Full Scan Workflow for {self.test_target} ---")

        # 1. Submit target for scan
        submit_url = f"{self.FLASK_API_URL}/api/v1/scan/recon"
        payload = {"target": self.test_target}
        try:
            response = requests.post(submit_url, json=payload, timeout=10)
            response.raise_for_status() # Raise an exception for HTTP errors
        except requests.RequestException as e:
            self.fail(f"Failed to submit scan for {self.test_target}: {e}")

        self.assertEqual(response.status_code, 202)
        response_data = response.json()
        self.assertIn("scan_id", response_data)
        scan_id = response_data["scan_id"]
        print(f"Scan ID for {self.test_target}: {scan_id}")

        # 2. Poll status endpoint
        status_url = f"{self.FLASK_API_URL}{response_data['status_endpoint']}"
        max_wait_time = 300  # Max wait 5 minutes for the scan (adjust as needed for testphp.vulnweb.com)
        poll_interval = 10   # Poll every 10 seconds
        start_time = time.time()
        scan_status = ""

        while time.time() - start_time < max_wait_time:
            print(f"Polling status for scan {scan_id}...")
            try:
                status_response = requests.get(status_url, timeout=5)
                status_response.raise_for_status()
                status_data = status_response.json()
                scan_status = status_data.get("status")
                print(f"Current scan status: {scan_status}, Error: {status_data.get('error')}")
                if scan_status == "completed":
                    break
                if scan_status == "failed":
                    self.fail(f"Scan {scan_id} failed: {status_data.get('error', 'Unknown error')}")
            except requests.RequestException as e:
                print(f"Could not poll status (will retry): {e}")

            time.sleep(poll_interval)
        else: # Loop exhausted
            self.fail(f"Scan {scan_id} did not complete within {max_wait_time} seconds. Last status: {scan_status}")

        self.assertEqual(scan_status, "completed", "Scan did not complete successfully.")

        # 3. Fetch results
        results_url = f"{self.FLASK_API_URL}{response_data['results_endpoint']}"
        print(f"Fetching results for scan {scan_id} from {results_url}...")
        try:
            results_response = requests.get(results_url, timeout=10)
            results_response.raise_for_status()
        except requests.RequestException as e:
            self.fail(f"Failed to fetch results for scan {scan_id}: {e}")

        self.assertEqual(results_response.status_code, 200)
        results_data = results_response.json()
        # print(f"Results data: {json.dumps(results_data, indent=2)}")


        # 4. Verify aggregated_vulnerabilities_file
        self.assertIn("aggregated_vulnerabilities_file", results_data,
                      "'aggregated_vulnerabilities_file' key missing from API results.")

        aggregated_file_path = results_data["aggregated_vulnerabilities_file"]
        self.assertIsNotNone(aggregated_file_path, "Path for aggregated vulnerabilities file is null.")

        # The path returned by API is absolute path within the container/server.
        # We need to check if this file exists.
        # For testing, we assume the test script has access to this path or can map it.
        # Since SCAN_OUTPUT_BASE_DIR_CONFIG is set, the path should be under there.
        # This check might be tricky if tests run outside the Flask container's FS view.
        # For now, let's assume the path is accessible as is.
        self.assertTrue(os.path.exists(aggregated_file_path),
                        f"Aggregated vulnerabilities file does not exist at path: {aggregated_file_path}")

        # 5. Basic check on aggregated file content
        try:
            with open(aggregated_file_path, 'r') as f:
                aggregated_content = json.load(f)
            self.assertIsInstance(aggregated_content, list,
                                  "Aggregated vulnerabilities content is not a JSON list.")
            print(f"Successfully loaded aggregated vulnerabilities file: {aggregated_file_path}. Contains {len(aggregated_content)} items.")
            if aggregated_content: # If not empty, check first item schema roughly
                first_vuln = aggregated_content[0]
                self.assertIn("id", first_vuln)
                self.assertIn("vulnerability_type", first_vuln)
                self.assertIn("target_url", first_vuln)
                self.assertIn("scan_id", first_vuln)
                self.assertEqual(first_vuln["scan_id"], scan_id)
        except json.JSONDecodeError:
            self.fail(f"Aggregated vulnerabilities file is not valid JSON: {aggregated_file_path}")
        except Exception as e:
            self.fail(f"Error reading or validating aggregated_vulnerabilities.json: {e}")

        print(f"Full workflow test for {self.test_target} passed.")

        # 6. Verify network_scan_results_file (Phase 19)
        self.assertIn("network_scan_results_file", results_data,
                      "'network_scan_results_file' key missing from API results.")
        network_results_file_path = results_data["network_scan_results_file"]
        self.assertIsNotNone(network_results_file_path, "Path for network scan results file is null.")
        self.assertTrue(os.path.exists(network_results_file_path),
                        f"Network scan results file does not exist at path: {network_results_file_path}")

        try:
            with open(network_results_file_path, 'r') as f:
                network_content = json.load(f)
            self.assertIsInstance(network_content, dict,
                                  "Network scan results content is not a JSON object.")
            self.assertIn("scan_id", network_content)
            self.assertEqual(network_content["scan_id"], scan_id)
            self.assertIn("hosts", network_content)
            self.assertIsInstance(network_content["hosts"], list)
            # For testphp.vulnweb.com (no live subdomains after initial recon),
            # network scan should be skipped.
            if self.test_target == "testphp.vulnweb.com":
                 self.assertEqual(network_content.get("status"), "skipped_no_subdomains_found_by_any_tool", # Updated expected status
                                 f"Expected network scan status 'skipped_no_subdomains_found_by_any_tool' for {self.test_target}, got {network_content.get('status')}")
            print(f"Successfully loaded network_scan_results.json: {network_results_file_path}. Status: {network_content.get('status')}")

        except json.JSONDecodeError:
            self.fail(f"Network scan results file is not valid JSON: {network_results_file_path}")
        except Exception as e:
            self.fail(f"Error reading or validating network_scan_results.json: {e}")

        print(f"Network scan module integration checks passed for {self.test_target}.")


if __name__ == "__main__":
    unittest.main()
