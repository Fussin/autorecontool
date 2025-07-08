# CyberHunter 3D - Setup and Usage Instructions

## Overview

This document provides instructions on how to set up and run the current components of the CyberHunter 3D reconnaissance tool. The project is under active development.

Current capabilities include:
1.  A comprehensive reconnaissance script that performs:
    *   Subdomain enumeration using Subfinder, Sublist3r, Amass, and Assetfinder.
    *   Liveness checks on discovered subdomains using httpx.
    *   URL discovery from live subdomains using Waybackurls and Katana.
    *   Filtering of discovered URLs by HTTP status code (200s/30xs vs 40x/50xs) using httpx.
    *   Outputs results into structured text files.
2.  A basic asynchronous Flask API to trigger and manage these reconnaissance scans.

## 1. Setup Instructions

### 1.1. Prerequisites
*   Python 3.8+
*   `pip` (Python package installer)
*   `git` (for cloning, if you were to get this from a repository)
*   Go language environment (for installing Go-based tools)

### 1.2. Get the Code
If this were a Git repository, you would clone it:
```bash
git clone <repository_url>
cd cyberhunter3d
```
For now, you have the code in your current environment.

### 1.3. Setup Python Virtual Environment
It's highly recommended to use a virtual environment to manage project dependencies.

```bash
# Navigate to the project root directory (e.g., cyberhunter3d)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 1.4. Install Python Dependencies
Install all required Python libraries using `requirements.txt`:
```bash
pip install -r requirements.txt
```
This will install `Flask`, `httpx`, `sublist3r`, and their dependencies.

### 1.5. Install Go-based Tools
Several external Go-based tools are used by the reconnaissance script. You need to install them and ensure they are in your system's PATH.

*   **Subfinder:**
    ```bash
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    ```
*   **Amass:** (The script uses `amass intel -d <domain> -whois -ip`)
    ```bash
    go install -v github.com/owasp-amass/amass/v4/cmd/amass@master
    ```
*   **Assetfinder:**
    ```bash
    go install -v github.com/tomnomnom/assetfinder@latest
    ```
*   **Waybackurls:**
    ```bash
    go install -v github.com/tomnomnom/waybackurls@latest
    ```
*   **Katana:** (The script uses `katana -u <target> -silent -jc -nc -aff -kf all`)
    ```bash
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    ```
*   **Subzy:** (For subdomain takeover checks)
    ```bash
    go install -v github.com/LukaSikic/subzy@latest
    ```

**Verification:** After installation, ensure each tool is accessible by typing its name in the terminal (e.g., `subfinder -h`, `subzy -h`). If you get a "command not found" error, ensure your Go binary path (usually `$HOME/go/bin` or `$GOPATH/bin`) is added to your system's `PATH` environment variable.

## 2. Running the Reconnaissance Script Directly

You can run the comprehensive reconnaissance workflow directly from the command line.

### 2.1. Command
Navigate to the project root (`cyberhunter3d`) if you are not already there.
```bash
# Ensure your virtual environment is active: source .venv/bin/activate
python ch_modules/subdomain_enumeration/main.py
```
The script currently defaults to scanning `projectdiscovery.io` and saves results in `./temp_scan_results_comprehensive/`. You can modify the `test_domain` and `output_dir` variables in the `if __name__ == '__main__':` block of the script for different targets.

### 2.2. Output
The script will:
*   Print INFO and ERROR messages to the console, indicating which tools are being run and if they are found/fail.
*   Create an output directory structure like `output_dir/target_domain/`.
*   Generate the following files (among others):
    *   `Subdomain.txt`: All unique subdomains found.
    *   `subdomain_dns_resolutions.json`: JSON mapping subdomains to their resolved IP addresses.
    *   `subdomains_alive.txt`: Live subdomains (checked on ports 80, 443, 8000, 8080).
    *   `subdomains_dead.txt`: Subdomains that did not respond on the probed ports.
    *   `subdomain_takeover_vulnerable.txt`: Potential subdomain takeovers found by Subzy.
    *   `Way_kat.txt`: All URLs found from waybackurls/katana.
    *   `alive_domain.txt`: Live URLs (200s/30xs).
    *   `dead_domain.txt`: Dead/Error URLs (40xs/50xs).
    *   `sensitive_exposure.txt`: URLs of potential sensitive files/paths found.

## 3. Running the API Server

The Flask API allows you to manage scans programmatically.

### 3.1. Start the API Server
Navigate to the project root (`cyberhunter3d`).
Ensure your Python virtual environment is active.
Set the `PYTHONPATH` to include the project root, then run the API module:

```bash
# From the 'cyberhunter3d' directory
export PYTHONPATH=.:$PYTHONPATH # On Linux/macOS
# For Windows (cmd): set PYTHONPATH=.;%PYTHONPATH%
# For Windows (PowerShell): $env:PYTHONPATH = ".;" + $env:PYTHONPATH

python -m ch_api.main_api
```
The API server will start, typically on `http://localhost:5000`. Log messages, including the output directory for API scans (`scan_results_api/`), will be printed to the console.

### 3.2. Interacting with the API
You can use `curl` or tools like Postman to interact with the API.

*   **Health Check:**
    ```bash
    curl http://localhost:5000/health
    ```
    Expected Response: `{"status":"healthy","message":"CyberHunter API is up!"}`

*   **Start a New Reconnaissance Scan:**
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"target": "example.com"}' http://localhost:5000/api/v1/scan/recon
    ```
    Expected Response (202 Accepted):
    ```json
    {
      "message": "Reconnaissance scan initiated.",
      "results_endpoint": "/api/v1/scan/recon/results/YOUR_SCAN_ID",
      "scan_id": "YOUR_SCAN_ID",
      "status_endpoint": "/api/v1/scan/recon/status/YOUR_SCAN_ID"
    }
    ```
    Replace `YOUR_SCAN_ID` with the actual ID returned.

*   **Check Scan Status:**
    ```bash
    curl http://localhost:5000/api/v1/scan/recon/status/YOUR_SCAN_ID
    ```
    Expected Response (200 OK):
    ```json
    {
      "error": null,
      "scan_id": "YOUR_SCAN_ID",
      "status": "queued" // or "running", "completed", "failed"
      "target": "example.com"
    }
    ```

*   **Get Scan Results (once completed):**
    ```bash
    curl http://localhost:5000/api/v1/scan/recon/results/YOUR_SCAN_ID
    ```
    Expected Response (200 OK if completed): A JSON object containing paths to all generated output files.
    Example (paths will be absolute on your system, shown here relative to `instance/` for brevity):
    ```json
    {
        "all_subdomains_file": ".../instance/scan_outputs/example.com/Subdomain.txt",
        "sensitive_exposure_file": ".../instance/scan_outputs/example.com/sensitive_exposure.txt",
        "status": "completed_no_urls_discovered", // Example status
        // ... other file paths
    }
    ```
    If the scan is not yet complete, you'll get a 202 response. If failed, a 200 response with status "failed" in the body (or 500 for some DB errors).

*   **Accessing the Mock Login Page:**
    Once the API server is running (using `python -m ch_api.main_api`), you can open a web browser and navigate to:
    *   `http://localhost:5000/`
    *   or `http://localhost:5000/login`
    This will display the placeholder login page.
    *   `http://localhost:5000/targets`
    This will display the target input page.

*   **Interacting with Scan & Target Submission APIs (via `curl`):**
    *   **Submit Single Target for Scan:** (This is the original scan endpoint)
        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"target": "example.com"}' http://localhost:5000/api/v1/scan/recon
        ```
    *   **Submit Multiple Targets for Scans:**
        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"targets": ["example.com", "sub.example.org", "1.2.3.4"]}' http://localhost:5000/api/v1/targets/submit
        ```
        Expected Response (200 OK):
        ```json
        {
            "message": "Targets processed.",
            "submitted_targets": 3,
            "successfully_queued_scans": 3, // or fewer if some had errors
            "scan_details": [
                { "target": "example.com", "scan_id": "...", "status_endpoint": "...", "results_endpoint": "..." },
                // ... other targets
            ],
            "errors": [] // or list of errors if any
        }
        ```

*   **Interacting with Mock Auth API Endpoints (via `curl`):**
    *   **Login (mock - username: "testuser", password: "password123"):**
        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"username": "testuser", "password": "password123"}' http://localhost:5000/api/v1/auth/login
        ```
        Expected mock success: `{"status":"success","message":"Login successful. Please proceed with 2FA.","user_id":"mock_user_123","session_token_mock":"mock_session_abcxyz"}`
    *   **Verify 2FA (mock - code: "123456"):**
        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"two_fa_code": "123456"}' http://localhost:5000/api/v1/auth/verify-2fa
        ```
        Expected mock success: `{"status":"success","message":"2FA verification successful. Access granted (mock).","access_token_mock":"mock_jwt_token_for_full_access"}`
    *   **Logout (mock):**
        ```bash
        curl -X POST http://localhost:5000/api/v1/auth/logout
        ```
        Expected mock success: `{"status":"success","message":"Successfully logged out (mock)."}`

## 4. Current Limitations & Notes

*   **Go Tools in Sandbox:** The development environment where these instructions are generated might not have the Go-based tools (Subfinder, Amass, etc.) installed. The script and API are designed to handle this by logging errors and continuing. For full functionality on your local machine, ensure these tools are installed and in your PATH.
*   **API Storage:** Scan job status and result information are now stored in a local SQLite database file (`instance/scan_jobs.db` relative to the project root `cyberhunter3d/`). This makes scan information persistent across API server restarts. The `instance/` folder is created automatically by Flask if it doesn't exist.
*   **Asynchronous Task Handling:** The API uses Python's `concurrent.futures.ThreadPoolExecutor` for asynchronous scan execution. For a more robust and scalable production setup, a dedicated task queue system like Celery (with Redis or RabbitMQ as a broker) is recommended.
*   **Output File Paths:** The API currently returns absolute paths to output files (e.g., in `instance/scan_outputs/target_domain/`). For a distributed setup or different client access, these paths might need to be relative or served via dedicated download endpoints. The scan output files are now also stored within the `instance/` directory.

## 5. Further Development

This project is a foundational step towards the larger vision of CyberHunter 3D. Future work will involve:
*   Integrating more reconnaissance and vulnerability scanning tools.
*   Implementing the other modules outlined in the project brief (XSS, SQLi, etc.).
*   Developing the AI-driven analysis and 3D visualization components.
*   Adding robust database integration, user authentication, and more.

Refer to `AGENTS.md` for more detailed notes on project structure, tool dependencies, and specific module instructions relevant to AI agent development.
---

This `INSTRUCTIONS.md` file should provide a good starting point for anyone looking to set up and run the tool locally.
```
