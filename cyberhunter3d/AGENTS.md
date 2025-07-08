# AGENTS.md for CyberHunter 3D

This document provides guidelines for AI agents working on the CyberHunter 3D project.

## General Principles
1.  **Modularity:** Strive to create modular and decoupled components. Each scanning tool or major feature should ideally reside in its own module.
2.  **Clarity:** Write clear, commented, and maintainable code.
3.  **Testability:** Ensure code is testable. Write unit tests for new functionalities.
4.  **Configuration:** Externalize configuration (e.g., API keys, tool paths) where possible. Do not hardcode sensitive information.
5.  **Error Handling:** Implement robust error handling and logging.
6.  **Output Standardization:** Adhere to the output formats specified in the project documentation (even if it's preliminary).
7.  **Tool Integration:** When integrating external tools, ensure their installation and execution are handled gracefully. Provide clear instructions or automated scripts if manual steps are unavoidable for the user.

## Project Structure
-   `ch_core/`: Core application logic, orchestration, and shared services.
-   `ch_modules/`: Individual scanning and processing modules (e.g., `subdomain_enumeration`, `xss_hunter`).
    -   Each module should be self-contained as much as possible.
-   `ch_api/`: API definitions and implementation (e.g., Flask, FastAPI).
-   `ch_utils/`: Common utility functions and classes.
-   `tests/`: Unit and integration tests.
-   `docs/`: Project documentation.
-   `scripts/`: Helper scripts (e.g., for installation, setup).

## Specific Instructions
-   **Reconnaissance Workflow Output Files (`ch_modules/subdomain_enumeration/main.py`):**
    -   `Subdomain.txt`: Consolidated unique subdomains from Subfinder, Sublist3r, Amass, Assetfinder.
    -   `subdomain_dns_resolutions.json`: JSON file mapping each discovered subdomain to a list of its resolved IP addresses (or an error/status message).
    -   `subdomains_alive.txt`: Subdomains from `Subdomain.txt` that responded to HTTP/HTTPS checks on ports 80, 443, 8000, or 8080 (via httpx).
    -   `subdomains_dead.txt`: Subdomains from `Subdomain.txt` that did not respond on any of the probed ports.
    -   `subdomain_takeover_vulnerable.txt`: Output from `subzy` listing potential subdomain takeover vulnerabilities.
    -   `Way_kat.txt`: Consolidated unique URLs discovered by Waybackurls, Katana, GAU, and Hakrawler, run against live subdomains. Basic filtering for common non-content file extensions (CSS, JS, images) is applied before saving.
    -   `interesting_params.txt`: A list of unique query parameter names extracted from URLs in `Way_kat.txt`.
    -   `alive_domain.txt`: URLs from `Way_kat.txt` that returned HTTP 200-399 status codes.
    -   `dead_domain.txt`: URLs from `Way_kat.txt` that returned HTTP 400-599 status codes or failed requests (includes status code in output).
    -   `sensitive_exposure.txt`: URLs of potential sensitive files/paths discovered (e.g., `.env`, `.git/config`, `backup.sql`).
    -   `xss_vulnerabilities.json`: Placeholder output for XSS hunter module.
    -   `sqli_vulnerabilities.json`: Placeholder output for SQLi scanner module.
    -   Placeholders: `wildcard_domains.txt`, `subdomain_technologies.json` are also created.
-   **URL Discovery Enhancement:**
    -   Integrated `gau` and `hakrawler` into the URL discovery phase.
-   **Parameter Extraction:**
    -   A new step extracts unique query parameter names from all discovered URLs (`Way_kat.txt`) and saves them to `interesting_params.txt`.
-   **Subdomain Takeover Check (Integrated into Recon Workflow):**
    -   Uses `subzy` tool.
    -   Runs against `subdomains_alive.txt`.
    -   Outputs findings to `subdomain_takeover_vulnerable.txt`.
-   **Sensitive Data Discovery Module (`ch_modules/sensitive_data_discovery/main.py`):**
    -   Reads URLs from a specified input file (e.g., `alive_domain.txt` from the recon workflow).
    -   Checks against a list of common sensitive patterns (file extensions, paths).
    -   Uses `httpx` to verify if these potential sensitive URLs are accessible (200 OK).
    -   Outputs findings to `sensitive_exposure.txt`.
-   **XSS Hunter Module (Placeholder - `ch_modules/xss_hunter/main.py`):**
    -   Currently a placeholder, integrated into the main recon workflow.
    -   Takes `urls_alive_file` as input.
    -   Intended tools for future integration: Gxss, kxss, Dalfox, XSStrike.
    -   Outputs a placeholder `xss_vulnerabilities.json` file.
-   **SQLi Scanner Module (Placeholder - `ch_modules/sqli_scanner/main.py`):**
    -   Currently a placeholder, integrated into the main recon workflow.
    -   Takes `urls_alive_file` and `interesting_params.txt` as input.
    -   Intended tools for future integration: SQLMap, Ghauri.
    -   Outputs a placeholder `sqli_vulnerabilities.json` file.
-   **Tool Dependencies for Reconnaissance Workflow:**
    -   **Python Libraries (in `requirements.txt`):**
        -   `httpx`: For HTTP/S liveness checks and sensitive data discovery URL checks.
        -   `sublist3r`: For subdomain enumeration.
        -   `Flask`: Python library for the API server. Included in `requirements.txt`.
    -   **Go-based Tools (Manual Install - Must be in PATH):**
        -   `subfinder`: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
        -   `amass`: `go install -v github.com/owasp-amass/amass/v4/cmd/amass@master` (script uses `amass intel -d <domain> -whois -ip`)
        -   `assetfinder`: `go install -v github.com/tomnomnom/assetfinder@latest`
        -   `waybackurls`: `go install -v github.com/tomnomnom/waybackurls@latest`
        -   `katana`: `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` (script uses `katana -u <target> -silent -jc -nc -aff -kf all`)
        -   `subzy`: `go install -v github.com/LukaSikic/subzy@latest` (for subdomain takeover checks)
        -   `gau`: `go install -v github.com/lc/gau@latest` (for URL discovery)
        -   `hakrawler`: `go install -v github.com/hakluke/hakrawler@latest` (for URL discovery)
-   **API Design & Endpoints:**
    -   The API is built using Flask.
    -   Asynchronous tasks (like running the recon workflow) are currently handled using `concurrent.futures.ThreadPoolExecutor`. For production, consider migrating to a more robust task queue like Celery with Redis/RabbitMQ.
    -   Scan job statuses and result paths are now stored persistently in an **SQLite database** (`instance/scan_jobs.db`).
        -   **DB Schema (`scan_jobs` table in `ch_api/db_handler.py`):**
            -   `scan_id` (TEXT PRIMARY KEY)
            -   `target_domain` (TEXT NOT NULL)
            -   `status` (TEXT NOT NULL: queued, running, completed, failed)
            -   `created_at` (TEXT ISO 8601)
            -   `updated_at` (TEXT ISO 8601)
            -   `results_json` (TEXT: JSON string of result file paths)
            -   `error_message` (TEXT)
    -   The main API application is in `ch_api/main_api.py` (initializes DB, registers all blueprints).
    -   Scan routes are in `ch_api/routes/scan_routes.py`.
    -   Placeholder authentication API routes are in `ch_api/routes/auth_routes.py`.
    -   Web UI routes (serving login page and target input page) are in `ch_web/routes.py`. The `ch_web` directory contains `templates/login.html`, `templates/target_input.html` and `static/css/style.css`.
    -   **Scan & Target Submission API Endpoints:**
        -   Scan initiation for a single target: `POST /api/v1/scan/recon`
            -   Request Body: `{"target": "example.com"}`
            -   Response (202): `{"message": "...", "scan_id": "...", "target":"...", "status_endpoint": "...", "results_endpoint": "..."}`
        -   Target submission for multiple targets: `POST /api/v1/targets/submit` (within `scan_routes.py`)
            -   Request Body: `{"targets": ["example.com", "another.org"]}`
            -   Response (200): `{"message": "...", "submitted_targets": count, "successfully_queued_scans": count, "scan_details": [{...}], "errors": [{...}]}`
        -   `GET /recon/status/<scan_id>`: Retrieves the status of a scan.
            -   Response (200): `{"scan_id": "...", "target": "...", "status": "queued|running|completed|failed", "error": "..."}`
        -   `GET /recon/results/<scan_id>`: Retrieves the results of a completed scan (paths to files).
            -   Response (200 if completed): Dictionary of result file paths.
            -   Response (202 if in progress, 404 if not found, 500 if failed).
    -   **Auth API Endpoints (Placeholders - base: `/api/v1/auth`):**
        -   `POST /login`: Mock user login (username: "testuser", password: "password123").
            -   Request: `{"username": "...", "password": "..."}`
            -   Response (200 on mock success): `{"status": "success", "message": "Login successful. Please proceed with 2FA."}`
            -   Response (401 on mock failure): `{"status": "error", "message": "Invalid username or password (mock)."}`
        -   `POST /verify-2fa`: Mock 2FA verification (code: "123456").
            -   Request: `{"two_fa_code": "..."}`
            -   Response (200 on mock success): `{"status": "success", "message": "2FA verification successful. Access granted (mock)."}`
            -   Response (401 on mock failure): `{"status": "error", "message": "Invalid 2FA code (mock)."}`
        -   `POST /logout`: Mock user logout.
            -   Response (200): `{"status": "success", "message": "Successfully logged out (mock)."}`
    -   A basic `/health` endpoint is available at the root of the API server (`ch_api/main_api.py`).
    -   A placeholder login page (`login.html`) is served at `/` or `/login` by the `ch_web` module.

## Future Vision (3D Interface & AI)
While the initial focus might be on backend logic and tool integration, keep the ultimate vision of a 3D holographic interface and AI-driven analysis in mind. Design components in a way that they can eventually feed data into such a system. For instance, ensure structured data output that can be easily parsed and visualized.

Thank you for your contribution to CyberHunter 3D!
