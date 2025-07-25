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
    -   `subdomains_alive.txt`: Subdomains from `Subdomain.txt` that responded to HTTP/HTTPS checks (via httpx).
    -   `subdomains_dead.txt`: Subdomains from `Subdomain.txt` that did not respond.
    -   `Way_kat.txt`: Consolidated unique URLs discovered by Waybackurls and Katana run against live subdomains.
    -   `alive_domain.txt`: URLs from `Way_kat.txt` that returned HTTP 200-399 status codes.
    -   `dead_domain.txt`: URLs from `Way_kat.txt` that returned HTTP 400-599 status codes or failed requests (includes status code in output).
    -   Placeholders: `subdomain_takeover.txt`, `wildcard_domains.txt`, `subdomain_technologies.json` are also created.
-   **Tool Dependencies for Reconnaissance Workflow:**
    -   **Python Libraries (in `requirements.txt`):**
        -   `httpx`: For HTTP/S liveness checks.
        -   `sublist3r`: For subdomain enumeration.
        -   `Flask`: Python library for the API server. Included in `requirements.txt`.
    -   **Go-based Tools (Manual Install - Must be in PATH):**
        -   `subfinder`: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
        -   `amass`: `go install -v github.com/owasp-amass/amass/v4/cmd/amass@master` (script uses `amass intel -d <domain> -whois -ip`)
        -   `assetfinder`: `go install -v github.com/tomnomnom/assetfinder@latest`
        -   `waybackurls`: `go install -v github.com/tomnomnom/waybackurls@latest`
        -   `katana`: `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` (script uses `katana -u <target> -silent -jc -nc -aff -kf all`)
-   **API Design & Endpoints:**
    -   The API is built using Flask.
    -   Asynchronous tasks (like running the recon workflow) are currently handled using `concurrent.futures.ThreadPoolExecutor`. For production, consider migrating to a more robust task queue like Celery with Redis/RabbitMQ.
    -   Scan job statuses and result paths are stored in-memory. This will need to be replaced by a persistent store (e.g., database) for a production system.
    -   The main API application is in `ch_api/main_api.py` and routes are in `ch_api/routes/scan_routes.py`.
    -   **Endpoints (base: `/api/v1/scan` - prefix applied in `main_api.py` where `scan_bp` is registered):**
        -   `POST /recon`: Initiates a new reconnaissance scan.
            -   Request Body: `{"target": "example.com"}`
            -   Response (202): `{"message": "...", "scan_id": "...", "status_endpoint": "...", "results_endpoint": "..."}`
        -   `GET /recon/status/<scan_id>`: Retrieves the status of a scan.
            -   Response (200): `{"scan_id": "...", "target": "...", "status": "queued|running|completed|failed", "error": "..."}`
        -   `GET /recon/results/<scan_id>`: Retrieves the results of a completed scan (paths to files).
            -   Response (200 if completed): Dictionary of result file paths.
            -   Response (202 if in progress, 404 if not found, 500 if failed).
    -   A basic `/health` endpoint is available at the root of the API server (`ch_api/main_api.py`).

## Future Vision (3D Interface & AI)
While the initial focus might be on backend logic and tool integration, keep the ultimate vision of a 3D holographic interface and AI-driven analysis in mind. Design components in a way that they can eventually feed data into such a system. For instance, ensure structured data output that can be easily parsed and visualized.

Thank you for your contribution to CyberHunter 3D!
