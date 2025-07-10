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
    -   `Subdomain.txt`: Consolidated unique subdomains.
    -   `subdomain_dns_resolutions.json`: Subdomain to IP mappings.
    -   `subdomains_alive.txt`: Live subdomains (ports 80, 443, 8000, 8080).
    -   `subdomains_dead.txt`: Non-responsive subdomains.
    -   `subdomain_takeover_vulnerable.txt`: Potential subdomain takeovers (from Subzy).
    -   `Way_kat.txt`: URLs from Waybackurls, Katana, GAU, Hakrawler (filtered).
    -   `interesting_params.txt`: Unique query parameters from `Way_kat.txt`.
    -   `alive_domain.txt`: Live URLs (200-399 status).
    -   `dead_domain.txt`: Dead/Error URLs (400-599 status or failed requests).
    -   `sensitive_data_findings.json`: Placeholder for structured sensitive data exposure findings. (Replaces older `sensitive_exposure.txt`).
    -   `xss_vulnerabilities.json`: Placeholder XSS scan results.
    -   `sqli_vulnerabilities.json`: SQLMap SQLi scan results (heuristic parsing).
    -   `lfi_vulnerabilities.json`: Placeholder LFI scan results.
    -   `cors_vulnerabilities.json`: Placeholder CORS scan results.
    -   `ssrf_vulnerabilities.json`: Placeholder SSRF scan results.
    -   `xxe_vulnerabilities.json`: Placeholder XXE scan results.
    -   `rce_vulnerabilities.json`: Placeholder RCE scan results.
    -   Placeholders: `wildcard_domains.txt`, `subdomain_technologies.json`.

-   **URL Discovery Enhancement:** Uses GAU & Hakrawler in addition to Waybackurls & Katana.
-   **Parameter Extraction:** Extracts unique query params from URLs into `interesting_params.txt`.
-   **Subdomain Takeover Check:** Uses `subzy`.
-   **XSS Hunter Module (Placeholder - `ch_modules/xss_hunter/`):**
    -   Takes `urls_alive_file`. Intended tools: Gxss, kxss, Dalfox, XSStrike. Outputs `xss_vulnerabilities.json`.
-   **SQLi Scanner Module (`ch_modules/sqli_scanner/`):**
    -   Uses SQLMap on URLs with parameters. Flags: `--batch --level=1 --risk=1 --technique=EBU --dbms --banner --is-dba`.
    -   Heuristic stdout parsing. Output: `sqli_vulnerabilities.json` with path to SQLMap session dir.
    -   Planned: Better parsing, more techniques, Ghauri.
-   **LFI Hunter Module (Enhanced Placeholder - `ch_modules/lfi_hunter/`):**
    -   Structured with sub-modules (`wrapper_fuzzer.py`, `traversal_generator.py`, etc.).
    -   Conceptually covers: Path traversal, wrappers, null byte, log poisoning, RCE chains. Planned tools: ffuf. Output: `lfi_vulnerabilities.json`.
-   **CORS Hunter Module (Enhanced Placeholder - `ch_modules/cors_hunter/`):**
    -   Structured with sub-modules (`origin_tester.py`, `wildcard_checker.py`, etc.).
    -   Conceptually covers: Origin reflection, wildcard, credentials, null origin, subdomain abuse. Planned: Nuclei templates. Output: `cors_vulnerabilities.json`.
-   **Sensitive Data Exposure Hunter Module (Enhanced Placeholder - `ch_modules/sensitive_data_hunter/`):**
    -   Structured with sub-modules (`git_exposure_scanner.py`, `api_key_detector.py`, etc.).
    -   Conceptually covers: .git exposure, API keys, backups, configs, entropy, AI classification. Output: `sensitive_data_findings.json`.
-   **SSRF Hunter Module (Enhanced Placeholder - `ch_modules/ssrf_hunter/`):**
    -   Structured with sub-modules (`dnslog_checker.py`, `payload_generator.py`, etc.).
    -   Conceptually covers: Internal IP fuzzing, DNS callbacks, protocol smuggling, metadata abuse, RCE chains. Output: `ssrf_vulnerabilities.json`.
-   **XXE Hunter Module (Enhanced Placeholder - `ch_modules/xxe_hunter/`):**
    -   Structured with sub-modules (`payload_generator.py`, `oob_logger.py`, etc.).
    -   Conceptually covers: Basic entity injection, OOB, file disclosure, blind XXE, param/header injection, SOAP XXE. Planned: Nuclei, WS-Attacker. Output: `xxe_vulnerabilities.json`.
-   **RCE Hunter Module (Enhanced Placeholder - `ch_modules/rce_hunter/`):**
    -   **Structure:** Contains `main.py` orchestrator and sub-modules: `payload_generator.py`, `callback_checker.py`, `eval_fuzzer.py`, `reverse_shell_poc.py` (conceptual), and `report_builder.py`.
    -   All sub-modules currently contain placeholder functions that log their conceptual checks.
    -   `main.py` calls these placeholder functions.
    -   `report_builder.py` compiles the final `rce_vulnerabilities.json` with notes reflecting the detailed conceptual checks.
    -   **Conceptually Considers Techniques:** Command injection payloads (chaining ;, &&, |), Out-of-band detection via DNS, Language-specific payloads (PHP, Bash, Python), Eval/exec fuzzing (?cmd=, ?code=), and Reverse shell PoC generation ideas.

-   **Tool Dependencies for Reconnaissance Workflow:**
    -   **Python Libraries (in `requirements.txt`):**
        -   `httpx`: For HTTP/S liveness checks.
        -   `sublist3r`: For subdomain enumeration.
        -   `Flask`: Python library for the API server.
    -   **Go-based Tools (Manual Install - Must be in PATH):**
        -   `subfinder`, `amass`, `assetfinder`, `waybackurls`, `katana`, `subzy`, `gau`, `hakrawler`. (See `INSTRUCTIONS.md` for install commands).
    -   **SQLMap (Manual Install - Must be in PATH or configured):**
        -   (See `INSTRUCTIONS.md` for install commands).

-   **API Design & Endpoints:**
    -   Flask-based, uses `concurrent.futures.ThreadPoolExecutor` for async tasks.
    -   Scan jobs persisted in SQLite (`instance/scan_jobs.db`).
    -   Main app: `ch_api/main_api.py`. Scan routes: `ch_api/routes/scan_routes.py`. Auth (mock): `ch_api/routes/auth_routes.py`. Web UI: `ch_web/routes.py`.
    -   **Scan & Target Submission API Endpoints:**
        -   `POST /api/v1/scan/recon` (single target)
        -   `POST /api/v1/targets/submit` (multiple targets)
        -   `GET /api/v1/scan/recon/status/<scan_id>`
        -   `GET /api/v1/scan/recon/results/<scan_id>`
    -   **Auth API Endpoints (Placeholders - base: `/api/v1/auth`):**
        -   `POST /login`, `POST /verify-2fa`, `POST /logout`
    -   `/health` check endpoint.
    -   Web UI: `/login` (mock), `/targets` (input form).

## Future Vision (3D Interface & AI)
While the initial focus might be on backend logic and tool integration, keep the ultimate vision of a 3D holographic interface and AI-driven analysis in mind. Design components in a way that they can eventually feed data into such a system. For instance, ensure structured data output that can be easily parsed and visualized.

Thank you for your contribution to CyberHunter 3D!
```
