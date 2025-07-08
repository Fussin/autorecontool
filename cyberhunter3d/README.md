# CyberHunter 3D

Welcome to CyberHunter 3D - The Million-Dollar Enterprise Security Platform.

This project aims to create the most advanced bug bounty automation platform ever conceived,
featuring a revolutionary 3D holographic interface.

## Current Status
Initial project structure setup. The tool currently features a comprehensive reconnaissance script and a basic asynchronous API to manage scans.

**For detailed setup and usage instructions, please see [INSTRUCTIONS.md](INSTRUCTIONS.md).**

## Current Capabilities
- **Reconnaissance Script (`ch_modules/subdomain_enumeration/main.py`):**
    - Subdomain Enumeration (Subfinder, Sublist3r, Amass, Assetfinder)
    - Subdomain Liveness Checks (httpx)
    - URL Discovery (Waybackurls, Katana)
    - URL Filtering (httpx status codes)
    - Basic Sensitive Data Discovery (common files/paths like `.env`, `.git/config`, backups)
- **API (`ch_api/`):**
    - Flask-based server.
    - Endpoints to start reconnaissance scans (including sensitive data discovery), check status, and retrieve results.
    - Asynchronous scan execution using `ThreadPoolExecutor`.
    - Persistent storage of scan jobs and results metadata using SQLite (`instance/scan_jobs.db`).
- **Web Interface (Placeholder):**
    - Basic HTML/CSS login page (`ch_web/templates/login.html`) with mock 2FA UI flow.
    - Served by the main Flask application at `/` or `/login`.
- **Authentication API (Placeholders `ch_api/routes/auth_routes.py`):**
    - Mock endpoints for `/login`, `/verify-2fa`, `/logout`. No real authentication.


## Modules (Planned & In Progress)
- Core Engine (Foundation)
- Reconnaissance Module (Subdomain Enumeration, URL Collection, Basic Sensitive Data Discovery - *Implemented*)
- Authentication & Web UI (Basic Placeholders - *Implemented*)
- Sensitive Data Discovery (*Further enhancements planned*)
- XSS Hunting
- SQL Injection Testing
- And many more as per the project brief...

## Getting Started
Please refer to [INSTRUCTIONS.md](INSTRUCTIONS.md) for detailed setup and execution steps.

## Contributing
(To be added - general open source contribution guidelines would apply)
