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
-   **Subdomain Enumeration Output:** Ensure the subdomain enumeration module produces output files as specified: `Subdomain.txt`, `subdomains_alive.txt`, etc. (Refer to section 5.1 of the main project brief).
-   **API Design:** When designing APIs, aim for RESTful principles. Clearly define request and response payloads.

## Future Vision (3D Interface & AI)
While the initial focus might be on backend logic and tool integration, keep the ultimate vision of a 3D holographic interface and AI-driven analysis in mind. Design components in a way that they can eventually feed data into such a system. For instance, ensure structured data output that can be easily parsed and visualized.

Thank you for your contribution to CyberHunter 3D!
