# CyberHunter 3D - Subdomain Enumeration API

# This file outlines the design for the API endpoints related to
# subdomain enumeration.
# Actual implementation (e.g., using Flask, FastAPI) will follow separately.

# --- API Endpoint Definitions ---

# 1. Start Subdomain Enumeration Scan
#   - Method: POST
#   - Endpoint: /api/v1/scan/subdomain
#   - Description: Initiates a new subdomain enumeration scan for a given target.
#   - Request Body (JSON):
#     {
#       "target": "example.com",  // Required: The domain to scan
#       "scan_profile": "default", // Optional: "default", "fast", "deep" - influences tools/configs used
#       "force_rerun": false,     // Optional: If true, re-runs even if recent results exist
#       "callback_url": null      // Optional: URL to POST results to when scan is complete
#     }
#   - Success Response (202 Accepted):
#     {
#       "scan_id": "uuid-generated-scan-id-12345",
#       "message": "Subdomain enumeration scan initiated.",
#       "status_endpoint": "/api/v1/scan/subdomain/status/uuid-generated-scan-id-12345",
#       "results_endpoint": "/api/v1/scan/subdomain/results/uuid-generated-scan-id-12345"
#     }
#   - Error Responses:
#     - 400 Bad Request: Invalid input (e.g., missing target, invalid domain format)
#       { "error": "Invalid target domain provided." }
#     - 500 Internal Server Error: If the scan initiation fails unexpectedly.
#       { "error": "Failed to initiate scan due to an internal error." }

# 2. Get Scan Status
#   - Method: GET
#   - Endpoint: /api/v1/scan/subdomain/status/{scan_id}
#   - Description: Retrieves the current status of a specific subdomain enumeration scan.
#   - Path Parameters:
#     - scan_id: The unique identifier of the scan.
#   - Success Response (200 OK):
#     {
#       "scan_id": "uuid-generated-scan-id-12345",
#       "target": "example.com",
#       "status": "running", // Possible values: "pending", "queued", "running", "completed", "failed", "cancelled"
#       "progress": 65,      // Optional: Percentage completion (0-100)
#       "start_time": "2023-10-27T10:00:00Z",
#       "last_update_time": "2023-10-27T10:30:00Z",
#       "estimated_remaining_time_seconds": 1200 // Optional
#     }
#   - Error Responses:
#     - 404 Not Found: If the scan_id is not found.
#       { "error": "Scan ID not found." }

# 3. Get Scan Results
#   - Method: GET
#   - Endpoint: /api/v1/scan/subdomain/results/{scan_id}
#   - Description: Retrieves the results of a completed subdomain enumeration scan.
#                  This endpoint should only return results if the scan status is "completed".
#                  It could also support streaming results or pagination for very large result sets.
#   - Path Parameters:
#     - scan_id: The unique identifier of the scan.
#   - Success Response (200 OK - if scan completed):
#     {
#       "scan_id": "uuid-generated-scan-id-12345",
#       "target": "example.com",
#       "status": "completed",
#       "start_time": "2023-10-27T10:00:00Z",
#       "completion_time": "2023-10-27T11:00:00Z",
#       "summary": {
#         "total_subdomains_found": 150,
#         "alive_subdomains": 75,
#         "vulnerable_to_takeover": 2
#       },
#       "outputs": { // Corresponds to section 5.1 of the project brief
#         "all_subdomains_file": "/path/to/scan_results/example.com/Subdomain.txt", // Or direct content / download link
#         "alive_subdomains_file": "/path/to/scan_results/example.com/subdomains_alive.txt",
#         "dead_subdomains_file": "/path/to/scan_results/example.com/subdomains_dead.txt",
#         "takeover_vulnerable_file": "/path/to/scan_results/example.com/subdomain_takeover.txt",
#         "wildcard_domains_file": "/path/to/scan_results/example.com/wildcard_domains.txt",
#         "subdomain_technologies_json": "/path/to/scan_results/example.com/subdomain_technologies.json"
#       },
#       "data": { // Alternatively, embed some data directly for quick access
#          "alive_subdomains_sample": ["www.example.com", "api.example.com", "..."], // Sample or paginated list
#       }
#     }
#   - Success Response (202 Accepted - if scan still running/pending):
#     {
#       "scan_id": "uuid-generated-scan-id-12345",
#       "status": "running", // or "pending", "queued"
#       "message": "Scan is still in progress. Check status endpoint for updates."
#     }
#   - Error Responses:
#     - 404 Not Found: If the scan_id is not found.
#       { "error": "Scan ID not found." }
#     - 500 Internal Server Error: If results retrieval fails.

# 4. Cancel Scan (Optional but good to have)
#   - Method: POST
#   - Endpoint: /api/v1/scan/subdomain/cancel/{scan_id}
#   - Description: Attempts to cancel an ongoing subdomain enumeration scan.
#   - Path Parameters:
#     - scan_id: The unique identifier of the scan.
#   - Success Response (200 OK):
#     {
#       "scan_id": "uuid-generated-scan-id-12345",
#       "message": "Scan cancellation request accepted. Status will be updated shortly."
#     }
#   - Error Responses:
#     - 404 Not Found: If the scan_id is not found.
#     - 409 Conflict: If the scan is already completed or cannot be cancelled.

# --- Data Models (Conceptual) ---

# SubdomainResult:
#   - subdomain: string
#   - ip_address: string (optional)
#   - http_status: integer (optional)
#   - technologies: list[string] (optional)
#   - is_alive: boolean
#   - potential_takeover: boolean

# ScanJob:
#   - scan_id: string (UUID)
#   - target_domain: string
#   - status: string (pending, queued, running, completed, failed, cancelled)
#   - created_at: datetime
#   - started_at: datetime (optional)
#   - completed_at: datetime (optional)
#   - results_path: string (path to stored result files)
#   - configuration: dict (scan profile, etc.)

# --- Notes on API Design ---
# - Authentication/Authorization: Not detailed here, but would be crucial (e.g., API keys, OAuth2).
# - Versioning: Using /v1/ in the path for versioning.
# - Asynchronous Operations: Scanning is a long-running task, so API calls to start scans are asynchronous.
#   Client polls status endpoint or uses callbacks.
# - Rate Limiting: Important for public-facing APIs.
# - Logging: Comprehensive logging of API requests and responses.
# - Output Files: The `outputs` section in results could provide direct download links or paths accessible
#   to the system. For a fully integrated platform, providing file content directly (paginated) might be better
#   than just file paths. The current design leans towards paths, which the `ch_modules.subdomain_enumeration.main.py`
#   also reflects in its return dict.

# This design provides a basic structure. Further details would be fleshed out
# during actual implementation with a web framework.
# The design considers the output requirements mentioned in AGENTS.md and section 5.1 of the project brief.
print("[INFO] API design for subdomain enumeration module created in cyberhunter3d/ch_api/api_subdomain.py")
