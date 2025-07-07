# CyberHunter 3D - Scan API Routes

from flask import Blueprint, request, jsonify, current_app
import uuid
from concurrent.futures import ThreadPoolExecutor
import os # For path joining

# Assuming your recon workflow function is here:
from ch_modules.subdomain_enumeration.main import run_recon_workflow


# Using a Blueprint for scan routes, prefixed with /api/v1 (prefix applied in main_api.py)
# The url_prefix is actually applied when registering the blueprint in main_api.py,
# so it's removed here to avoid double prefixing if main_api.py also sets it.
# scan_bp = Blueprint('scan_api', __name__, url_prefix='/api/v1/scan')
scan_bp = Blueprint('scan_api', __name__)

# In-memory store for scan jobs and their results/status
# In a production app, this would be a database (e.g., Redis, PostgreSQL)
scan_jobs = {}

# ThreadPoolExecutor for running scans asynchronously
# max_workers can be tuned. Let's start with a small number.
# This should ideally be managed by the app context if it needs to be shared across requests/blueprints
# For simplicity here, defined globally within this module.
# A better approach might be to initialize it in create_app and pass it around or use app.extensions
executor = ThreadPoolExecutor(max_workers=2) # Max 2 concurrent scans for now


def run_scan_wrapper(scan_id: str, target_domain: str, output_base_dir: str):
    """
    Wrapper function to run the recon workflow and update scan status.
    This function is what the ThreadPoolExecutor will execute.
    """
    print(f"[API Worker] Starting scan {scan_id} for target: {target_domain}")
    scan_jobs[scan_id]['status'] = 'running'

    # Ensure the specific output directory for this scan exists
    # output_path_for_scan = os.path.join(output_base_dir, scan_id) # Store results under scan_id
    # The run_recon_workflow already creates output_base_dir/target_domain, which is fine for now.
    # For multi-tenancy or more complex scenarios, scan_id in path would be better.
    # Current output path for run_recon_workflow is output_base_dir (which is app.config["SCAN_OUTPUT_BASE_DIR"])
    # and it internally creates a subdirectory for target_domain.

    try:
        # The run_recon_workflow expects output_path to be the parent of the target_domain directory
        results = run_recon_workflow(target_domain, output_path=output_base_dir)
        scan_jobs[scan_id]['status'] = 'completed'
        scan_jobs[scan_id]['results'] = results # Store the dictionary of file paths
        print(f"[API Worker] Scan {scan_id} completed successfully.")
    except Exception as e:
        scan_jobs[scan_id]['status'] = 'failed'
        scan_jobs[scan_id]['error'] = str(e)
        print(f"[API Worker] Scan {scan_id} failed: {e}")


@scan_bp.route('/recon', methods=['POST'])
def start_recon_scan():
    """
    Initiates a new comprehensive reconnaissance scan.
    """
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "Missing 'target' in request body"}), 400

    target_domain = data['target']
    # Basic validation for target_domain can be added here
    if not isinstance(target_domain, str) or '.' not in target_domain:
         return jsonify({"error": "Invalid target domain format"}), 400

    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        'scan_id': scan_id,
        'target': target_domain,
        'status': 'queued',
        'results': None,
        'error': None
    }

    # Submit the scan to the executor
    # current_app.config is available here because of Flask's app context
    output_dir_for_scans = current_app.config["SCAN_OUTPUT_BASE_DIR"]
    executor.submit(run_scan_wrapper, scan_id, target_domain, output_dir_for_scans)

    print(f"[API] Queued scan {scan_id} for target: {target_domain}")

    return jsonify({
        "message": "Reconnaissance scan initiated.",
        "scan_id": scan_id,
        "status_endpoint": f"/api/v1/scan/recon/status/{scan_id}",
        "results_endpoint": f"/api/v1/scan/recon/results/{scan_id}"
    }), 202


@scan_bp.route('/recon/status/<scan_id>', methods=['GET'])
def get_recon_scan_status(scan_id):
    """
    Retrieves the status of a specific reconnaissance scan.
    """
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "Scan ID not found"}), 404

    return jsonify({
        "scan_id": job['scan_id'],
        "target": job['target'],
        "status": job['status'],
        "error": job.get('error') # Will be None if no error
    }), 200


@scan_bp.route('/recon/results/<scan_id>', methods=['GET'])
def get_recon_scan_results(scan_id):
    """
    Retrieves the results of a completed reconnaissance scan.
    """
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "Scan ID not found"}), 404

    if job['status'] == 'completed':
        # The 'results' key in job should hold the dictionary from run_recon_workflow
        return jsonify(job['results']), 200
    elif job['status'] == 'failed':
        return jsonify({
            "scan_id": job['scan_id'],
            "target": job['target'],
            "status": "failed",
            "error": job.get('error', "An unknown error occurred.")
        }), 500 # Internal server error might be more appropriate if it's a system failure
    else: # Queued or running
        return jsonify({
            "scan_id": job['scan_id'],
            "target": job['target'],
            "status": job['status'],
            "message": "Scan is not yet completed. Check status endpoint."
        }), 202 # Accepted, but not ready

# Note: To make ThreadPoolExecutor shutdown gracefully, Flask's app context teardown can be used,
# or a more robust application setup with `atexit`. For this example, it's kept simple.
# executor.shutdown(wait=True) would typically be called on app exit.
