# CyberHunter 3D - Scan API Routes

from flask import Blueprint, request, jsonify, current_app
import uuid
from concurrent.futures import ThreadPoolExecutor
import os # For path joining

# Assuming your recon workflow function is here:
from ch_modules.subdomain_enumeration.main import run_recon_workflow


import json # For deserializing results from DB
from .. import db_handler # Import the db_handler

# Using a Blueprint for scan routes
scan_bp = Blueprint('scan_api', __name__)

# ThreadPoolExecutor for running scans asynchronously
# This can remain as is, or be initialized in create_app and accessed via current_app if preferred.
# For now, keeping it module-level for simplicity.
executor = ThreadPoolExecutor(max_workers=2)


def run_scan_wrapper(scan_id: str, target_domain: str, output_base_dir: str, db_path: str):
    """
    Wrapper function to run the recon workflow and update scan status in the database.
    This function is what the ThreadPoolExecutor will execute.
    """
    print(f"[API Worker] Starting scan {scan_id} for target: {target_domain}. DB: {db_path}")
    try:
        db_handler.update_scan_job_status(scan_id, 'running', db_path=db_path)

        results = run_recon_workflow(target_domain, output_path=output_base_dir)

        db_handler.update_scan_job_completed(scan_id, results, db_path=db_path)
        print(f"[API Worker] Scan {scan_id} completed successfully.")
    except Exception as e:
        error_message = f"Error during scan execution for {scan_id}: {str(e)}"
        print(f"[API Worker] {error_message}")
        try:
            db_handler.update_scan_job_failed(scan_id, error_message, db_path=db_path)
        except Exception as db_e:
            print(f"[API Worker ERROR] Failed to even update DB for failed scan {scan_id}: {db_e}")


@scan_bp.route('/recon', methods=['POST'])
def start_recon_scan():
    """
    Initiates a new comprehensive reconnaissance scan.
    """
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "Missing 'target' in request body"}), 400

    target_domain = data['target']
    if not isinstance(target_domain, str) or '.' not in target_domain:
         return jsonify({"error": "Invalid target domain format"}), 400

    scan_id = str(uuid.uuid4())
    db_path = current_app.config['DATABASE'] # Get DB path from app config

    try:
        db_handler.add_scan_job(scan_id, target_domain, db_path=db_path)
    except Exception as e: # Handle potential DB errors during initial add
        print(f"[API ERROR] Failed to add scan job {scan_id} to DB: {e}")
        return jsonify({"error": "Failed to initiate scan due to database issue."}), 500

    output_dir_for_scans = current_app.config["SCAN_OUTPUT_BASE_DIR"]
    # Pass the db_path to the worker
    executor.submit(run_scan_wrapper, scan_id, target_domain, output_dir_for_scans, db_path)

    print(f"[API] Queued scan {scan_id} for target: {target_domain}")

    return jsonify({
        "message": "Reconnaissance scan initiated.",
        "scan_id": scan_id,
        "status_endpoint": f"/api/v1/scan/recon/status/{scan_id}", # Assuming /api/v1/scan is the blueprint prefix
        "results_endpoint": f"/api/v1/scan/recon/results/{scan_id}"
    }), 202


@scan_bp.route('/recon/status/<scan_id>', methods=['GET'])
def get_recon_scan_status(scan_id):
    """
    Retrieves the status of a specific reconnaissance scan from the database.
    """
    db_path = current_app.config['DATABASE']
    job_row = db_handler.get_scan_job(scan_id, db_path=db_path)

    if not job_row:
        return jsonify({"error": "Scan ID not found"}), 404

    return jsonify({
        "scan_id": job_row['scan_id'],
        "target": job_row['target_domain'],
        "status": job_row['status'],
        "created_at": job_row['created_at'],
        "updated_at": job_row['updated_at'],
        "error": job_row['error_message'] # Will be None if no error
    }), 200


@scan_bp.route('/recon/results/<scan_id>', methods=['GET'])
def get_recon_scan_results(scan_id):
    """
    Retrieves the results of a completed reconnaissance scan from the database.
    """
    db_path = current_app.config['DATABASE']
    job_row = db_handler.get_scan_job(scan_id, db_path=db_path)

    if not job_row:
        return jsonify({"error": "Scan ID not found"}), 404

    if job_row['status'] == 'completed':
        try:
            results_data = json.loads(job_row['results_json']) if job_row['results_json'] else {}
            return jsonify(results_data), 200
        except json.JSONDecodeError:
            return jsonify({"error": "Failed to parse results data from database."}), 500
    elif job_row['status'] == 'failed':
        return jsonify({
            "scan_id": job_row['scan_id'],
            "target": job_row['target_domain'],
            "status": "failed",
            "error": job_row['error_message'] or "An unknown error occurred."
        }), 200 # Return 200 but with status failed in body, or 500 if preferred for server-side failure
    else: # Queued or running
        return jsonify({
            "scan_id": job_row['scan_id'],
            "target": job_row['target_domain'],
            "status": job_row['status'],
            "message": "Scan is not yet completed. Check status endpoint."
        }), 202
