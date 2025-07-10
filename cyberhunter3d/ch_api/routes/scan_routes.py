# CyberHunter 3D - Scan API Routes

from flask import Blueprint, request, jsonify, current_app
import uuid
# Removed: from concurrent.futures import ThreadPoolExecutor
import os
import logging

from cyberhunter3d.ch_modules.subdomain_enumeration.main import run_recon_workflow

import json
from .. import db_handler

scan_bp = Blueprint('scan_api', __name__)
logger = logging.getLogger(__name__)

if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Removed module-level: executor = ThreadPoolExecutor(...)

def run_scan_wrapper(app_context, scan_id: str, target_domain: str, output_base_dir: str, db_path: str):
    """
    Wrapper function to run the recon workflow and update scan status in the database.
    This function is what the ThreadPoolExecutor will execute.
    It now takes an app_context (the actual app object) to create a context for its operations.
    """
    with app_context.app_context(): # Create an app context for the thread
        logger.info(f"[API Worker - {scan_id}] Starting scan for target: {target_domain}. DB: {db_path}")
        try:
            db_handler.update_scan_job_status(scan_id, 'running', db_path=db_path)

            results = run_recon_workflow(target_domain, scan_id, output_path=output_base_dir)

            db_handler.update_scan_job_completed(scan_id, results, db_path=db_path)
            logger.info(f"[API Worker - {scan_id}] Scan completed successfully for {target_domain}.")
        except Exception as e:
            error_message = f"Error during scan execution for {scan_id} on {target_domain}: {str(e)}"
            logger.error(f"[API Worker - {scan_id}] {error_message}", exc_info=True)
            try:
                db_handler.update_scan_job_failed(scan_id, error_message, db_path=db_path)
            except Exception as db_e:
                logger.error(f"[API Worker ERROR - {scan_id}] Failed to even update DB for failed scan: {db_e}", exc_info=True)


@scan_bp.route('/recon', methods=['POST'])
def start_recon_scan():
    data = request.get_json()
    if not data or 'target' not in data:
        logger.warning("[API /recon] Bad request: Missing 'target'")
        return jsonify({"error": "Missing 'target' in request body"}), 400

    target_domain = data['target']
    if not isinstance(target_domain, str) or '.' not in target_domain:
         logger.warning(f"[API /recon] Bad request: Invalid target format '{target_domain}'")
         return jsonify({"error": "Invalid target domain format"}), 400

    scan_id = str(uuid.uuid4())
    db_path = current_app.config['DATABASE']

    try:
        db_handler.add_scan_job(scan_id, target_domain, db_path=db_path)
    except Exception as e:
        logger.error(f"[API /recon ERROR] Failed to add scan job {scan_id} to DB for '{target_domain}': {e}", exc_info=True)
        return jsonify({"error": "Failed to initiate scan due to database issue."}), 500

    output_dir_for_scans = current_app.config["SCAN_OUTPUT_BASE_DIR"]

    # Get the actual app instance for passing to the new thread's app_context
    app_instance = current_app._get_current_object()
    current_app.scan_executor.submit(run_scan_wrapper, app_instance, scan_id, target_domain, output_dir_for_scans, db_path)

    logger.info(f"[API /recon] Queued scan {scan_id} for target: {target_domain}")

    return jsonify({
        "message": "Reconnaissance scan initiated.",
        "scan_id": scan_id,
        "target": target_domain,
        "status_endpoint": f"/api/v1/scan/status/{scan_id}",
        "results_endpoint": f"/api/v1/scan/results/{scan_id}"
    }), 202


@scan_bp.route('/targets/submit', methods=['POST'])
def submit_targets_for_scan():
    data = request.get_json()
    if not data or 'targets' not in data or not isinstance(data['targets'], list):
        logger.warning("[API /targets/submit] Bad request: Invalid payload structure.")
        return jsonify({"error": "Request body must be JSON with a 'targets' list."}), 400

    targets_to_scan = data['targets']
    if not targets_to_scan:
        logger.warning("[API /targets/submit] Bad request: Empty 'targets' list.")
        return jsonify({"error": "The 'targets' list cannot be empty."}), 400

    scan_details = []
    validation_errors = []

    db_path = current_app.config['DATABASE']
    output_dir_for_scans = current_app.config["SCAN_OUTPUT_BASE_DIR"]
    app_instance = current_app._get_current_object() # Get app instance once

    for target_item in targets_to_scan:
        target_str = str(target_item).strip()
        if not target_str:
            validation_errors.append({"target": target_item, "error": "Target cannot be empty."})
            continue

        if '.' not in target_str:
             validation_errors.append({"target": target_str, "error": "Invalid target format (must contain a period)."})
             continue

        scan_id = str(uuid.uuid4())

        try:
            db_handler.add_scan_job(scan_id, target_str, db_path=db_path)
            current_app.scan_executor.submit(run_scan_wrapper, app_instance, scan_id, target_str, output_dir_for_scans, db_path)
            scan_details.append({
                "target": target_str,
                "scan_id": scan_id,
                "status_endpoint": f"/api/v1/scan/status/{scan_id}",
                "results_endpoint": f"/api/v1/scan/results/{scan_id}"
            })
            logger.info(f"[API /targets/submit] Queued scan {scan_id} for target: {target_str}")
        except Exception as e:
            logger.error(f"[API /targets/submit ERROR] Failed to initiate scan for {target_str}: {e}", exc_info=True)
            validation_errors.append({"target": target_str, "error": f"Failed to initiate scan: {str(e)}"})

    response_message = "Targets processed."
    if not scan_details and not validation_errors:
        response_message = "No targets were provided or processed."
    elif not scan_details and validation_errors:
        response_message = "All submitted targets had validation errors or failed to queue."

    return jsonify({
        "message": response_message,
        "submitted_targets_count": len(targets_to_scan),
        "successfully_queued_scans_count": len(scan_details),
        "scan_initiation_details": scan_details,
        "errors": validation_errors
    }), 200


@scan_bp.route('/status/<scan_id>', methods=['GET'])
def get_recon_scan_status(scan_id):
    db_path = current_app.config['DATABASE']
    job_row = db_handler.get_scan_job(scan_id, db_path=db_path)

    if not job_row:
        logger.warning(f"[API /status] Scan ID not found: {scan_id}")
        return jsonify({"error": "Scan ID not found"}), 404

    logger.debug(f"[API /status] Status check for {scan_id}: {job_row['status']}")
    return jsonify({
        "scan_id": job_row['scan_id'],
        "target": job_row['target_domain'],
        "status": job_row['status'],
        "created_at": job_row['created_at'],
        "updated_at": job_row['updated_at'],
        "error": job_row['error_message']
    }), 200


@scan_bp.route('/results/<scan_id>', methods=['GET'])
def get_recon_scan_results(scan_id):
    db_path = current_app.config['DATABASE']
    job_row = db_handler.get_scan_job(scan_id, db_path=db_path)

    if not job_row:
        logger.warning(f"[API /results] Scan ID not found: {scan_id}")
        return jsonify({"error": "Scan ID not found"}), 404

    if job_row['status'] == 'completed':
        try:
            results_data = json.loads(job_row['results_json']) if job_row['results_json'] else {}
            logger.info(f"[API /results] Successfully retrieved results for completed scan {scan_id}.")
            return jsonify(results_data), 200
        except json.JSONDecodeError:
            logger.error(f"[API /results ERROR] Failed to parse results data for scan {scan_id}.", exc_info=True)
            return jsonify({"error": "Failed to parse results data from database."}), 500
    elif job_row['status'] == 'failed':
        logger.warning(f"[API /results] Accessing results for failed scan {scan_id}.")
        return jsonify({
            "scan_id": job_row['scan_id'],
            "target": job_row['target_domain'],
            "status": "failed",
            "error": job_row['error_message'] or "An unknown error occurred."
        }), 200
    else:
        logger.info(f"[API /results] Scan {scan_id} is not yet completed. Status: {job_row['status']}")
        return jsonify({
            "scan_id": job_row['scan_id'],
            "target": job_row['target_domain'],
            "status": job_row['status'],
            "message": "Scan is not yet completed. Check status endpoint."
        }), 202
