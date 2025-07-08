# CyberHunter 3D - Database Handler (SQLite)

import sqlite3
import os
import json # For serializing results
from datetime import datetime, timezone

# Define the path for the SQLite database file.
# It's good practice to place instance-specific files outside the main app package,
# e.g., in an 'instance' folder at the project root.
# For simplicity here, we'll place it inside ch_api for now, but this should be configurable.
DATABASE_NAME = "scan_jobs.db"
# DATABASE_PATH will be set by the main_api using app.instance_path or similar for better practice.
# For now, let's define a default relative to this file for direct testing,
# but the API will override this.
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATABASE_NAME)

def get_db_connection(db_path=None):
    """Establishes a connection to the SQLite database."""
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row # Access columns by name
    return conn

def init_db(db_path=None):
    """Initializes the database and creates the scan_jobs table if it doesn't exist."""
    if db_path is None:
        db_path = DEFAULT_DB_PATH

    # Ensure the directory for the database exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
        print(f"[DB] Created database directory: {db_dir}")

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            scan_id TEXT PRIMARY KEY,
            target_domain TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            results_json TEXT,
            error_message TEXT
        )
    """)
    conn.commit()
    conn.close()
    print(f"[DB] Database initialized at {db_path}")

# --- CRUD Operations for scan_jobs ---

def add_scan_job(scan_id: str, target_domain: str, db_path=None):
    """Adds a new scan job to the database with 'queued' status."""
    conn = get_db_connection(db_path)
    created_at_iso = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO scan_jobs (scan_id, target_domain, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, target_domain, 'queued', created_at_iso, created_at_iso)
        )
        conn.commit()
        print(f"[DB] Added scan job {scan_id} for {target_domain}")
    except sqlite3.IntegrityError:
        print(f"[DB ERROR] Scan ID {scan_id} already exists.")
        # Handle appropriately, maybe raise an error or return False
    finally:
        conn.close()

def update_scan_job_status(scan_id: str, new_status: str, db_path=None):
    """Updates the status and updated_at timestamp of a scan job."""
    conn = get_db_connection(db_path)
    updated_at_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE scan_jobs SET status = ?, updated_at = ? WHERE scan_id = ?",
        (new_status, updated_at_iso, scan_id)
    )
    conn.commit()
    conn.close()
    print(f"[DB] Updated status for scan {scan_id} to {new_status}")

def update_scan_job_completed(scan_id: str, results: dict, db_path=None):
    """Updates a scan job to 'completed' and stores its results."""
    conn = get_db_connection(db_path)
    updated_at_iso = datetime.now(timezone.utc).isoformat()
    results_json_str = json.dumps(results)
    conn.execute(
        "UPDATE scan_jobs SET status = ?, updated_at = ?, results_json = ? WHERE scan_id = ?",
        ('completed', updated_at_iso, results_json_str, scan_id)
    )
    conn.commit()
    conn.close()
    print(f"[DB] Marked scan {scan_id} as completed with results.")

def update_scan_job_failed(scan_id: str, error_msg: str, db_path=None):
    """Updates a scan job to 'failed' and stores the error message."""
    conn = get_db_connection(db_path)
    updated_at_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE scan_jobs SET status = ?, updated_at = ?, error_message = ? WHERE scan_id = ?",
        ('failed', updated_at_iso, error_msg, scan_id)
    )
    conn.commit()
    conn.close()
    print(f"[DB] Marked scan {scan_id} as failed. Error: {error_msg[:100]}...")


def get_scan_job(scan_id: str, db_path=None) -> sqlite3.Row | None:
    """Retrieves a scan job by its ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_jobs WHERE scan_id = ?", (scan_id,))
    job = cursor.fetchone()
    conn.close()
    return job

if __name__ == '__main__':
    # Example of initializing and using the DB functions directly
    # This will create 'scan_jobs.db' in the same directory as db_handler.py
    print(f"Running DB Handler directly for testing with DB at: {DEFAULT_DB_PATH}")
    init_db(DEFAULT_DB_PATH)

    test_scan_id = "test-scan-123"
    test_target = "example-direct.com"

    print(f"\nAttempting to add job: {test_scan_id}")
    add_scan_job(test_scan_id, test_target, db_path=DEFAULT_DB_PATH)

    job = get_scan_job(test_scan_id, db_path=DEFAULT_DB_PATH)
    if job:
        print(f"\nRetrieved job: ID={job['scan_id']}, Target={job['target_domain']}, Status={job['status']}, Created={job['created_at']}")
    else:
        print(f"\nJob {test_scan_id} not found after adding.")

    print(f"\nUpdating status for {test_scan_id} to 'running'")
    update_scan_job_status(test_scan_id, "running", db_path=DEFAULT_DB_PATH)
    job = get_scan_job(test_scan_id, db_path=DEFAULT_DB_PATH)
    if job:
        print(f"Updated job: Status={job['status']}, Updated={job['updated_at']}")

    print(f"\nUpdating job {test_scan_id} to 'completed'")
    mock_results = {"file1": "/path/to/results.txt", "notes": "Scan successful"}
    update_scan_job_completed(test_scan_id, mock_results, db_path=DEFAULT_DB_PATH)
    job = get_scan_job(test_scan_id, db_path=DEFAULT_DB_PATH)
    if job:
        print(f"Completed job: Status={job['status']}, Results JSON: {job['results_json']}")
        retrieved_results = json.loads(job['results_json'])
        print(f"Deserialized results: {retrieved_results}")

    test_fail_id = "test-fail-456"
    print(f"\nAdding job {test_fail_id} and marking as failed")
    add_scan_job(test_fail_id, "fail-example.com", db_path=DEFAULT_DB_PATH)
    update_scan_job_failed(test_fail_id, "Something went very wrong during the scan.", db_path=DEFAULT_DB_PATH)
    job = get_scan_job(test_fail_id, db_path=DEFAULT_DB_PATH)
    if job:
         print(f"Failed job: Status={job['status']}, Error: {job['error_message']}")

    print("\nDB direct test finished.")
    # You might want to manually delete scan_jobs.db after testing if it's in this directory.
