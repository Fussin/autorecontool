# CyberHunter 3D - Main API Application
# Initializes the Flask app and registers API routes/blueprints.

from flask import Flask, jsonify
import os

# Import routes after app is created to avoid circular imports if routes use app
# from .routes import scan_routes # Example if using Blueprints
import sys # For path manipulation

def create_app():
    """Creates and configures the Flask application."""
    # Explicitly set instance_path to be 'instance' directory at project root (one level up from ch_api)
    # app.root_path is the directory where main_api.py is (i.e., ch_api)
    instance_folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'instance'))
    app = Flask(__name__, instance_path=instance_folder_path)

    # Configuration (can be loaded from a config file or environment variables)
    app.config["DEBUG"] = True # Set to False in production
    app.config["SECRET_KEY"] = os.urandom(24) # Important for session management, etc.

    # Define instance path if it doesn't exist - good for DB files, logs etc.
    if not os.path.exists(app.instance_path):
        try:
            os.makedirs(app.instance_path)
            print(f"Instance path explicitly created at: {app.instance_path}")
        except OSError as e:
            print(f"Could not create instance path at: {app.instance_path}. Error: {e}")
            # Fallback or raise error, for now, we'll let it proceed and potentially fail at DB creation.

    # Database configuration
    app.config["DATABASE"] = os.path.join(app.instance_path, "scan_jobs.db")
    print(f"Database will be located at: {app.config['DATABASE']}")

    # Initialize Database
    from . import db_handler # Import db_handler
    db_handler.init_db(app.config["DATABASE"]) # Initialize DB with the app-configured path


    # Base output directory for scans - ensure it's an absolute path or resolved correctly
    # This assumes the API is run from the root of the 'cyberhunter3d' project or similar context
    # Let's place scan results inside the instance path as well for better organization
    app.config["SCAN_OUTPUT_BASE_DIR"] = os.path.join(app.instance_path, "scan_outputs")
    # os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scan_results_api"))
    os.makedirs(app.config["SCAN_OUTPUT_BASE_DIR"], exist_ok=True)

    print(f"Scan output base directory: {app.config['SCAN_OUTPUT_BASE_DIR']}")

    # --- Register Blueprints (if you structure your routes in separate files) ---
    from .routes.scan_routes import scan_bp
    app.register_blueprint(scan_bp, url_prefix='/api/v1/scan')

    from .routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')

    # Register Web UI blueprint (served from the root or a specific path like /ui)
    # Assuming ch_web is a sibling package to ch_api
    try:
        from ch_web.routes import web_bp as main_web_bp
        app.register_blueprint(main_web_bp) # Serves login page at '/' and '/login'
        print("Web UI blueprint registered.")
    except ImportError:
        print("[WARN] ch_web.routes (web_bp) not found or could not be imported. Web UI will not be available.")


    # --- Basic Routes (can be moved to blueprint files later) ---
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({"status": "healthy", "message": "CyberHunter API is up!"}), 200

    # Import and register scan routes - already done above
    # from .routes import scan_routes
    # app.register_blueprint(scan_routes.scan_bp) # Assuming scan_bp is defined in scan_routes

    return app

if __name__ == '__main__':
    # This allows running the Flask development server directly
    # Adjust sys.path to allow relative imports to work correctly when run directly
    current_dir_main = os.path.dirname(os.path.abspath(__file__))
    project_root_main = os.path.abspath(os.path.join(current_dir_main, '../../')) # up 2 levels: ch_api -> cyberhunter3d
    if project_root_main not in sys.path:
        sys.path.insert(0, project_root_main)

    app = create_app()
    # Note: ThreadPoolExecutor will be initialized within the route handlers that need it.
    # host='0.0.0.0' makes it accessible externally (be careful in dev)
    # port=5000 is the default Flask port
    app.run(host='0.0.0.0', port=5000)
    # For production: gunicorn --workers 4 --bind 0.0.0.0:5000 cyberhunter3d.ch_api.main_api:create_app()
    # (Assuming your project structure allows this import path)
