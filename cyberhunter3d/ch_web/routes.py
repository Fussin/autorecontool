# CyberHunter 3D - Web UI Routes

from flask import Blueprint, render_template

# Blueprint for web related routes (e.g., serving HTML pages)
# The 'web_ui' Blueprint will serve files from the 'ch_web' package's templates and static folders.
# Flask automatically looks for 'templates' and 'static' in the package where the Blueprint is defined,
# or you can specify template_folder and static_folder arguments in Blueprint() if they are elsewhere.
web_bp = Blueprint('web_ui', __name__,
                   template_folder='templates',
                   static_folder='static',
                   static_url_path='/ch_web/static') # To avoid conflict with ch_api static if any

@web_bp.route('/')
@web_bp.route('/login')
def login_page():
    """Serves the main login page."""
    # Renders login.html from the 'templates' folder within 'ch_web'
    return render_template('login.html', title="CyberHunter Login")

# You could add other web pages here later, like a dashboard:
# @web_bp.route('/dashboard')
# def dashboard():
#     # Check authentication status here in a real app
#     return render_template('dashboard.html', title="Dashboard")

# This blueprint needs to be registered in the main Flask app (main_api.py or a dedicated app factory)
# For example, in main_api.py:
# from ch_web.routes import web_bp as main_web_bp # Alias to avoid name clash if main_api also has web_bp
# app.register_blueprint(main_web_bp)
