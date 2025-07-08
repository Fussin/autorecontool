# CyberHunter 3D - API Package

# This __init__.py makes 'ch_api' a package.
# It can also be used for centralizing Blueprint registrations or app factory pattern.

# from .main_api import create_app # If you want to expose create_app directly

__version__ = "0.0.2" # Version bump for API addition
__all__ = [] # Define what 'from ch_api import *' imports, if anything

# If using Blueprints and want to collect them here:
# from .routes.scan_routes import scan_bp
# all_blueprints = [scan_bp]
