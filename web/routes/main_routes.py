from flask import Blueprint, render_template, request

# Create a blueprint for main routes
bp = Blueprint('main', __name__)

@bp.route('/')
def main_page():
    # Import app functions when needed to avoid circular imports
    import web.app
    return render_template('main.html', 
                          scan_progress=web.app.scan_progress, 
                          scan_status=web.app.scan_status,
                          scan_results=web.app.get_scan_results(),
                          camera_results=web.app.get_camera_results())