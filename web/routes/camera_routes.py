from flask import Blueprint, render_template, request

# Create a blueprint for camera routes
bp = Blueprint('camera', __name__)

@bp.route('/cameras')
def cameras_page():
    # Import app functions when needed to avoid circular imports
    import web.app
    return render_template('cameras.html', cameras=web.app.get_camera_results())