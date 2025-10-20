from flask import Blueprint, render_template, request

# Create a blueprint for settings routes
bp = Blueprint('settings', __name__)

@bp.route('/settings')
def settings_page():
    return render_template('settings.html')