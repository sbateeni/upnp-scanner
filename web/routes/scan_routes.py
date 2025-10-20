from flask import Blueprint, render_template, request

# Create a blueprint for scan routes
bp = Blueprint('scan', __name__)

@bp.route('/scan')
def scan_page():
    return render_template('scan.html')