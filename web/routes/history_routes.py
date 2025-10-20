from flask import Blueprint, render_template, request

# Create a blueprint for history routes
bp = Blueprint('history', __name__)

@bp.route('/history')
def history_page():
    return render_template('history.html')