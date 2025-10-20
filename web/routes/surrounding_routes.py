from flask import Blueprint, render_template, request

# Create a blueprint for surrounding routes
bp = Blueprint('surrounding', __name__)

@bp.route('/surrounding')
def surrounding_page():
    return render_template('surrounding.html')