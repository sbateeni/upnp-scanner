from flask import Blueprint, render_template, request

# Create a blueprint for routers routes
bp = Blueprint('routers', __name__)

@bp.route('/routers')
def routers_page():
    return render_template('routers.html')