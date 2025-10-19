from flask import render_template, request
from web.app import app

@app.route('/surrounding')
def surrounding_page():
    return render_template('surrounding.html')