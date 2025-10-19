from flask import render_template, request
from web.app import app

@app.route('/scan')
def scan_page():
    return render_template('scan.html')