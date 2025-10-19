from flask import render_template, request
from web.app import app, get_scan_results, get_camera_results, scan_progress, scan_status

@app.route('/')
def main_page():
    return render_template('main.html', 
                          scan_progress=scan_progress, 
                          scan_status=scan_status,
                          scan_results=get_scan_results(),
                          camera_results=get_camera_results())