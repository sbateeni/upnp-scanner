from flask import render_template, request
from web.app import app, get_camera_results

@app.route('/cameras')
def cameras_page():
    return render_template('cameras.html', cameras=get_camera_results())