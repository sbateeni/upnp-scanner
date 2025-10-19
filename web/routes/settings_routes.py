from flask import render_template, request
from web.app import app

@app.route('/settings')
def settings_page():
    return render_template('settings.html')