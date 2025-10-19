from flask import render_template, request
from web.app import app

@app.route('/history')
def history_page():
    return render_template('history.html')