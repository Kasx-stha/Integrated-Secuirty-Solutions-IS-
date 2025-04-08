from flask import Flask, jsonify, render_template, send_from_directory
from flask_cors import CORS
import subprocess
import os
import datetime
import glob

app = Flask(__name__,
            template_folder='../frontend/templates',
            static_folder='../frontend/static')
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/start-systems', methods=['POST'])
def start_systems():
    try:
        subprocess.run(['sudo', './IS.zsh'], cwd=BASE_DIR, check=True)
        return jsonify({'success': True})
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/download-latest-report', methods=['GET'])
def download_latest_report():
    report_files = sorted(glob.glob(os.path.join(BASE_DIR, "Integrated_Security_Daily_Report_*.pdf")), reverse=True)

    if report_files:
        latest_report = os.path.basename(report_files[0])  # Get the latest file
        print(f"[DEBUG] Latest report found: {latest_report}")
        return send_from_directory(BASE_DIR, latest_report, as_attachment=True)
    else:
        print("[DEBUG] No report found.")
        return jsonify({'success': False, 'error': 'Report not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
