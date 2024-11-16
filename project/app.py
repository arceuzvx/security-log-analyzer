from flask import Flask, request, jsonify, render_template
import os
from werkzeug.utils import secure_filename
from analyzer import SecurityLogAnalyzer  # Import your analyzer class

UPLOAD_FOLDER = 'uploads'  # Folder to store uploaded files
ALLOWED_EXTENSIONS = {'evtx', 'evt', 'log', 'txt', 'json', 'gz', 'csv', 'xml', 'zip'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Serve the HTML dashboard."""
    return render_template('dashboard.html')  # HTML file goes here

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    files = request.files.getlist('file')
    uploaded_files = []

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            uploaded_files.append(filepath)
    
    if not uploaded_files:
        return jsonify({'error': 'No valid files uploaded'}), 400

    # Analyze files
    analyzer = SecurityLogAnalyzer()
    reports = []
    for file_path in uploaded_files:
        report = analyzer.analyze_log_file(file_path)
        reports.append(report)

    return jsonify(reports)

if __name__ == '__main__':
    app.run(debug=True)
