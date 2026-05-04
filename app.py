from flask import Flask, render_template, request, jsonify, send_file
import os
import csv
import io
from datetime import datetime
from werkzeug.utils import secure_filename
from analyzer import PCAPAnalyzer

app = Flask(__name__)

UPLOAD_FOLDER = '/tmp/pcap_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng', 'cap'}
app.secret_key = os.urandom(24)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413


@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/tool')
def tool():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Supported: .pcap, .pcapng, .cap'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(filepath)
        analyzer = PCAPAnalyzer(filepath)
        results = analyzer.run()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/export', methods=['POST'])
def export():
    data = request.get_json()
    findings = data.get('findings', [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Severity', 'Category', 'Title', 'Description', 'Count', 'Indicator'])

    for f in findings:
        writer.writerow([
            f.get('severity', ''),
            f.get('category', ''),
            f.get('title', ''),
            f.get('description', ''),
            f.get('count', ''),
            f.get('indicator', '')
        ])

    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'pcap_analysis_{timestamp}.csv'
    )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
