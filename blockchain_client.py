from flask import Flask, render_template, request, jsonify, send_from_directory, abort
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import hashlib
import os
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


class Certificate:

    def __init__(
        self,
        university_public_key,
        university_private_key,
        student_public_key,
        student_name,
        degree,
        major,
        date_issued,
        certificate_hash,
    ):
        self.university_public_key = university_public_key
        self.university_private_key = university_private_key
        self.student_public_key = student_public_key
        self.student_name = student_name
        self.degree = degree
        self.major = major
        self.date_issued = date_issued
        self.certificate_hash = certificate_hash

    def to_dict(self):
        return OrderedDict({
            'university_public_key': self.university_public_key,
            'student_public_key': self.student_public_key,
            'student_name': self.student_name,
            'degree': self.degree,
            'major': self.major,
            'date_issued': self.date_issued,
            'certificate_hash': self.certificate_hash,
        })

    def sign_certificate(self):
        private_key = RSA.importKey(binascii.unhexlify(self.university_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__, template_folder="templates_client")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('view_transactions.html')

#new
@app.route('/verify/certificate', methods=['GET', 'POST'])
def verify_certificate_page():
    result = None
    error = None
    node_url = 'http://127.0.0.1:5001'

    if request.method == 'POST':
        node_url = request.form.get('node_url', node_url).strip()
        cert_file = request.files.get('certificate_file')

        if not cert_file:
            error = "Please upload a certificate file."
        else:
            try:
                file_bytes = cert_file.read()
                cert_hash = hashlib.sha256(file_bytes).hexdigest()

                resp = requests.post(node_url.rstrip('/') + '/certificate/verify',
                                     data={'certificate_hash': cert_hash})

                # Expect JSON response from node
                result = resp.json()
                result['certificate_hash'] = cert_hash
            except Exception as e:
                error = f"Error contacting node: {e}"

    return render_template('employer_verify.html',
                           result=result,
                           error=error,
                           node_url=node_url)

#New
@app.route('/student/wallet', methods=['GET', 'POST'])
def student_wallet():
    certificates = None
    error = None
    node_url = 'http://127.0.0.1:5001'
    student_public_key = ''

    if request.method == 'POST':
        node_url = request.form.get('node_url', node_url).strip()
        student_public_key = request.form.get('student_public_key', '').strip()

        if not student_public_key:
            error = "Please enter your student public key."
        else:
            try:
                resp = requests.get(
                    node_url.rstrip('/') + '/certificates/student',
                    params={'student_public_key': student_public_key}
                )
                data = resp.json()
                certificates = data.get('certificates', [])
            except Exception as e:
                error = f"Error contacting node: {e}"

    return render_template('student_wallet.html',
                           certificates=certificates,
                           error=error,
                           node_url=node_url,
                           student_public_key=student_public_key)

#New
@app.route('/certificate/file/<cert_hash>')
def download_certificate_file(cert_hash):
    for filename in os.listdir(UPLOAD_DIR):
        if filename.startswith(cert_hash):
            return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)
    abort(404)


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    university_public_key = request.form['sender_public_key']
    university_private_key = request.form['sender_private_key']
    student_public_key = request.form['recipient_public_key']
    student_name = request.form['student_name']
    degree = request.form['degree']
    major = request.form['major']
    date_issued = request.form['date_issued']

    cert_file = request.files.get('certificate_file')
    if not cert_file:
        return jsonify({'error': 'Certificate file is required'}), 400

    file_bytes = cert_file.read()
    cert_hash = hashlib.sha256(file_bytes).hexdigest()

    original_ext = os.path.splitext(cert_file.filename)[1] or '.bin'
    stored_name = cert_hash + original_ext
    stored_path = os.path.join(UPLOAD_DIR, stored_name)
    with open(stored_path, 'wb') as f:
        f.write(file_bytes)

    certificate = Certificate(
        university_public_key=university_public_key,
        university_private_key=university_private_key,
        student_public_key=student_public_key,
        student_name=student_name,
        degree=degree,
        major=major,
        date_issued=date_issued,
        certificate_hash=cert_hash,
    )

    response = {
        'certificate': certificate.to_dict(),
        'signature': certificate.sign_certificate()
    }
    return jsonify(response), 200


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format('DER'))).decode('ascii')
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='0.0.0.0', port=port, debug=True)
