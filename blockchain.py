from flask import Flask, request, jsonify, render_template
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse

MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        self.certificates = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        self.create_block(0, '00')

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def create_block(self, nonce, previous_hash):
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'certificates': self.certificates,
            'nonce': nonce,
            'previous_hash': previous_hash
        }

        self.certificates = []
        self.chain.append(block)
        return block

    def verify_certificate_signature(self, university_public_key, signature, certificate_payload):
        public_key = RSA.importKey(binascii.unhexlify(university_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(certificate_payload).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    @staticmethod
    def valid_proof(certificates, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(certificates) + str(last_hash) + str(nonce)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while not self.valid_proof(self.certificates, last_hash, nonce):
            nonce += 1
        return nonce

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)
        for node in neighbours:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def valid_chain(self, chain):
        if not chain:
            return False

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != self.hash(last_block):
                return False

            certificates = block['certificates']

            if not self.valid_proof(certificates, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def submit_certificate(
        self,
        university_public_key,
        student_public_key,
        signature,
        student_name,
        degree,
        major,
        date_issued,
        certificate_hash,
    ):
        certificate = OrderedDict({
            'university_public_key': university_public_key,
            'student_public_key': student_public_key,
            'student_name': student_name,
            'degree': degree,
            'major': major,
            'date_issued': date_issued,
            'certificate_hash': certificate_hash,
        })

        signature_valid = self.verify_certificate_signature(university_public_key, signature, certificate)
        if signature_valid:
            self.certificates.append(certificate)
            return len(self.chain) + 1
        else:
            return False
    #New
    def find_certificate_by_hash(self, cert_hash):
        for block in self.chain:
            for cert in block.get('certificates', []):
                if cert.get('certificate_hash') == cert_hash:
                    return block, cert
        return None, None
    #New
    def list_certificates_for_student(self, student_public_key):
        results = []
        for block in self.chain:
            for cert in block.get('certificates', []):
                if cert.get('student_public_key') == student_public_key:
                    results.append(cert)
        return results


blockchain = Blockchain()

app = Flask(__name__, template_folder="templates_node")
CORS(app)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/certificates/get', methods=['GET'])
def get_certificates():
    certificates = blockchain.certificates
    response = {'certificates': certificates}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    nonce = blockchain.proof_of_work()
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': 'New block created',
        'block_number': block['block_number'],
        'certificates': block['certificates'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/certificates/new', methods=['POST'])
def new_certificate():
    values = request.form

    required = [
        'confirmation_university_public_key',
        'confirmation_student_public_key',
        'confirmation_student_name',
        'confirmation_degree',
        'confirmation_major',
        'confirmation_date_issued',
        'confirmation_certificate_hash',
        'certificate_signature',
    ]
    if not all(k in values for k in required):
        return 'Missing values', 400

    result = blockchain.submit_certificate(
        university_public_key=values['confirmation_university_public_key'],
        student_public_key=values['confirmation_student_public_key'],
        signature=values['certificate_signature'],
        student_name=values['confirmation_student_name'],
        degree=values['confirmation_degree'],
        major=values['confirmation_major'],
        date_issued=values['confirmation_date_issued'],
        certificate_hash=values['confirmation_certificate_hash'],
    )

    if result is False:
        response = {'message': 'Invalid certificate / signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Certificate will be added to Block ' + str(result)}
        return jsonify(response), 201

#New
@app.route('/certificate/verify', methods=['POST'])
def verify_certificate():
    values = request.form or request.json or {}
    cert_hash = values.get('certificate_hash')
    if not cert_hash:
        return 'Missing certificate_hash', 400

    block, cert = blockchain.find_certificate_by_hash(cert_hash)
    if cert is None:
        return jsonify({'valid': False, 'message': 'Certificate hash not found on chain.'}), 200

    return jsonify({
        'valid': True,
        'block_number': block['block_number'],
        'certificate': cert,
    }), 200

#New
@app.route('/certificates/student', methods=['GET'])
def certificates_for_student():
    student_public_key = request.args.get('student_public_key')
    if not student_public_key:
        return 'Missing student_public_key', 400
    certs = blockchain.list_certificates_for_student(student_public_key)
    return jsonify({'certificates': certs}), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = request.form
    # 127.0.0.1:5002,127.0.0.1:5003,127.0.0.1:5004
    nodes = values.get('nodes').replace(' ', '').split(',')

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
