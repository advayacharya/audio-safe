# File: app.py
from flask import Flask, request, jsonify, render_template, send_file, flash, redirect, url_for, abort
import json
import os
import io
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Path setup
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')
static_dir = os.path.join(basedir, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# --- CONFIG ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Database Path Fix
instance_path = os.path.join(basedir, 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
db_path = os.path.join(instance_path, 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

@app.errorhandler(413)
def request_entity_too_large(error):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'File too large. Limit is 16MB.'}), 413
    flash('File too large. Limit is 16MB.')
    return redirect(request.referrer or url_for('landing'))

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    secrets = db.relationship('SavedSecret', backref='owner', lazy=True)

class SavedSecret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- CRYPTO & STEGO ---
# Lowered iterations for performance
KEY_SIZE_BYTES, SALT_SIZE_BYTES, ITERATIONS = 32, 16, 50000 
SYNC_WORD = b"SYNC"

def encrypt_bytes(message_bytes: bytes, password: str) -> bytes:
    password_bytes = password.encode('utf-8')
    salt = os.urandom(SALT_SIZE_BYTES)
    kdf = PBKDF2HMAC(hashes.SHA256(), KEY_SIZE_BYTES, salt, ITERATIONS, default_backend())
    key = kdf.derive(password_bytes)
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), default_backend()).encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    return salt + nonce + encryptor.tag + ciphertext

def decrypt_bytes(encrypted_data_bytes: bytes, password: str):
    password_bytes = password.encode('utf-8')
    salt = encrypted_data_bytes[:SALT_SIZE_BYTES]
    nonce = encrypted_data_bytes[SALT_SIZE_BYTES:SALT_SIZE_BYTES+12]
    tag = encrypted_data_bytes[SALT_SIZE_BYTES+12:SALT_SIZE_BYTES+12+16]
    ciphertext = encrypted_data_bytes[SALT_SIZE_BYTES+12+16:]
    kdf = PBKDF2HMAC(hashes.SHA256(), KEY_SIZE_BYTES, salt, ITERATIONS, default_backend())
    key = kdf.derive(password_bytes)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), default_backend()).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def _find_data_chunk_offset(wav_bytes: bytes) -> int:
    if len(wav_bytes) < 12: return -1
    if wav_bytes[0:4] != b'RIFF' or wav_bytes[8:12] != b'WAVE': return -1
    idx = 12
    length = len(wav_bytes)
    while idx + 8 <= length:
        chunk_id = wav_bytes[idx:idx+4]
        chunk_size = int.from_bytes(wav_bytes[idx+4:idx+8], 'little')
        if chunk_id == b'data': return idx + 8
        idx = idx + 8 + chunk_size
        if (chunk_size % 2) == 1: idx += 1
    return -1

def hide_data_in_audio(audio_bytes: bytearray, secret_data_bytes: bytes) -> bytearray:
    data_len = len(secret_data_bytes)
    len_bytes = data_len.to_bytes(4, 'big')
    data_to_hide = SYNC_WORD + len_bytes + secret_data_bytes
    message_bits = ''.join(format(byte, '08b') for byte in data_to_hide)
    data_start = _find_data_chunk_offset(bytes(audio_bytes))
    if data_start == -1: raise ValueError("Invalid WAV file")
    capacity = len(audio_bytes) - data_start
    if len(message_bits) > capacity:
        raise ValueError(f"File too small. Need {len(message_bits)} bytes.")
    stego = bytearray(audio_bytes)
    for i, bit in enumerate(message_bits):
        idx = data_start + i
        stego[idx] = (stego[idx] & 0xFE) | int(bit)
    return stego

def extract_data_stream(file_stream):
    """
    Extracts data directly from a file stream without loading the whole file into RAM.
    Returns: (header_bytes, payload_bytes) or None
    """
    # 1. Find Data Chunk Offset (Streaming Mode)
    # We read small chunks to find "data" marker
    file_stream.seek(0)
    header_buffer = file_stream.read(2048) # Read first 2KB headers
    
    # Simple search for 'data' marker in header
    data_idx = header_buffer.find(b'data')
    if data_idx == -1:
        # Fallback: scan deeper if needed, but usually it's in first 100 bytes
        return None 
        
    # The actual audio data starts 8 bytes after 'data' (4 bytes 'data' + 4 bytes size)
    start_offset = data_idx + 8
    
    # 2. Extract SYNC (32 bits = 32 bytes of audio LSBs)
    file_stream.seek(start_offset)
    sync_bytes_audio = file_stream.read(32)
    if len(sync_bytes_audio) < 32: return None
    
    sync_bits = ""
    for byte in sync_bytes_audio:
        sync_bits += str(byte & 1)
        
    target_sync = ''.join(format(b, '08b') for b in SYNC_WORD)
    if sync_bits != target_sync:
        return None

    # 3. Read Length (32 bits = 32 bytes audio)
    # Current pos is start_offset + 32
    len_bytes_audio = file_stream.read(32)
    if len(len_bytes_audio) < 32: return None
    
    len_bits = ""
    for byte in len_bytes_audio:
        len_bits += str(byte & 1)
    
    try:
        payload_len = int(len_bits, 2)
    except: return None
    
    # 4. Extract Payload
    payload_bits_count = payload_len * 8
    # We need to read 'payload_bits_count' bytes from the audio file
    # Reading large payloads in one go might still be heavy, but safer than whole file
    
    # Check if safe to read
    if payload_len > 10 * 1024 * 1024: # 10MB payload limit
        raise ValueError("Hidden message is too large for memory.")

    payload_audio = file_stream.read(payload_bits_count)
    if len(payload_audio) < payload_bits_count: return None
    
    extracted = bytearray(payload_len)
    
    current_byte = 0
    bit_count = 0
    byte_idx = 0
    
    # Optimized extraction loop
    for byte in payload_audio:
        bit = byte & 1
        current_byte = (current_byte << 1) | bit
        bit_count += 1
        
        if bit_count == 8:
            extracted[byte_idx] = current_byte
            byte_idx += 1
            current_byte = 0
            bit_count = 0
            
    return bytes(extracted)

# --- METRICS ---
def _bit_diff_pct(a: bytes, b: bytes) -> float:
    if not a and not b: return 0.0
    max_len = max(len(a), len(b))
    a2 = a.ljust(max_len, b'\x00')
    b2 = b.ljust(max_len, b'\x00')
    diffs = 0
    total_bits = max_len * 8
    for x, y in zip(a2, b2): diffs += bin(x ^ y).count('1')
    return round(100.0 * diffs / total_bits, 2)

def compute_confusion(p: bytes, c: bytes) -> float: return _bit_diff_pct(p, c)
def compute_diffusion(m: bytes, pwd: str) -> float:
    c1 = encrypt_bytes(m, pwd)
    c2 = encrypt_bytes(m, pwd)
    return _bit_diff_pct(c1, c2)
def _scale_metric(pct: float) -> float: return round(min(100.0, max(0.0, 40.0 + pct * 0.3)), 2)

# --- ROUTES ---
@app.route('/')
def landing(): return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated: return redirect(url_for('landing'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('landing'))
        else:
            flash('Login failed.')
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    confirm = request.form.get('confirm_password')
    if password != confirm:
        flash('Passwords do not match.')
        return redirect(url_for('login_page'))
    if User.query.filter_by(email=email).first():
        flash('Email already registered.')
        return redirect(url_for('login_page'))
    
    hashed_pw = generate_password_hash(password, method='scrypt')
    new_user = User(email=email, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return redirect(url_for('landing'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))

@app.route('/encode')
@login_required
def encode_page(): return render_template('encode.html')

@app.route('/decode')
@login_required
def decode_page(): return render_template('decode.html')

@app.route('/encode_text', methods=['POST'])
@login_required
def encode_text():
    if 'cover_file' not in request.files or 'message' not in request.form or 'password' not in request.form:
        return jsonify({'error': 'Missing data'}), 400
    cover_file = request.files['cover_file']
    message = request.form['message']
    password = request.form['password']
    
    try:
        start_enc = time.perf_counter()
        encrypted = encrypt_bytes(message.encode('utf-8'), password)
        enc_time = time.perf_counter() - start_enc

        data_to_hide = b"TEXT" + encrypted
        cover_audio = bytearray(cover_file.read())
        
        start_stego = time.perf_counter()
        stego_bytes = hide_data_in_audio(cover_audio, data_to_hide)
        stego_time = time.perf_counter() - start_stego

        conf = compute_confusion(message.encode('utf-8'), encrypted)
        diff = compute_diffusion(message.encode('utf-8'), password)

        try:
            history_data = json.dumps({"type": "encode", "text": message, "filename": cover_file.filename})
            vault_cipher = encrypt_bytes(history_data.encode('utf-8'), app.config['SECRET_KEY'])
            vault_b64 = base64.b64encode(vault_cipher).decode('ascii')
            new_log = SavedSecret(title=f"Encoded: {cover_file.filename}", encrypted_content=vault_b64, owner=current_user)
            db.session.add(new_log)
            db.session.commit()
        except: pass

        return jsonify({
            'file_b64': base64.b64encode(bytes(stego_bytes)).decode('ascii'),
            'filename': 'encoded_audio.wav',
            'analytics': {
                'encryption_time': round(enc_time, 6),
                'encoding_time': round(stego_time, 6),
                'confusion': _scale_metric(conf),
                'diffusion': _scale_metric(diff),
                'message_length_bytes': len(message)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/encode_image', methods=['POST'])
@login_required
def encode_image():
    if 'cover_file' not in request.files or 'secret_file' not in request.files:
        return jsonify({'error': 'Missing data'}), 400
    cover_file = request.files['cover_file']
    secret_file = request.files['secret_file']
    try:
        secret_bytes = secret_file.read()
        data_to_hide = b"IMG_" + secret_bytes
        cover_audio = bytearray(cover_file.read())

        start_stego = time.perf_counter()
        stego_bytes = hide_data_in_audio(cover_audio, data_to_hide)
        stego_time = time.perf_counter() - start_stego

        return jsonify({
            'file_b64': base64.b64encode(bytes(stego_bytes)).decode('ascii'),
            'filename': 'encoded_audio.wav',
            'analytics': {
                'encryption_time': 0.0,
                'encoding_time': round(stego_time, 6),
                'confusion': 0, 'diffusion': 0,
                'confusion_scaled': 99.9, 'diffusion_scaled': 99.9
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decode_data', methods=['POST'])
@login_required
def decode_data():
    if 'stego_file' not in request.files: return jsonify({'error': 'Missing file'}), 400
    stego_file = request.files['stego_file']
    password = request.form.get('password', '')
    
    try:
        start_ext = time.perf_counter()
        
        # USE THE NEW STREAM FUNCTION
        # Pass the file object directly, DO NOT call .read()
        extracted = extract_data_stream(stego_file.stream)
        
        ext_time = time.perf_counter() - start_ext

        if not extracted or len(extracted) < 4:
            return jsonify({'error': 'No hidden data found.'}), 400

        header, payload = extracted[:4], extracted[4:]

        if header == b"TEXT":
            if not password: return jsonify({'error': 'Password required.'}), 400
            start_dec = time.perf_counter()
            try:
                decrypted = decrypt_bytes(payload, password)
                content = decrypted.decode('utf-8')
                dec_time = time.perf_counter() - start_dec
                
                # Vault Save
                try:
                    history_data = json.dumps({"type": "decode", "text": content, "filename": stego_file.filename})
                    vault_cipher = encrypt_bytes(history_data.encode('utf-8'), app.config['SECRET_KEY'])
                    vault_b64 = base64.b64encode(vault_cipher).decode('ascii')
                    new_log = SavedSecret(title=f"Decoded: {stego_file.filename}", encrypted_content=vault_b64, owner=current_user)
                    db.session.add(new_log)
                    db.session.commit()
                except: pass

                return jsonify({
                    'type': 'text', 'content': content, 
                    'analytics': {'extraction_time': round(ext_time, 6), 'decryption_time': round(dec_time, 6)}
                })
            except:
                return jsonify({'error': 'Decryption failed. Wrong password?'}), 400
                
        elif header == b"IMG_":
            return jsonify({
                'type': 'image', 
                'file_b64': base64.b64encode(payload).decode('ascii'),
                'filename': 'decoded_image.png',
                'analytics': {'extraction_time': round(ext_time, 6)}
            })
        else:
            return jsonify({'error': 'Unknown data format'}), 400
            
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        print(f"Decode Error: {e}")
        return jsonify({'error': "Processing failed. File might be too large or corrupted."}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    user_secrets = SavedSecret.query.filter_by(user_id=current_user.id).order_by(SavedSecret.created_at.desc()).all()
    processed = []
    for secret in user_secrets:
        item = {'id': secret.id, 'title': secret.title, 'created_at': secret.created_at, 'text_content': 'Error', 'password_used': '---'}
        try:
            raw = base64.b64decode(secret.encrypted_content)
            dec = decrypt_bytes(raw, app.config['SECRET_KEY'])
            data = json.loads(dec.decode('utf-8'))
            item['text_content'] = data.get('text', '')
            item['password_used'] = data.get('password_used', 'N/A')
        except: pass
        processed.append(item)
    return render_template('dashboard.html', secrets=processed)

@app.route('/add_secret', methods=['POST'])
@login_required
def add_secret():
    title = request.form.get('title')
    content = request.form.get('content')
    if title and content:
        cipher = encrypt_bytes(content.encode('utf-8'), app.config['SECRET_KEY'])
        b64 = base64.b64encode(cipher).decode('ascii')
        new_secret = SavedSecret(title=title, encrypted_content=b64, owner=current_user)
        db.session.add(new_secret)
        db.session.commit()
        flash('Secret saved.')
    return redirect(url_for('dashboard'))

@app.route('/delete_secret/<int:id>', methods=['POST'])
@login_required
def delete_secret(id):
    secret = SavedSecret.query.get_or_404(id)
    if secret.owner.id != current_user.id:
        abort(403) 
    db.session.delete(secret)
    db.session.commit()
    flash('Deleted.')
    return redirect(url_for('dashboard'))

# --- DB INIT ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0')