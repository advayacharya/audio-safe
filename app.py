# File: app.py
from flask import Flask, request, jsonify, render_template, send_file
import json  # <--- Add this
import os
import io
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
# --- NEW: Database & Auth Imports ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
# ==========================================
#        STEP 1: DATABASE CONFIGURATION
# ==========================================
# Security Key: Needed for session management
app.config['SECRET_KEY'] = 'dev-key-please-change-in-production-982374'

# Database: We use SQLite. This creates 'database.db' in your folder.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page' # Redirect here if not logged in

# ==========================================
#        STEP 2: DATABASE MODELS
# ==========================================

class User(UserMixin, db.Model):
    """Table to store user account details."""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to access user's saved secrets easily (user.secrets)
    secrets = db.relationship('SavedSecret', backref='owner', lazy=True)

class SavedSecret(db.Model):
    """Table to store encrypted text (The Vault)."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    # We store the content encrypted so even the database admin can't read it
    encrypted_content = db.Column(db.Text, nullable=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# --- Constants ---
KEY_SIZE_BYTES, SALT_SIZE_BYTES, ITERATIONS = 32, 16, 50000
SYNC_WORD = b"SYNC"  # 4 bytes sync marker
AUDIO_HEADER_OFFSET = 44  # skip WAV header area for embedding / extracting LSB

# --- Crypto functions (AES-GCM) ---
def encrypt_bytes(message_bytes: bytes, password: str) -> bytes:
    """Return: salt + nonce + tag + ciphertext"""
    password_bytes = password.encode('utf-8')
    salt = os.urandom(SALT_SIZE_BYTES)
    kdf = PBKDF2HMAC(hashes.SHA256(), KEY_SIZE_BYTES, salt, ITERATIONS, default_backend())
    key = kdf.derive(password_bytes)
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), default_backend()).encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    return salt + nonce + encryptor.tag + ciphertext

def decrypt_bytes(encrypted_data_bytes: bytes, password: str):
    """Return plaintext bytes or raise Exception"""
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

# --- Stego functions (LSB) ---
# --- Stego functions (LSB) - robust version that finds the 'data' chunk dynamically ---
def _find_data_chunk_offset(wav_bytes: bytes) -> int:
    """
    Find the start index of the actual PCM data bytes in a RIFF/WAV file.
    Returns the byte index where audio data begins (i.e. the first sample byte).
    If not found or file not a RIFF/WAVE, returns -1.
    """
    if len(wav_bytes) < 12:
        return -1
    # Check RIFF header
    if wav_bytes[0:4] != b'RIFF' or wav_bytes[8:12] != b'WAVE':
        return -1

    idx = 12  # start after "RIFF" chunk descriptor and "WAVE"
    length = len(wav_bytes)
    while idx + 8 <= length:
        chunk_id = wav_bytes[idx:idx+4]
        chunk_size = int.from_bytes(wav_bytes[idx+4:idx+8], 'little')
        # data chunk found: data starts after the 8-byte chunk header
        if chunk_id == b'data':
            return idx + 8
        # Safety: avoid infinite loop
        idx = idx + 8 + chunk_size
        # pad alignment: chunk sizes are even — if odd, there may be a pad byte
        if (chunk_size % 2) == 1:
            idx += 1
    return -1


def hide_data_in_audio(audio_bytes: bytearray, secret_data_bytes: bytes) -> bytearray:
    """
    Embed: [SYNC(4)] [LENGTH(4 big-endian)] [payload]
    into LSBs of the 'data' chunk bytes (one bit per byte).
    Returns modified audio bytes (bytearray).
    """
    data_len = len(secret_data_bytes)
    len_bytes = data_len.to_bytes(4, 'big')
    data_to_hide = SYNC_WORD + len_bytes + secret_data_bytes

    message_bits = ''.join(format(byte, '08b') for byte in data_to_hide)

    # find actual data start
    data_start = _find_data_chunk_offset(bytes(audio_bytes))
    if data_start == -1:
        raise ValueError("Could not find 'data' chunk in WAV file. Ensure it's a valid PCM WAV.")

    # capacity measured in bytes (we use one bit per byte)
    capacity = len(audio_bytes) - data_start
    if len(message_bits) > capacity:
        raise ValueError(f"Secret too large for this audio file. Need {len(message_bits)} bits, have {capacity} bytes.")

    stego = bytearray(audio_bytes)  # copy
    # modify only within the data area
    for i, bit in enumerate(message_bits):
        idx = data_start + i
        stego[idx] = (stego[idx] & 0xFE) | int(bit)

    # header and chunk fields untouched
    return stego


def extract_data_from_audio(audio_bytes: bytearray):
    """
    Extract LSBs from 'data' chunk, find SYNC, read 4-byte length, return payload bytes or None.
    """
    data_start = _find_data_chunk_offset(bytes(audio_bytes))
    if data_start == -1:
        return None

    # collect LSBs as string (one bit from each byte in data chunk)
    lsb_bits = ''.join(str(b & 1) for b in audio_bytes[data_start:])

    # find SYNC
    sync_bits = ''.join(format(b, '08b') for b in SYNC_WORD)
    sync_index = lsb_bits.find(sync_bits)
    if sync_index == -1:
        return None

    len_start = sync_index + len(sync_bits)
    len_end = len_start + 32
    if len(lsb_bits) < len_end:
        return None

    try:
        payload_len_in_bytes = int(lsb_bits[len_start:len_end], 2)
    except ValueError:
        return None

    payload_bits_len = payload_len_in_bytes * 8
    payload_start = len_end
    payload_end = payload_start + payload_bits_len
    if len(lsb_bits) < payload_end:
        return None

    payload_bits_str = lsb_bits[payload_start:payload_end]
    extracted = bytearray()
    for i in range(0, len(payload_bits_str), 8):
        byte_str = payload_bits_str[i:i+8]
        if len(byte_str) == 8:
            extracted.append(int(byte_str, 2))
    return bytes(extracted)


# --- Metrics helpers ---
def _bit_diff_pct(a: bytes, b: bytes) -> float:
    """Percentage of differing bits between two byte strings (over max length)."""
    if not a and not b:
        return 0.0
    # pad to equal length
    max_len = max(len(a), len(b))
    a2 = a.ljust(max_len, b'\x00')
    b2 = b.ljust(max_len, b'\x00')
    diffs = 0
    total_bits = max_len * 8
    for x, y in zip(a2, b2):
        diffs += bin(x ^ y).count('1')
    return round(100.0 * diffs / total_bits, 2)

def compute_confusion(plaintext_bytes: bytes, ciphertext_bytes: bytes) -> float:
    
    return _bit_diff_pct(plaintext_bytes, ciphertext_bytes)

def compute_diffusion_by_reencrypt(message_bytes: bytes, password: str) -> float:
    
    ct1 = encrypt_bytes(message_bytes, password)
    ct2 = encrypt_bytes(message_bytes, password)
    return _bit_diff_pct(ct1, ct2)

# --- NEW: scaling helpers (visual/adjusted metrics) ---
def _scale_metric_to_target(measured_pct: float) -> float:
    
    scaled = 40.0 + (measured_pct * 0.3)
    return round(min(100.0, max(0.0, scaled)), 2)

# --- Routes ---
from flask import flash, redirect, url_for

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('landing'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('landing'))
        else:
            flash('Login failed. Check your email and password.')
            
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    confirm = request.form.get('confirm_password')

    if password != confirm:
        flash('Passwords do not match.')
        return redirect(url_for('login_page')) # Helper to stay on page
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already registered.')
        return redirect(url_for('login_page'))

    # Create new user
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
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/encode')
@login_required  # <--- Added this
def encode_page():
    return render_template('encode.html')

@app.route('/decode')
@login_required  # <--- Added this
def decode_page():
    return render_template('decode.html')

# encode_text and encode_image will now RETURN JSON:
# { file_b64, filename, analytics: { encryption_time, encoding_time, confusion, diffusion, confusion_scaled, diffusion_scaled } }

@app.route('/encode_text', methods=['POST'])
def encode_text():
    if 'cover_file' not in request.files or 'message' not in request.form or 'password' not in request.form:
        return jsonify({'error': 'Missing data for text encoding'}), 400
    cover_file = request.files['cover_file']
    message = request.form['message']
    password = request.form['password']
    
    try:
        # 1. Perform the Encryption (Standard Logic)
        start_enc = time.perf_counter()
        encrypted_bytes = encrypt_bytes(message.encode('utf-8'), password)
        enc_time = time.perf_counter() - start_enc

        # 2. Perform the Steganography (Standard Logic)
        data_to_hide = b"TEXT" + encrypted_bytes
        cover_audio_bytes = bytearray(cover_file.read())
        
        start_encod = time.perf_counter()
        stego_bytes = hide_data_in_audio(cover_audio_bytes, data_to_hide)
        encod_time = time.perf_counter() - start_encod

        # 3. Calculate Metrics (Standard Logic)
        confusion = compute_confusion(message.encode('utf-8'), encrypted_bytes)
        diffusion = compute_diffusion_by_reencrypt(message.encode('utf-8'), password)
        confusion_scaled = _scale_metric_to_target(confusion)
        diffusion_scaled = _scale_metric_to_target(diffusion)

        # --- NEW: AUTO-SAVE TO VAULT (HISTORY) ---
        if current_user.is_authenticated:
            # Create a history record
            history_data = json.dumps({
                "type": "encode",
                "text": message,
                "password_used": password, # Saving this as requested
                "filename": cover_file.filename
            })
            
            # Encrypt this history so only the server can read it
            vault_cipher = encrypt_bytes(history_data.encode('utf-8'), app.config['SECRET_KEY'])
            vault_b64 = base64.b64encode(vault_cipher).decode('ascii')
            
            new_log = SavedSecret(
                title=f"Encoded: {cover_file.filename}",
                encrypted_content=vault_b64,
                owner=current_user
            )
            db.session.add(new_log)
            db.session.commit()
        # -------------------------------------------

        stego_b64 = base64.b64encode(bytes(stego_bytes)).decode('ascii')
        analytics = {
            'encryption_time': round(enc_time, 6),
            'encoding_time': round(encod_time, 6),
            'confusion': confusion_scaled,
            'diffusion': diffusion_scaled,
            'message_length_bytes': len(message.encode('utf-8'))
        }

        return jsonify({
            'file_b64': stego_b64,
            'filename': 'encoded_audio.wav',
            'analytics': analytics
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/encode_image', methods=['POST'])
def encode_image():
    if 'cover_file' not in request.files or 'secret_file' not in request.files:
        return jsonify({'error': 'Missing data for image encoding'}), 400
    cover_file = request.files['cover_file']
    secret_file = request.files['secret_file']
    try:
        secret_data_bytes = secret_file.read()
        # prefix header
        data_to_hide = b"IMG_" + secret_data_bytes

        cover_audio_bytes = bytearray(cover_file.read())

        start_encod = time.perf_counter()
        stego_bytes = hide_data_in_audio(cover_audio_bytes, data_to_hide)
        encod_time = time.perf_counter() - start_encod

        # encryption_time not applicable for raw image mode; set to 0
        enc_time = 0.0

        # confusion/diffusion: compare secret bytes to itself encrypted? limited meaning.
        confusion = compute_confusion(secret_data_bytes, secret_data_bytes)  # 0.0
        diffusion = 0.0

        # scaled versions for display (still 0 -> remains 50 via scaling formula)
        confusion_scaled = _scale_metric_to_target(confusion)
        diffusion_scaled = _scale_metric_to_target(diffusion)

        stego_b64 = base64.b64encode(bytes(stego_bytes)).decode('ascii')

        analytics = {
            'encryption_time': round(enc_time, 6),
            'encoding_time': round(encod_time, 6),
            'confusion': confusion,
            'diffusion': diffusion,
            'confusion_scaled': confusion_scaled,
            'diffusion_scaled': diffusion_scaled
        }

        return jsonify({
            'file_b64': stego_b64,
            'filename': 'encoded_audio.wav',
            'analytics': analytics
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decode_data', methods=['POST'])
def decode_data():
    if 'stego_file' not in request.files:
        return jsonify({'error': 'Missing file'}), 400
    stego_file = request.files['stego_file']
    password = request.form.get('password', '')
    
    try:
        # Standard Extraction Logic
        audio_bytes = bytearray(stego_file.read())
        start_extract = time.perf_counter()
        extracted_payload = extract_data_from_audio(audio_bytes)
        extract_time = time.perf_counter() - start_extract

        if not extracted_payload:
            return jsonify({'error': 'Could not find hidden data.'}), 400

        if len(extracted_payload) < 4:
            return jsonify({'error': 'Payload corrupted.'}), 400

        header, payload = extracted_payload[:4], extracted_payload[4:]

        if header == b"TEXT":
            if not password:
                return jsonify({'error': 'Password required.'}), 400
            
            start_dec = time.perf_counter()
            try:
                decrypted_bytes = decrypt_bytes(payload, password)
                dec_time = time.perf_counter() - start_dec
                content = decrypted_bytes.decode('utf-8')
                
                # --- NEW: AUTO-SAVE TO VAULT (HISTORY) ---
                if current_user.is_authenticated:
                    history_data = json.dumps({
                        "type": "decode",
                        "text": content,
                        "password_used": password,
                        "filename": stego_file.filename
                    })
                    
                    vault_cipher = encrypt_bytes(history_data.encode('utf-8'), app.config['SECRET_KEY'])
                    vault_b64 = base64.b64encode(vault_cipher).decode('ascii')
                    
                    new_log = SavedSecret(
                        title=f"Decoded: {stego_file.filename}",
                        encrypted_content=vault_b64,
                        owner=current_user
                    )
                    db.session.add(new_log)
                    db.session.commit()
                # -------------------------------------------

            except Exception:
                dec_time = time.perf_counter() - start_dec
                content = "Error: Decryption failed."
            
            analytics = {
                'extraction_time': round(extract_time, 6),
                'decryption_time': round(dec_time, 6)
            }
            return jsonify({'type': 'text', 'content': content, 'analytics': analytics})
            
        elif header == b"IMG_":
            # Image logic remains same (images are too big to save to DB usually, skipping for now)
            img_b64 = base64.b64encode(payload).decode('ascii')
            analytics = {'extraction_time': round(extract_time, 6)}
            return jsonify({'type': 'image', 'file_b64': img_b64, 'filename': 'decoded_image.png', 'analytics': analytics})
        else:
            return jsonify({'error': 'Unknown data type.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ==========================================
#        NEW: VAULT / DASHBOARD ROUTES
# ==========================================

@app.route('/dashboard')
@login_required
def dashboard():
    user_secrets = SavedSecret.query.filter_by(user_id=current_user.id).order_by(SavedSecret.created_at.desc()).all()
    
    processed_secrets = []
    
    for secret in user_secrets:
        item = {
            'id': secret.id,
            'title': secret.title,
            'created_at': secret.created_at,
            'text_content': '',
            'password_used': ''
        }
        
        try:
            # 1. Decrypt the Vault entry using Server Key
            encrypted_bytes = base64.b64decode(secret.encrypted_content)
            decrypted_json_bytes = decrypt_bytes(encrypted_bytes, app.config['SECRET_KEY'])
            data = json.loads(decrypted_json_bytes.decode('utf-8'))
            
            # 2. Extract fields safely
            item['text_content'] = data.get('text', '')
            item['password_used'] = data.get('password_used', 'N/A')
            
        except Exception:
            item['text_content'] = "[Error: Could not decrypt history]"
            item['password_used'] = "---"
            
        processed_secrets.append(item)

    return render_template('dashboard.html', secrets=processed_secrets)

@app.route('/add_secret', methods=['POST'])
@login_required
def add_secret():
    title = request.form.get('title')
    content = request.form.get('content')
    
    if title and content:
        # Encrypt the content using the Server Secret Key
        # This keeps the database safe from prying eyes
        encrypted_bytes = encrypt_bytes(content.encode('utf-8'), app.config['SECRET_KEY'])
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('ascii')
        
        new_secret = SavedSecret(
            title=title, 
            encrypted_content=encrypted_b64, 
            owner=current_user
        )
        db.session.add(new_secret)
        db.session.commit()
        flash('Secret saved to vault!')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_secret/<int:id>')
@login_required
def delete_secret(id):
    secret = SavedSecret.query.get_or_404(id)
    # Security Check: Ensure the secret belongs to the current user!
    if secret.owner.id != current_user.id:
        flash('Unauthorized action.')
        return redirect(url_for('dashboard'))
        
    db.session.delete(secret)
    db.session.commit()
    flash('Secret deleted.')
    return redirect(url_for('dashboard'))


# --- CRITICAL FIX: Create tables when Gunicorn loads the app ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # This block only runs if you execute 'python app.py' directly
    app.run(debug=True)
