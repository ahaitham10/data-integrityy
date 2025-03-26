from flask import Flask, request, jsonify
import mysql.connector
import bcrypt
import pyotp
import qrcode
import os
from io import BytesIO
import base64
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# 🔹 Configure JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'  # Change this in production
jwt = JWTManager(app)

# 🔹 Connect to MySQL (XAMPP)
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",  # XAMPP default has no password
        database="auth_system"
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL successfully!")
except mysql.connector.Error as err:
    print(f"❌ MySQL Connection Error: {err}")

# 🔹 Ensure QR Code Directory Exists
QR_CODE_DIR = "qr_codes"
if not os.path.exists(QR_CODE_DIR):
    os.makedirs(QR_CODE_DIR)

# 🔹 Test Route
@app.route('/')
def home():
    return jsonify({"message": "Flask API is running!"})

# 🔹 Test Database Connection
@app.route('/test_db', methods=['GET'])
def test_db():
    try:
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        return jsonify({'tables': [table[0] for table in tables]})
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500

# 🔹 User Registration with 2FA QR Code
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Generate a secret key for Google Authenticator
    secret = pyotp.random_base32()
    
    # Generate QR Code URL
    otp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyApp")

    # Generate and save QR Code image
    qr = qrcode.make(otp_auth_url)
    qr_filename = os.path.join(QR_CODE_DIR, f"{username}.png")
    qr.save(qr_filename)

    # Convert QR Code to Base64 for API response
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    try:
        cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)", 
                       (username, hashed_password.decode('utf-8'), secret))
        db.commit()
        return jsonify({
            "message": "User registered successfully",
            "2FA_secret": secret,
            "qr_code": f"data:image/png;base64,{qr_base64}",
            "qr_image_path": qr_filename
        }), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

# 🔹 User Login with 2FA Verification
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    otp_code = data.get("otp_code")

    cursor.execute("SELECT id, password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode(), user[1].encode()):
        # Verify the OTP
        totp = pyotp.TOTP(user[2])
        if not totp.verify(otp_code):
            return jsonify({"error": "Invalid OTP code"}), 401

        access_token = create_access_token(identity=user[0])
        return jsonify({"token": access_token})
    
    return jsonify({"error": "Invalid username or password"}), 401

# 🔹 Protected Route (Requires Token)
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello User {current_user}, you are authorized!"})

if __name__ == '__main__':
    app.run(debug=True)
