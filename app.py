# app.py
import os
import base64
import requests
from datetime import datetime, timedelta
from decimal import Decimal
from dotenv import load_dotenv

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   jsonify, send_file)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_jwt_extended import (JWTManager, create_access_token, jwt_required, get_jwt_identity)
from functools import wraps
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden if not admin
        return f(*args, **kwargs)
    return decorated_function

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "change-me")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'mubea_phase1.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "supersecretjwt")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
jwt = JWTManager(app)

# --- M-Pesa config (sandbox by default) ---
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY", "")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET", "")
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE", "174379")  # sandbox shortcode
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY", "")
MPESA_CALLBACK_URL = os.getenv("MPESA_CALLBACK_URL", "")  # public URL (ngrok) to receive callbacks
MPESA_BASE = "https://sandbox.safaricom.co.ke"  # change to live endpoint when production

# ----------------- Models -----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(120))
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), default="client")  # admin, agent, client
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    wallet = db.relationship('Wallet', uselist=False, backref='user')

    def set_password(self, pw):
        self.password_hash = bcrypt.generate_password_hash(pw).decode()

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Numeric(12,2), default=0.00)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class WalletTx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'))
    type = db.Column(db.String(20))  # deposit, purchase, commission, refund
    amount = db.Column(db.Numeric(12,2))
    note = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reference = db.Column(db.String(255))

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    

# ----------------- Login -----------------
@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# ----------------- Helpers -----------------
def create_wallet_for_user(user):
    if not user.wallet:
        w = Wallet(user=user, balance=0.00)
        db.session.add(w)
        db.session.commit()

def add_wallet_tx(wallet, tx_type, amount, note="", reference=""):
    wallet.balance = Decimal(wallet.balance) + Decimal(amount)
    wallet.updated_at = datetime.utcnow()
    wt = WalletTx(wallet_id=wallet.id, type=tx_type, amount=amount, note=note, reference=reference)
    db.session.add(wt)
    db.session.commit()

def receive_wallet_tx(wallet, amount, note="", reference=""):
    """
    Credits a wallet. Used specifically for incoming funds like P2P transfers.
    """
    wallet.balance = Decimal(wallet.balance) + Decimal(amount)
    wallet.updated_at = datetime.utcnow()
    # Use 'transfer_in' type for the recipient's transaction
    wt = WalletTx(wallet_id=wallet.id, type="transfer_in", amount=amount, note=note, reference=reference)
    db.session.add(wt)
    db.session.commit()

def deduct_wallet(wallet, amount, note="", reference=""):
    if Decimal(wallet.balance) < Decimal(amount):
        raise ValueError("Insufficient balance")
    wallet.balance = Decimal(wallet.balance) - Decimal(amount)
    wallet.updated_at = datetime.utcnow()
    wt = WalletTx(wallet_id=wallet.id, type="purchase", amount=-Decimal(amount), note=note, reference=reference)
    db.session.add(wt)
    db.session.commit()

# ----------------- M-Pesa functions -----------------
def get_mpesa_token():
    """Get OAuth token from Daraja (sandbox)."""
    url = f"{MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials"
    resp = requests.get(url, auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
    resp.raise_for_status()
    return resp.json().get("access_token")

def stk_push(phone, amount, account_ref="WalletTopup", description="Wallet deposit"):
    """Send STK Push request. phone must be in 2547XXXXXXXX format. amount int."""
    token = get_mpesa_token()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode((MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()).decode()

    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(amount),
        "PartyA": phone,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": account_ref,
        "TransactionDesc": description
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(f"{MPESA_BASE}/mpesa/stkpush/v1/processrequest", json=payload, headers=headers)
    return r.json()

# ----------------- Routes (Web) -----------------
@app.route('/')
def home():
    if current_user.is_authenticated:
        create_wallet_for_user(current_user)
        return render_template('dashboard.html', user=current_user)
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        name = request.form.get('name','').strip()
        password = request.form['password']
        role = request.form.get('role','client')
        if User.query.filter_by(phone=phone).first():
            flash("Phone already registered", "danger"); return redirect(url_for('register'))
        u = User(phone=phone, name=name, role=role)
        u.set_password(password)
        db.session.add(u); db.session.commit()
        create_wallet_for_user(u)
        flash("Account created. Please login.", "success"); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        pw = request.form['password']
        u = User.query.filter_by(phone=phone).first()
        if u and u.check_password(pw):
            login_user(u)
            flash("Logged in", "success")
            return redirect(url_for('home'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for('home'))

@app.route('/wallet', methods=['GET'])
@login_required
def wallet_view():
    create_wallet_for_user(current_user)
    txs = WalletTx.query.filter_by(wallet_id=current_user.wallet.id).order_by(WalletTx.timestamp.desc()).all()
    return render_template('wallet.html', wallet=current_user.wallet, txs=txs)

@app.route('/wallet/deposit', methods=['POST'])
@login_required
def wallet_deposit():
    amount_raw = request.form.get('amount','').strip()
    phone = request.form.get('phone', current_user.phone).strip()
    try:
        amount = int(float(amount_raw))
        if amount <= 0: raise ValueError()
    except:
        flash("Enter a valid positive amount", "danger"); return redirect(url_for('wallet_view'))

    if not phone.startswith("254"):
        flash("Phone must be in format 2547XXXXXXXX", "danger"); return redirect(url_for('wallet_view'))
    # Initiate STK push
    try:
        res = stk_push(phone, amount, account_ref=f"UID{current_user.id}", description="Wallet deposit")
        # record the request in txs (pending)
        create_wallet_for_user(current_user)
        add_wallet_tx(current_user.wallet, "deposit_pending", Decimal(0), note=f"STK push initiated: {res.get('ResponseDescription')}", reference=res.get('CheckoutRequestID', ''))
        flash("STK Push sent to your phone. Complete the payment on your phone.", "info")
    except Exception as e:
        flash(f"Error initiating STK push: {e}", "danger")
    return redirect(url_for('wallet_view'))

# ----------------- M-Pesa callback endpoint -----------------
@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    payload = request.get_json(force=True, silent=True)
    # Daraja sends JSON with Body->stkCallback ...
    try:
        body = payload.get('Body', {})
        stk = body.get('stkCallback', {})
        result_code = stk.get('ResultCode')
        checkout_request_id = stk.get('CheckoutRequestID')
        # if success, find amount and update the corresponding wallet (we saved a pending tx with reference)
        if result_code == 0:
            # find Amount from CallbackMetadata
            items = stk.get('CallbackMetadata', {}).get('Item', [])
            amount = None; phone = None
            for it in items:
                if it.get('Name') == 'Amount':
                    amount = Decimal(it.get('Value'))
                if it.get('Name') == 'PhoneNumber':
                    phone = str(it.get('Value'))
            # find user by pending tx reference
            pending = WalletTx.query.filter_by(reference=checkout_request_id, type='deposit_pending').order_by(WalletTx.timestamp.desc()).first()
            if pending:
                wallet = Wallet.query.get(pending.wallet_id)
                add_wallet_tx(wallet, "deposit", Decimal(amount), note=f"Mpesa deposit from {phone}", reference=checkout_request_id)
                # optionally remove pending entry or mark it (we leave record)
        else:
            # failed or cancelled: mark pending with note
            pending = WalletTx.query.filter_by(reference=checkout_request_id, type='deposit_pending').order_by(WalletTx.timestamp.desc()).first()
            if pending:
                pending.note = f"Failed STK result_code={result_code}"
                db.session.commit()
    except Exception as e:
        print("Error processing callback:", e)
    # Daraja expects a quick JSON response
    return jsonify({"ResultCode":0, "ResultDesc":"Accepted"})

# ----------------- Simple Admin API endpoints -----------------
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    phone = data.get('phone'); pw = data.get('password')
    u = User.query.filter_by(phone=phone).first()
    if u and u.check_password(pw):
        access = create_access_token(identity=u.id, expires_delta=timedelta(days=7))
        return jsonify({"access_token": access, "user": {"id": u.id, "phone": u.phone, "name": u.name, "role": u.role}})
    return jsonify({"msg":"Invalid credentials"}), 401

@app.route('/api/me', methods=['GET'])
@jwt_required()
def api_me():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    create_wallet_for_user(u)
    return jsonify({"id": u.id, "phone": u.phone, "name": u.name, "role": u.role, "wallet_balance": float(u.wallet.balance)})
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)


# ----------------- Client Service Routes -----------------
@app.route('/buy_airtime', methods=['GET', 'POST'])
@login_required
def buy_airtime():
    if request.method == 'POST':
        amount = request.form.get('amount', '').strip()
        phone = request.form.get('phone', '').strip() or current_user.phone
        try:
            amount = int(float(amount))
            if amount <= 0:
                raise ValueError()
        except:
            flash("Enter a valid amount", "danger")
            return redirect(url_for('buy_airtime'))

        # Deduct wallet and record tx (later you can add API integration here)
        try:
            deduct_wallet(current_user.wallet, amount, note=f"Airtime for {phone}")
            flash(f"Airtime of KSh {amount} purchased for {phone}", "success")
        except ValueError as e:
            flash(str(e), "danger")

        return redirect(url_for('wallet_view'))

    return render_template('buy_airtime.html', user=current_user)


@app.route('/pay_bill', methods=['GET', 'POST'])
@login_required
def pay_bill():
    if request.method == 'POST':
        account_number = request.form.get('account_number', '').strip()
        amount = request.form.get('amount', '').strip()
        try:
            amount = int(float(amount))
            if amount <= 0:
                raise ValueError()
        except:
            flash("Enter a valid amount", "danger")
            return redirect(url_for('pay_bill'))

        try:
            deduct_wallet(current_user.wallet, amount, note=f"Bill payment for {account_number}")
            flash(f"Bill of KSh {amount} paid for account {account_number}", "success")
        except ValueError as e:
            flash(str(e), "danger")

        return redirect(url_for('wallet_view'))

    return render_template('pay_bill.html', user=current_user)


@app.route('/buy_data', methods=['GET', 'POST'])
@login_required
def buy_data():
    if request.method == 'POST':
        bundle_size = request.form.get('bundle_size', '').strip()
        phone = request.form.get('phone', '').strip() or current_user.phone
        amount = request.form.get('amount', '').strip()

        try:
            amount = int(float(amount))
            if amount <= 0:
                raise ValueError()
        except:
            flash("Enter a valid amount", "danger")
            return redirect(url_for('buy_data'))

        try:
            deduct_wallet(current_user.wallet, amount, note=f"Data {bundle_size} for {phone}")
            flash(f"Data bundle ({bundle_size}) purchased for {phone}", "success")
        except ValueError as e:
            flash(str(e), "danger")

        return redirect(url_for('wallet_view'))

    return render_template('buy_data.html', user=current_user)

@app.route('/manage_services', methods=['GET', 'POST'])
@login_required
def manage_services():
    if current_user.role != 'agent':
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        service_name = request.form.get('service_name', '').strip()
        if service_name:
            new_service = Service(name=service_name, created_by=current_user.id)
            db.session.add(new_service)
            db.session.commit()
            flash(f"Service '{service_name}' added successfully ✅", "success")
        else:
            flash("Please enter a valid service name", "danger")
        return redirect(url_for('manage_services'))

    # Show services created by the logged-in agent
    my_services = Service.query.filter_by(created_by=current_user.id).order_by(Service.created_at.desc()).all()
    return render_template('manage_services.html', user=current_user, my_services=my_services)

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer_funds():
    create_wallet_for_user(current_user) # Ensure sender has a wallet
    
    if request.method == 'POST':
        # 1. Get and Validate Input
        recipient_phone = request.form.get('recipient_phone', '').strip()
        amount_raw = request.form.get('amount', '').strip()
        
        try:
            amount = Decimal(amount_raw)
            if amount <= 0:
                flash("Enter a valid positive amount.", "danger"); return redirect(url_for('transfer_funds'))
        except:
            flash("Enter a valid amount.", "danger"); return redirect(url_for('transfer_funds'))
            
        # Check against sender's phone
        if recipient_phone == current_user.phone:
            flash("Cannot send money to yourself.", "danger"); return redirect(url_for('transfer_funds'))
        
        # 2. Find Recipient
        recipient = User.query.filter_by(phone=recipient_phone).first()
        if not recipient:
            flash(f"User with phone number {recipient_phone} not found.", "danger"); return redirect(url_for('transfer_funds'))

        create_wallet_for_user(recipient) # Ensure recipient has a wallet
        
        # 3. Process Transaction
        try:
            # Generate a common reference for both transactions
            transfer_ref = f"P2P-{datetime.now().timestamp()}-{current_user.id}-{recipient.id}"
            
            # Sender: Deduct funds (uses existing deduct_wallet helper)
            deduct_wallet(
                current_user.wallet, 
                amount, 
                note=f"P2P transfer to {recipient.phone}", 
                reference=transfer_ref
            )
            
            # Recipient: Credit funds (uses new receive_wallet_tx helper)
            receive_wallet_tx(
                recipient.wallet, 
                amount, 
                note=f"P2P transfer from {current_user.phone}", 
                reference=transfer_ref
            )
            
            flash(f"Successfully sent KSh {amount} to {recipient.phone}.", "success")
        
        except ValueError as e:
            # Catches "Insufficient balance" from deduct_wallet
            flash(str(e), "danger")
        
        return redirect(url_for('wallet_view'))

    return render_template('transfer_funds.html', user=current_user)

# ----------------- Init and sample admin -----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # create an admin if missing
        if not User.query.filter_by(role='admin').first():
            admin = User(phone="254700000000", name="Administrator", role="admin")
            admin.set_password("admin123")
            db.session.add(admin); db.session.commit()
            create_wallet_for_user(admin)
    app.run(debug=True)

