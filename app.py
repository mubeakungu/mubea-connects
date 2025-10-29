import os
import base64
import requests
from datetime import datetime, timedelta
from decimal import Decimal
from dotenv import load_dotenv
import secrets
import re

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   jsonify, send_file)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_jwt_extended import (JWTManager, create_access_token, jwt_required, get_jwt_identity)
from functools import wraps
from flask import abort
from sqlalchemy import func

# ============== DECORATORS ==============
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("⚠️ Admin access required", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'agent']:
            flash("⚠️ Agent access required", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ============== CONFIG ==============
load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'mubea_enhanced.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page"
login_manager.login_message_category = "info"
jwt = JWTManager(app)

# M-Pesa Configuration
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY", "")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET", "")
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE", "174379")
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY", "")
MPESA_CALLBACK_URL = os.getenv("MPESA_CALLBACK_URL", "")
MPESA_BASE = os.getenv("MPESA_BASE", "https://sandbox.safaricom.co.ke")

# ============== MODELS ==============
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), default="client", index=True)
    referral_code = db.Column(db.String(20), unique=True, index=True)
    referred_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    loyalty_points = db.Column(db.Integer, default=0)
    membership_tier = db.Column(db.String(20), default="Bronze")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    wallet = db.relationship('Wallet', uselist=False, backref='user', cascade='all, delete-orphan')
    sent_transfers = db.relationship('P2PTransfer', foreign_keys='P2PTransfer.sender_id', backref='sender')
    received_transfers = db.relationship('P2PTransfer', foreign_keys='P2PTransfer.receiver_id', backref='receiver')
    savings_goals = db.relationship('SavingsGoal', backref='user', cascade='all, delete-orphan')
    loans = db.relationship('LoanApplication', backref='user', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', cascade='all, delete-orphan')

    def set_password(self, pw):
        self.password_hash = bcrypt.generate_password_hash(pw).decode()

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)
    
    def generate_referral_code(self):
        self.referral_code = f"MUB{secrets.token_hex(4).upper()}"

    @property
    def unread_notifications_count(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Numeric(12,2), default=0.00)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    transactions = db.relationship('WalletTx', backref='wallet', cascade='all, delete-orphan')

class WalletTx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), index=True)
    type = db.Column(db.String(20), index=True)
    amount = db.Column(db.Numeric(12,2))
    note = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    reference = db.Column(db.String(255), index=True)
    category = db.Column(db.String(50), index=True)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), index=True)
    commission_rate = db.Column(db.Numeric(5,2), default=0.00)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class P2PTransfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    amount = db.Column(db.Numeric(12,2))
    note = db.Column(db.String(255))
    status = db.Column(db.String(20), default="completed")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    reference = db.Column(db.String(50), unique=True, index=True)

class SavingsGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    goal_name = db.Column(db.String(120))
    target_amount = db.Column(db.Numeric(12,2))
    current_amount = db.Column(db.Numeric(12,2), default=0.00)
    deadline = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="active")
    
    @property
    def progress_percentage(self):
        if self.target_amount <= 0:
            return 0
        return min(int((self.current_amount / self.target_amount) * 100), 100)
    
    @property
    def days_remaining(self):
        if self.deadline:
            delta = self.deadline - datetime.now().date()
            return delta.days
        return None

class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    amount = db.Column(db.Numeric(12,2))
    purpose = db.Column(db.String(255))
    status = db.Column(db.String(20), default="pending", index=True)
    interest_rate = db.Column(db.Numeric(5,2))
    repayment_amount = db.Column(db.Numeric(12,2))
    due_date = db.Column(db.Date)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    repaid_at = db.Column(db.DateTime)

class Commission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    transaction_type = db.Column(db.String(50))
    transaction_amount = db.Column(db.Numeric(12,2))
    commission_amount = db.Column(db.Numeric(12,2))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    reference = db.Column(db.String(255))

class AgentFloat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    float_balance = db.Column(db.Numeric(12,2), default=0.00)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    title = db.Column(db.String(120))
    message = db.Column(db.Text)
    type = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# ============== LOGIN MANAGER ==============
@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# ============== HELPER FUNCTIONS ==============
def validate_phone(phone):
    """Validate Kenyan phone number format"""
    phone = phone.strip().replace(" ", "").replace("-", "")
    pattern = r'^254[17]\d{8}$'
    return re.match(pattern, phone) is not None

def format_currency(amount):
    """Format amount as currency"""
    return f"KSh {amount:,.2f}"

def create_wallet_for_user(user):
    """Ensure user has a wallet"""
    if not user.wallet:
        w = Wallet(user=user, balance=0.00)
        db.session.add(w)
        db.session.commit()
    return user.wallet

def add_wallet_tx(wallet, tx_type, amount, note="", reference="", category=""):
    """Add transaction to wallet"""
    try:
        wallet.balance = Decimal(wallet.balance) + Decimal(amount)
        wallet.updated_at = datetime.utcnow()
        
        wt = WalletTx(
            wallet_id=wallet.id,
            type=tx_type,
            amount=amount,
            note=note,
            reference=reference or f"TX{secrets.token_hex(6).upper()}",
            category=category
        )
        db.session.add(wt)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Error adding wallet transaction: {e}")
        return False

def deduct_wallet(wallet, amount, note="", reference="", category=""):
    """Deduct from wallet with validation"""
    try:
        amount = Decimal(amount)
        if Decimal(wallet.balance) < amount:
            raise ValueError("Insufficient balance")
        
        wallet.balance = Decimal(wallet.balance) - amount
        wallet.updated_at = datetime.utcnow()
        
        wt = WalletTx(
            wallet_id=wallet.id,
            type="purchase",
            amount=-amount,
            note=note,
            reference=reference or f"TX{secrets.token_hex(6).upper()}",
            category=category
        )
        db.session.add(wt)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        raise ValueError(str(e))

def add_loyalty_points(user, points):
    """Add loyalty points and update tier"""
    user.loyalty_points += points
    
    # Update membership tier
    if user.loyalty_points >= 10000:
        user.membership_tier = "Gold"
    elif user.loyalty_points >= 5000:
        user.membership_tier = "Silver"
    else:
        user.membership_tier = "Bronze"
    
    db.session.commit()

def calculate_commission(amount, service_type):
    """Calculate agent commission"""
    rates = {
        'airtime': 2.0,
        'data': 3.0,
        'bills': 1.5,
        'transfer': 1.0,
        'loan': 0.5
    }
    rate = rates.get(service_type, 1.0)
    return Decimal(amount) * Decimal(rate) / Decimal(100)

def create_notification(user_id, title, message, notification_type="info"):
    """Create notification for user"""
    try:
        notif = Notification(
            user_id=user_id,
            title=title,
            message=message,
            type=notification_type
        )
        db.session.add(notif)
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False

# ============== M-PESA FUNCTIONS ==============
def get_mpesa_token():
    """Get M-Pesa access token"""
    try:
        url = f"{MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials"
        resp = requests.get(url, auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET), timeout=30)
        resp.raise_for_status()
        return resp.json().get("access_token")
    except Exception as e:
        print(f"M-Pesa token error: {e}")
        raise

def stk_push(phone, amount, account_ref="WalletTopup", description="Wallet deposit"):
    """Initiate M-Pesa STK push"""
    try:
        token = get_mpesa_token()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(
            (MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()
        ).decode()

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
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        r = requests.post(
            f"{MPESA_BASE}/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers=headers,
            timeout=30
        )
        return r.json()
    except Exception as e:
        print(f"STK Push error: {e}")
        return {"ResponseCode": "1", "ResponseDescription": str(e)}

# ============== WEB ROUTES ==============
@app.route('/')
def home():
    if current_user.is_authenticated:
        create_wallet_for_user(current_user)
        
        # Get dashboard statistics
        recent_txs = WalletTx.query.filter_by(
            wallet_id=current_user.wallet.id
        ).order_by(WalletTx.timestamp.desc()).limit(5).all()
        
        # Calculate monthly spending
        month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_spending = db.session.query(func.sum(WalletTx.amount)).filter(
            WalletTx.wallet_id == current_user.wallet.id,
            WalletTx.amount < 0,
            WalletTx.timestamp >= month_start
        ).scalar() or 0
        
        # Get active savings goals
        active_goals = SavingsGoal.query.filter_by(
            user_id=current_user.id,
            status='active'
        ).count()
        
        return render_template(
            'dashboard.html',
            user=current_user,
            recent_txs=recent_txs,
            monthly_spending=abs(monthly_spending),
            active_goals=active_goals
        )
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'client')
        referral_code = request.form.get('referral_code', '').strip()
        
        # Validation
        if not all([phone, name, password]):
            flash("⚠️ Please fill in all required fields", "danger")
            return redirect(url_for('register'))
        
        if not validate_phone(phone):
            flash("⚠️ Invalid phone number format. Use 254XXXXXXXXX", "danger")
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash("⚠️ Password must be at least 6 characters", "danger")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("⚠️ Passwords do not match", "danger")
            return redirect(url_for('register'))
        
        if User.query.filter_by(phone=phone).first():
            flash("⚠️ Phone number already registered", "danger")
            return redirect(url_for('register'))
        
        if email and User.query.filter_by(email=email).first():
            flash("⚠️ Email already registered", "danger")
            return redirect(url_for('register'))
        
        try:
            # Create user
            u = User(phone=phone, name=name, email=email, role=role)
            u.set_password(password)
            u.generate_referral_code()
            
            # Handle referral
            if referral_code:
                referrer = User.query.filter_by(referral_code=referral_code).first()
                if referrer:
                    u.referred_by = referrer.id
                    add_loyalty_points(referrer, 100)
                    create_notification(
                        referrer.id,
                        "🎉 Referral Bonus",
                        f"You earned 100 points for referring {name}!",
                        "success"
                    )
            
            db.session.add(u)
            db.session.commit()
            
            # Create wallet
            create_wallet_for_user(u)
            
            # Welcome notification
            create_notification(
                u.id,
                "👋 Welcome to Mubea!",
                f"Hi {name}! Your account has been created. Your referral code is {u.referral_code}",
                "info"
            )
            
            flash("✅ Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"⚠️ Error creating account: {str(e)}", "danger")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        
        if not phone or not password:
            flash("⚠️ Please enter phone and password", "danger")
            return redirect(url_for('login'))
        
        u = User.query.filter_by(phone=phone).first()
        
        if u and u.check_password(password):
            if not u.is_active:
                flash("⚠️ Your account has been deactivated. Contact support.", "danger")
                return redirect(url_for('login'))
            
            u.last_login = datetime.utcnow()
            db.session.commit()
            login_user(u, remember=True)
            
            flash(f"✅ Welcome back, {u.name}!", "success")
            
            # Redirect to appropriate dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            elif u.role == 'admin':
                return redirect(url_for('admin_analytics'))
            elif u.role == 'agent':
                return redirect(url_for('agent_dashboard'))
            else:
                return redirect(url_for('home'))
        
        flash("⚠️ Invalid phone number or password", "danger")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("👋 Logged out successfully", "info")
    return redirect(url_for('home'))

# ============== WALLET ROUTES ==============
@app.route('/wallet')
@login_required
def wallet_view():
    create_wallet_for_user(current_user)
    
    # Get transactions with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    txs_pagination = WalletTx.query.filter_by(
        wallet_id=current_user.wallet.id
    ).order_by(WalletTx.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Calculate spending by category
    spending_stats = db.session.query(
        WalletTx.category,
        func.sum(WalletTx.amount).label('total')
    ).filter(
        WalletTx.wallet_id == current_user.wallet.id,
        WalletTx.amount < 0,
        WalletTx.category != None
    ).group_by(WalletTx.category).all()
    
    return render_template(
        'wallet.html',
        wallet=current_user.wallet,
        txs=txs_pagination.items,
        pagination=txs_pagination,
        spending_stats=spending_stats
    )

@app.route('/wallet/deposit', methods=['POST'])
@login_required
def wallet_deposit():
    amount_raw = request.form.get('amount', '').strip()
    phone = request.form.get('phone', current_user.phone).strip()
    
    # Validation
    try:
        amount = int(float(amount_raw))
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount < 10:
            raise ValueError("Minimum deposit is KSh 10")
        if amount > 150000:
            raise ValueError("Maximum deposit is KSh 150,000")
    except ValueError as e:
        flash(f"⚠️ {str(e)}", "danger")
        return redirect(url_for('wallet_view'))
    
    if not validate_phone(phone):
        flash("⚠️ Invalid phone number format. Use 254XXXXXXXXX", "danger")
        return redirect(url_for('wallet_view'))
    
    try:
        res = stk_push(
            phone,
            amount,
            account_ref=f"UID{current_user.id}",
            description="Wallet deposit"
        )
        
        if res.get('ResponseCode') == '0':
            create_wallet_for_user(current_user)
            add_wallet_tx(
                current_user.wallet,
                "deposit_pending",
                Decimal(0),
                note=f"STK push initiated",
                reference=res.get('CheckoutRequestID', '')
            )
            flash("📱 STK Push sent! Please complete payment on your phone.", "info")
        else:
            flash(f"⚠️ {res.get('ResponseDescription', 'Failed to initiate payment')}", "danger")
            
    except Exception as e:
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('wallet_view'))

# ============== P2P TRANSFER ==============
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def p2p_transfer():
    if request.method == 'POST':
        receiver_phone = request.form.get('receiver_phone', '').strip()
        amount_raw = request.form.get('amount', '').strip()
        note = request.form.get('note', '').strip()
        
        try:
            amount = Decimal(amount_raw)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount < 10:
                raise ValueError("Minimum transfer is KSh 10")
        except (ValueError, Exception) as e:
            flash(f"⚠️ {str(e)}", "danger")
            return redirect(url_for('p2p_transfer'))
        
        if not validate_phone(receiver_phone):
            flash("⚠️ Invalid phone number format", "danger")
            return redirect(url_for('p2p_transfer'))
        
        receiver = User.query.filter_by(phone=receiver_phone).first()
        if not receiver:
            flash("⚠️ Receiver not found. They may need to register first.", "danger")
            return redirect(url_for('p2p_transfer'))
        
        if receiver.id == current_user.id:
            flash("⚠️ Cannot transfer to yourself", "danger")
            return redirect(url_for('p2p_transfer'))
        
        if Decimal(current_user.wallet.balance) < amount:
            flash("⚠️ Insufficient balance", "danger")
            return redirect(url_for('p2p_transfer'))
        
        try:
            reference = f"P2P{secrets.token_hex(6).upper()}"
            
            # Deduct from sender
            deduct_wallet(
                current_user.wallet,
                amount,
                note=f"Transfer to {receiver.name}",
                reference=reference,
                category="transfer"
            )
            
            # Add to receiver
            create_wallet_for_user(receiver)
            add_wallet_tx(
                receiver.wallet,
                "p2p_receive",
                amount,
                note=f"From {current_user.name}",
                reference=reference,
                category="transfer"
            )
            
            # Record transfer
            transfer = P2PTransfer(
                sender_id=current_user.id,
                receiver_id=receiver.id,
                amount=amount,
                note=note,
                reference=reference
            )
            db.session.add(transfer)
            
            # Add loyalty points
            add_loyalty_points(current_user, int(amount / 100))
            
            # Notifications
            create_notification(
                receiver.id,
                "💰 Money Received",
                f"You received KSh {amount:,.2f} from {current_user.name}",
                "success"
            )
            
            db.session.commit()
            
            flash(f"✅ Successfully transferred KSh {amount:,.2f} to {receiver.name}", "success")
            return redirect(url_for('wallet_view'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"⚠️ Transfer failed: {str(e)}", "danger")
            return redirect(url_for('p2p_transfer'))
    
    return render_template('p2p_transfer.html', user=current_user)

# ============== SAVINGS GOALS ==============
@app.route('/savings', methods=['GET', 'POST'])
@login_required
def savings_goals():
    if request.method == 'POST':
        goal_name = request.form.get('goal_name', '').strip()
        target_amount = request.form.get('target_amount', '').strip()
        deadline = request.form.get('deadline', '').strip()
        
        try:
            target = Decimal(target_amount)
            if target <= 0:
                raise ValueError("Target amount must be positive")
            
            deadline_date = datetime.strptime(deadline, '%Y-%m-%d').date()
            if deadline_date <= datetime.now().date():
                raise ValueError("Deadline must be in the future")
            
            goal = SavingsGoal(
                user_id=current_user.id,
                goal_name=goal_name,
                target_amount=target,
                deadline=deadline_date
            )
            db.session.add(goal)
            db.session.commit()
            
            create_notification(
                current_user.id,
                "🎯 New Savings Goal",
                f"Created goal: {goal_name} - KSh {target:,.2f}",
                "success"
            )
            
            flash(f"✅ Savings goal '{goal_name}' created!", "success")
            return redirect(url_for('savings_goals'))
            
        except ValueError as e:
            flash(f"⚠️ {str(e)}", "danger")
        except Exception as e:
            flash(f"⚠️ Error creating goal: {str(e)}", "danger")
    
    goals = SavingsGoal.query.filter_by(
        user_id=current_user.id
    ).order_by(SavingsGoal.created_at.desc()).all()
    
    return render_template('savings_goals.html', user=current_user, goals=goals)

@app.route('/savings/<int:goal_id>/contribute', methods=['POST'])
@login_required
def contribute_to_savings(goal_id):
    goal = SavingsGoal.query.get_or_404(goal_id)
    
    if goal.user_id != current_user.id:
        flash("⚠️ Unauthorized", "danger")
        abort(403)
    
    if goal.status != 'active':
        flash("⚠️ Cannot contribute to inactive goal", "danger")
        return redirect(url_for('savings_goals'))
    
    amount_raw = request.form.get('amount', '').strip()
    
    try:
        amount = Decimal(amount_raw)
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        if Decimal(current_user.wallet.balance) < amount:
            raise ValueError("Insufficient wallet balance")
        
        # Deduct from wallet
        deduct_wallet(
            current_user.wallet,
            amount,
            note=f"Savings: {goal.goal_name}",
            category="savings"
        )
        
        # Update goal
        goal.current_amount += amount
        
        if goal.current_amount >= goal.target_amount:
            goal.status = "completed"
            create_notification(
                current_user.id,
                "🎉 Goal Achieved!",
                f"Congratulations! You've reached your '{goal.goal_name}' goal of KSh {goal.target_amount:,.2f}!",
                "success"
            )
            add_loyalty_points(current_user, 200)  # Bonus points for completing goal
        
        db.session.commit()
        
        flash(f"✅ Added KSh {amount:,.2f} to your savings goal", "success")
        
    except ValueError as e:
        flash(f"⚠️ {str(e)}", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('savings_goals'))

@app.route('/savings/<int:goal_id>/delete', methods=['POST'])
@login_required
def delete_savings_goal(goal_id):
    goal = SavingsGoal.query.get_or_404(goal_id)
    
    if goal.user_id != current_user.id:
        abort(403)
    
    try:
        # Return saved amount to wallet if any
        if goal.current_amount > 0:
            add_wallet_tx(
                current_user.wallet,
                "refund",
                goal.current_amount,
                note=f"Refund from cancelled goal: {goal.goal_name}",
                category="savings"
            )
        
        db.session.delete(goal)
        db.session.commit()
        
        flash(f"✅ Savings goal deleted. KSh {goal.current_amount:,.2f} returned to wallet.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('savings_goals'))

# ============== LOANS ==============
@app.route('/loans', methods=['GET', 'POST'])
@login_required
def loans():
    if request.method == 'POST':
        amount_raw = request.form.get('amount', '').strip()
        purpose = request.form.get('purpose', '').strip()
        
        try:
            amount = Decimal(amount_raw)
            
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount < 500:
                raise ValueError("Minimum loan amount is KSh 500")
            if amount > 50000:
                raise ValueError("Maximum loan amount is KSh 50,000")
            
            if not purpose or len(purpose) < 10:
                raise ValueError("Please provide a detailed purpose (at least 10 characters)")
            
            # Check existing active loans
            active_loan = LoanApplication.query.filter_by(
                user_id=current_user.id,
                status='approved'
            ).first()
            
            if active_loan:
                flash("⚠️ You have an active loan. Please repay it first.", "danger")
                return redirect(url_for('loans'))
            
            # Check pending applications
            pending_loan = LoanApplication.query.filter_by(
                user_id=current_user.id,
                status='pending'
            ).first()
            
            if pending_loan:
                flash("⚠️ You already have a pending loan application.", "danger")
                return redirect(url_for('loans'))
            
            # Calculate interest (10%)
            interest_rate = Decimal('10.0')
            repayment = amount + (amount * interest_rate / Decimal('100'))
            due_date = datetime.now() + timedelta(days=30)
            
            loan = LoanApplication(
                user_id=current_user.id,
                amount=amount,
                purpose=purpose,
                interest_rate=interest_rate,
                repayment_amount=repayment,
                due_date=due_date.date()
            )
            db.session.add(loan)
            db.session.commit()
            
            create_notification(
                current_user.id,
                "📋 Loan Application Submitted",
                f"Your loan application for KSh {amount:,.2f} is under review. You'll be notified once processed.",
                "info"
            )
            
            flash("✅ Loan application submitted successfully! We'll review it soon.", "success")
            return redirect(url_for('loans'))
            
        except ValueError as e:
            flash(f"⚠️ {str(e)}", "danger")
        except Exception as e:
            flash(f"⚠️ Error: {str(e)}", "danger")
    
    user_loans = LoanApplication.query.filter_by(
        user_id=current_user.id
    ).order_by(LoanApplication.applied_at.desc()).all()
    
    return render_template('loans.html', user=current_user, loans=user_loans)

@app.route('/loans/<int:loan_id>/repay', methods=['POST'])
@login_required
def repay_loan(loan_id):
    loan = LoanApplication.query.get_or_404(loan_id)
    
    if loan.user_id != current_user.id:
        abort(403)
    
    if loan.status != 'approved':
        flash("⚠️ This loan is not active", "danger")
        return redirect(url_for('loans'))
    
    try:
        if Decimal(current_user.wallet.balance) < loan.repayment_amount:
            raise ValueError("Insufficient balance to repay loan")
        
        # Deduct repayment from wallet
        deduct_wallet(
            current_user.wallet,
            loan.repayment_amount,
            note=f"Loan repayment",
            category="loan_repayment"
        )
        
        # Update loan status
        loan.status = 'repaid'
        loan.repaid_at = datetime.utcnow()
        
        # Reward for timely repayment
        add_loyalty_points(current_user, 50)
        
        create_notification(
            current_user.id,
            "✅ Loan Repaid",
            f"Thank you! Your loan of KSh {loan.amount:,.2f} has been fully repaid.",
            "success"
        )
        
        db.session.commit()
        
        flash(f"✅ Loan repaid successfully! KSh {loan.repayment_amount:,.2f} deducted.", "success")
        
    except ValueError as e:
        flash(f"⚠️ {str(e)}", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('loans'))

# ============== SERVICES ==============
@app.route('/buy_airtime', methods=['GET', 'POST'])
@login_required
def buy_airtime():
    if request.method == 'POST':
        amount_raw = request.form.get('amount', '').strip()
        phone = request.form.get('phone', '').strip() or current_user.phone
        
        try:
            amount = Decimal(amount_raw)
            if amount < 10:
                raise ValueError("Minimum airtime is KSh 10")
            if amount > 10000:
                raise ValueError("Maximum airtime is KSh 10,000")
        except (ValueError, Exception) as e:
            flash(f"⚠️ {str(e)}", "danger")
            return redirect(url_for('buy_airtime'))
        
        if not validate_phone(phone):
            flash("⚠️ Invalid phone number", "danger")
            return redirect(url_for('buy_airtime'))
        
        try:
            deduct_wallet(
                current_user.wallet,
                amount,
                note=f"Airtime for {phone}",
                category="airtime"
            )
            
            # Add loyalty points
            add_loyalty_points(current_user, int(amount / 20))
            
            # Agent commission
            if current_user.role == 'agent':
                comm = calculate_commission(amount, 'airtime')
                commission = Commission(
                    agent_id=current_user.id,
                    transaction_type='airtime',
                    transaction_amount=amount,
                    commission_amount=comm,
                    reference=f"AIRTIME{secrets.token_hex(4).upper()}"
                )
                db.session.add(commission)
                add_wallet_tx(
                    current_user.wallet,
                    "commission",
                    comm,
                    note="Commission: Airtime",
                    category="commission"
                )
            
            db.session.commit()
            
            flash(f"✅ Airtime of KSh {amount:,.2f} sent to {phone}", "success")
            
        except ValueError as e:
            flash(f"⚠️ {str(e)}", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"⚠️ Error: {str(e)}", "danger")
        
        return redirect(url_for('wallet_view'))
    
    return render_template('buy_airtime.html', user=current_user)

@app.route('/buy_data', methods=['GET', 'POST'])
@login_required
def buy_data():
    # Data bundles
    bundles = [
        {'size': '250MB', 'price': 50},
        {'size': '500MB', 'price': 99},
        {'size': '1GB', 'price': 150},
        {'size': '2GB', 'price': 250},
        {'size': '5GB', 'price': 500},
        {'size': '10GB', 'price': 999},
    ]
    
    if request.method == 'POST':
        bundle_size = request.form.get('bundle_size', '').strip()
        phone = request.form.get('phone', '').strip() or current_user.phone
        amount_raw = request.form.get('amount', '').strip()
        
        try:
            amount = Decimal(amount_raw)
            if amount < 50:
                raise ValueError("Minimum data bundle is KSh 50")
        except (ValueError, Exception) as e:
            flash(f"⚠️ {str(e)}", "danger")
            return redirect(url_for('buy_data'))
        
        if not validate_phone(phone):
            flash("⚠️ Invalid phone number", "danger")
            return redirect(url_for('buy_data'))
        
        try:
            deduct_wallet(
                current_user.wallet,
                amount,
                note=f"Data {bundle_size} for {phone}",
                category="data"
            )
            
            add_loyalty_points(current_user, int(amount / 20))
            
            if current_user.role == 'agent':
                comm = calculate_commission(amount, 'data')
                commission = Commission(
                    agent_id=current_user.id,
                    transaction_type='data',
                    transaction_amount=amount,
                    commission_amount=comm,
                    reference=f"DATA{secrets.token_hex(4).upper()}"
                )
                db.session.add(commission)
                add_wallet_tx(
                    current_user.wallet,
                    "commission",
                    comm,
                    note="Commission: Data",
                    category="commission"
                )
            
            db.session.commit()
            
            flash(f"✅ Data bundle ({bundle_size}) purchased for {phone}", "success")
            
        except ValueError as e:
            flash(f"⚠️ {str(e)}", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"⚠️ Error: {str(e)}", "danger")
        
        return redirect(url_for('wallet_view'))
    
    return render_template('buy_data.html', user=current_user, bundles=bundles)

@app.route('/pay_bill', methods=['GET', 'POST'])
@login_required
def pay_bill():
    bill_types = ['Utility', 'Water', 'Electricity', 'Internet', 'TV', 'Insurance', 'Rent']
    
    if request.method == 'POST':
        account_number = request.form.get('account_number', '').strip()
        amount_raw = request.form.get('amount', '').strip()
        bill_type = request.form.get('bill_type', 'Utility').strip()
        
        try:
            amount = Decimal(amount_raw)
            if amount < 10:
                raise ValueError("Minimum payment is KSh 10")
            
            if not account_number:
                raise ValueError("Account number is required")
                
        except (ValueError, Exception) as e:
            flash(f"⚠️ {str(e)}", "danger")
            return redirect(url_for('pay_bill'))
        
        try:
            deduct_wallet(
                current_user.wallet,
                amount,
                note=f"{bill_type} bill for {account_number}",
                category="bills"
            )
            
            add_loyalty_points(current_user, int(amount / 50))
            
            if current_user.role == 'agent':
                comm = calculate_commission(amount, 'bills')
                commission = Commission(
                    agent_id=current_user.id,
                    transaction_type='bills',
                    transaction_amount=amount,
                    commission_amount=comm,
                    reference=f"BILL{secrets.token_hex(4).upper()}"
                )
                db.session.add(commission)
                add_wallet_tx(
                    current_user.wallet,
                    "commission",
                    comm,
                    note="Commission: Bill Payment",
                    category="commission"
                )
            
            db.session.commit()
            
            flash(f"✅ {bill_type} bill of KSh {amount:,.2f} paid for account {account_number}", "success")
            
        except ValueError as e:
            flash(f"⚠️ {str(e)}", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"⚠️ Error: {str(e)}", "danger")
        
        return redirect(url_for('wallet_view'))
    
    return render_template('pay_bill.html', user=current_user, bill_types=bill_types)

# ============== AGENT ROUTES ==============
@app.route('/agent/dashboard')
@login_required
@agent_required
def agent_dashboard():
    # Statistics
    total_commissions = db.session.query(
        func.sum(Commission.commission_amount)
    ).filter_by(agent_id=current_user.id).scalar() or 0
    
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_commissions = db.session.query(
        func.sum(Commission.commission_amount)
    ).filter(
        Commission.agent_id == current_user.id,
        Commission.timestamp >= today_start
    ).scalar() or 0
    
    month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_commissions = db.session.query(
        func.sum(Commission.commission_amount)
    ).filter(
        Commission.agent_id == current_user.id,
        Commission.timestamp >= month_start
    ).scalar() or 0
    
    recent_commissions = Commission.query.filter_by(
        agent_id=current_user.id
    ).order_by(Commission.timestamp.desc()).limit(10).all()
    
    # Agent float
    agent_float = AgentFloat.query.filter_by(agent_id=current_user.id).first()
    if not agent_float:
        agent_float = AgentFloat(agent_id=current_user.id, float_balance=0.00)
        db.session.add(agent_float)
        db.session.commit()
    
    return render_template(
        'agent_dashboard.html',
        user=current_user,
        total_commissions=total_commissions,
        today_commissions=today_commissions,
        month_commissions=month_commissions,
        recent_commissions=recent_commissions,
        agent_float=agent_float
    )

@app.route('/manage_services', methods=['GET', 'POST'])
@login_required
@agent_required
def manage_services():
    if request.method == 'POST':
        service_name = request.form.get('service_name', '').strip()
        category = request.form.get('category', 'utility').strip()
        commission_rate = request.form.get('commission_rate', '0').strip()
        
        try:
            if not service_name:
                raise ValueError("Service name is required")
            
            rate = Decimal(commission_rate)
            if rate < 0 or rate > 20:
                raise ValueError("Commission rate must be between 0 and 20%")
            
            new_service = Service(
                name=service_name,
                category=category,
                commission_rate=rate,
                created_by=current_user.id
            )
            db.session.add(new_service)
            db.session.commit()
            
            flash(f"✅ Service '{service_name}' added successfully", "success")
            
        except ValueError as e:
            flash(f"⚠️ {str(e)}", "danger")
        except Exception as e:
            flash(f"⚠️ Error: {str(e)}", "danger")
        
        return redirect(url_for('manage_services'))
    
    my_services = Service.query.filter_by(
        created_by=current_user.id
    ).order_by(Service.created_at.desc()).all()
    
    return render_template('manage_services.html', user=current_user, my_services=my_services)

# ============== ADMIN ROUTES ==============
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_analytics():
    # User statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    new_users_today = User.query.filter(
        User.created_at >= datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()
    
    # Transaction statistics
    total_tx_value = db.session.query(
        func.sum(WalletTx.amount)
    ).filter(WalletTx.amount > 0).scalar() or 0
    
    # Loans
    pending_loans = LoanApplication.query.filter_by(status='pending').count()
    active_loans = LoanApplication.query.filter_by(status='approved').count()
    total_loan_value = db.session.query(
        func.sum(LoanApplication.amount)
    ).filter_by(status='approved').scalar() or 0
    
    # Revenue
    total_commissions = db.session.query(
        func.sum(Commission.commission_amount)
    ).scalar() or 0
    
    # Transactions by category
    tx_by_category = db.session.query(
        WalletTx.category,
        func.count(WalletTx.id).label('count'),
        func.sum(func.abs(WalletTx.amount)).label('total')
    ).filter(
        WalletTx.category != None,
        WalletTx.amount < 0
    ).group_by(WalletTx.category).all()
    
    # Recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_loans = LoanApplication.query.order_by(LoanApplication.applied_at.desc()).limit(5).all()
    
    return render_template(
        'admin_analytics.html',
        total_users=total_users,
        active_users=active_users,
        new_users_today=new_users_today,
        total_tx_value=total_tx_value,
        pending_loans=pending_loans,
        active_loans=active_loans,
        total_loan_value=total_loan_value,
        total_commissions=total_commissions,
        tx_by_category=tx_by_category,
        recent_users=recent_users,
        recent_loans=recent_loans
    )

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    
    query = User.query
    
    if search:
        query = query.filter(
            db.or_(
                User.name.contains(search),
                User.phone.contains(search),
                User.email.contains(search)
            )
        )
    
    users_pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin_users.html', users=users_pagination.items, pagination=users_pagination, search=search)

@app.route('/admin/user/<int:user_id>/toggle_status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.role == 'admin':
        flash("⚠️ Cannot deactivate admin users", "danger")
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = "activated" if user.is_active else "deactivated"
    flash(f"✅ User {user.name} has been {status}", "success")
    
    return redirect(url_for('admin_users'))

@app.route('/admin/loans')
@login_required
@admin_required
def admin_loans():
    status_filter = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    
    query = LoanApplication.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    loans_pagination = query.order_by(LoanApplication.applied_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template(
        'admin_loans.html',
        loans=loans_pagination.items,
        pagination=loans_pagination,
        status_filter=status_filter
    )

@app.route('/admin/loan/<int:loan_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_loan(loan_id):
    loan = LoanApplication.query.get_or_404(loan_id)
    
    if loan.status != 'pending':
        flash("⚠️ Loan is not pending", "danger")
        return redirect(url_for('admin_loans'))
    
    try:
        loan.status = 'approved'
        loan.approved_at = datetime.utcnow()
        
        # Add loan amount to user wallet
        user = User.query.get(loan.user_id)
        create_wallet_for_user(user)
        add_wallet_tx(
            user.wallet,
            "loan",
            loan.amount,
            note=f"Loan approved: {loan.purpose[:50]}",
            category="loan"
        )
        
        create_notification(
            user.id,
            "✅ Loan Approved!",
            f"Your loan of KSh {loan.amount:,.2f} has been approved and credited to your wallet!",
            "success"
        )
        
        db.session.commit()
        
        flash(f"✅ Loan approved successfully", "success")
        
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('admin_loans'))

@app.route('/admin/loan/<int:loan_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_loan(loan_id):
    loan = LoanApplication.query.get_or_404(loan_id)
    
    if loan.status != 'pending':
        flash("⚠️ Loan is not pending", "danger")
        return redirect(url_for('admin_loans'))
    
    reason = request.form.get('reason', 'Not specified').strip()
    
    try:
        loan.status = 'rejected'
        
        user = User.query.get(loan.user_id)
        create_notification(
            user.id,
            "❌ Loan Rejected",
            f"Your loan application has been rejected. Reason: {reason}",
            "warning"
        )
        
        db.session.commit()
        
        flash("✅ Loan rejected", "info")
        
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('admin_loans'))

# ============== MPESA CALLBACK ==============
@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    payload = request.get_json(force=True, silent=True)
    
    try:
        body = payload.get('Body', {})
        stk = body.get('stkCallback', {})
        result_code = stk.get('ResultCode')
        checkout_request_id = stk.get('CheckoutRequestID')
        
        if result_code == 0:
            # Successful payment
            items = stk.get('CallbackMetadata', {}).get('Item', [])
            amount = None
            phone = None
            
            for it in items:
                if it.get('Name') == 'Amount':
                    amount = Decimal(it.get('Value'))
                if it.get('Name') == 'PhoneNumber':
                    phone = str(it.get('Value'))
            
            # Find pending transaction
            pending = WalletTx.query.filter_by(
                reference=checkout_request_id,
                type='deposit_pending'
            ).order_by(WalletTx.timestamp.desc()).first()
            
            if pending and amount:
                wallet = Wallet.query.get(pending.wallet_id)
                add_wallet_tx(
                    wallet,
                    "deposit",
                    amount,
                    note=f"M-Pesa deposit from {phone}",
                    reference=checkout_request_id
                )
                
                # Add loyalty points
                user = User.query.get(wallet.user_id)
                add_loyalty_points(user, int(amount / 50))
                
                create_notification(
                    wallet.user_id,
                    "💰 Deposit Successful",
                    f"KSh {amount:,.2f} has been added to your wallet",
                    "success"
                )
        else:
            # Failed payment
            pending = WalletTx.query.filter_by(
                reference=checkout_request_id,
                type='deposit_pending'
            ).order_by(WalletTx.timestamp.desc()).first()
            
            if pending:
                pending.note = f"Payment cancelled or failed (code: {result_code})"
                db.session.commit()
                
    except Exception as e:
        print(f"Callback error: {e}")
    
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})

# ============== NOTIFICATIONS ==============
@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    
    notifications_pagination = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Mark all as read
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    return render_template(
        'notifications.html',
        notifications=notifications_pagination.items,
        pagination=notifications_pagination
    )

@app.route('/notifications/<int:notif_id>/delete', methods=['POST'])
@login_required
def delete_notification(notif_id):
    notif = Notification.query.get_or_404(notif_id)
    
    if notif.user_id != current_user.id:
        abort(403)
    
    db.session.delete(notif)
    db.session.commit()
    
    flash("✅ Notification deleted", "success")
    return redirect(url_for('notifications'))

# ============== PROFILE ==============
@app.route('/profile')
@login_required
def profile():
    # Get referral statistics
    referrals = User.query.filter_by(referred_by=current_user.id).all()
    referral_earnings = len(referrals) * 100  # 100 points per referral
    
    # Get transaction statistics
    total_spent = db.session.query(
        func.sum(func.abs(WalletTx.amount))
    ).filter(
        WalletTx.wallet_id == current_user.wallet.id,
        WalletTx.amount < 0
    ).scalar() or 0
    
    total_received = db.session.query(
        func.sum(WalletTx.amount)
    ).filter(
        WalletTx.wallet_id == current_user.wallet.id,
        WalletTx.amount > 0
    ).scalar() or 0
    
    return render_template(
        'profile.html',
        user=current_user,
        referrals=referrals,
        referral_earnings=referral_earnings,
        total_spent=total_spent,
        total_received=total_received
    )

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    
    try:
        if name:
            current_user.name = name
        
        if email:
            # Check if email already exists
            existing = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing:
                raise ValueError("Email already in use")
            current_user.email = email
        
        db.session.commit()
        flash("✅ Profile updated successfully", "success")
        
    except ValueError as e:
        flash(f"⚠️ {str(e)}", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('profile'))

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    try:
        if not current_user.check_password(current_password):
            raise ValueError("Current password is incorrect")
        
        if len(new_password) < 6:
            raise ValueError("New password must be at least 6 characters")
        
        if new_password != confirm_password:
            raise ValueError("Passwords do not match")
        
        current_user.set_password(new_password)
        db.session.commit()
        
        flash("✅ Password changed successfully", "success")
        
    except ValueError as e:
        flash(f"⚠️ {str(e)}", "danger")
    except Exception as e:
        flash(f"⚠️ Error: {str(e)}", "danger")
    
    return redirect(url_for('profile'))

# ============== API ROUTES ==============
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    phone = data.get('phone', '').strip()
    password = data.get('password', '')
    
    if not phone or not password:
        return jsonify({"msg": "Phone and password required"}), 400
    
    u = User.query.filter_by(phone=phone).first()
    
    if u and u.check_password(password):
        if not u.is_active:
            return jsonify({"msg": "Account deactivated"}), 403
        
        u.last_login = datetime.utcnow()
        db.session.commit()
        
        access = create_access_token(identity=u.id, expires_delta=timedelta(days=7))
        
        return jsonify({
            "access_token": access,
            "user": {
                "id": u.id,
                "phone": u.phone,
                "name": u.name,
                "email": u.email,
                "role": u.role,
                "loyalty_points": u.loyalty_points,
                "membership_tier": u.membership_tier,
                "referral_code": u.referral_code
            }
        })
    
    return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    phone = data.get('phone', '').strip()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    referral_code = data.get('referral_code', '').strip()
    
    # Validation
    if not all([phone, name, password]):
        return jsonify({"msg": "Phone, name, and password required"}), 400
    
    if not validate_phone(phone):
        return jsonify({"msg": "Invalid phone number format"}), 400
    
    if len(password) < 6:
        return jsonify({"msg": "Password must be at least 6 characters"}), 400
    
    if User.query.filter_by(phone=phone).first():
        return jsonify({"msg": "Phone number already registered"}), 400
    
    try:
        u = User(phone=phone, name=name, email=email, role='client')
        u.set_password(password)
        u.generate_referral_code()
        
        # Handle referral
        if referral_code:
            referrer = User.query.filter_by(referral_code=referral_code).first()
            if referrer:
                u.referred_by = referrer.id
                add_loyalty_points(referrer, 100)
        
        db.session.add(u)
        db.session.commit()
        
        create_wallet_for_user(u)
        
        create_notification(
            u.id,
            "👋 Welcome!",
            f"Welcome to Mubea! Your referral code: {u.referral_code}",
            "info"
        )
        
        access = create_access_token(identity=u.id, expires_delta=timedelta(days=7))
        
        return jsonify({
            "msg": "Registration successful",
            "access_token": access,
            "user": {
                "id": u.id,
                "phone": u.phone,
                "name": u.name,
                "role": u.role,
                "referral_code": u.referral_code
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": str(e)}), 500

@app.route('/api/me', methods=['GET'])
@jwt_required()
def api_me():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    
    if not u or not u.is_active:
        return jsonify({"msg": "User not found"}), 404
    
    create_wallet_for_user(u)
    
    return jsonify({
        "id": u.id,
        "phone": u.phone,
        "name": u.name,
        "email": u.email,
        "role": u.role,
        "wallet_balance": float(u.wallet.balance),
        "loyalty_points": u.loyalty_points,
        "membership_tier": u.membership_tier,
        "referral_code": u.referral_code,
        "created_at": u.created_at.isoformat(),
        "last_login": u.last_login.isoformat() if u.last_login else None
    })

@app.route('/api/wallet/transactions', methods=['GET'])
@jwt_required()
def api_wallet_transactions():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    create_wallet_for_user(u)
    
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    txs = WalletTx.query.filter_by(
        wallet_id=u.wallet.id
    ).order_by(WalletTx.timestamp.desc()).limit(limit).offset(offset).all()
    
    return jsonify({
        "transactions": [{
            "id": tx.id,
            "type": tx.type,
            "amount": float(tx.amount),
            "note": tx.note,
            "category": tx.category,
            "timestamp": tx.timestamp.isoformat(),
            "reference": tx.reference
        } for tx in txs],
        "count": len(txs)
    })

@app.route('/api/transfer', methods=['POST'])
@jwt_required()
def api_p2p_transfer():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    
    data = request.get_json()
    receiver_phone = data.get('receiver_phone', '').strip()
    amount_raw = data.get('amount')
    note = data.get('note', '').strip()
    
    try:
        amount = Decimal(str(amount_raw))
        
        if amount <= 0:
            return jsonify({"msg": "Amount must be positive"}), 400
        
        if not validate_phone(receiver_phone):
            return jsonify({"msg": "Invalid phone number"}), 400
        
        receiver = User.query.filter_by(phone=receiver_phone).first()
        if not receiver:
            return jsonify({"msg": "Receiver not found"}), 404
        
        if receiver.id == u.id:
            return jsonify({"msg": "Cannot transfer to yourself"}), 400
        
        if Decimal(u.wallet.balance) < amount:
            return jsonify({"msg": "Insufficient balance"}), 400
        
        reference = f"P2P{secrets.token_hex(6).upper()}"
        
        # Deduct from sender
        deduct_wallet(
            u.wallet,
            amount,
            note=f"Transfer to {receiver.name}",
            reference=reference,
            category="transfer"
        )
        
        # Add to receiver
        create_wallet_for_user(receiver)
        add_wallet_tx(
            receiver.wallet,
            "p2p_receive",
            amount,
            note=f"From {u.name}",
            reference=reference,
            category="transfer"
        )
        
        # Record transfer
        transfer = P2PTransfer(
            sender_id=u.id,
            receiver_id=receiver.id,
            amount=amount,
            note=note,
            reference=reference
        )
        db.session.add(transfer)
        
        add_loyalty_points(u, int(amount / 100))
        
        create_notification(
            receiver.id,
            "💰 Money Received",
            f"You received KSh {amount:,.2f} from {u.name}",
            "success"
        )
        
        db.session.commit()
        
        return jsonify({
            "msg": "Transfer successful",
            "reference": reference,
            "amount": float(amount),
            "receiver": receiver.name
        })
        
    except ValueError as e:
        return jsonify({"msg": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": str(e)}), 500

@app.route('/api/services/airtime', methods=['POST'])
@jwt_required()
def api_buy_airtime():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    
    data = request.get_json()
    phone = data.get('phone', u.phone).strip()
    amount_raw = data.get('amount')
    
    try:
        amount = Decimal(str(amount_raw))
        
        if amount < 10:
            return jsonify({"msg": "Minimum airtime is KSh 10"}), 400
        
        if not validate_phone(phone):
            return jsonify({"msg": "Invalid phone number"}), 400
        
        deduct_wallet(u.wallet, amount, note=f"Airtime for {phone}", category="airtime")
        add_loyalty_points(u, int(amount / 20))
        
        db.session.commit()
        
        return jsonify({
            "msg": "Airtime purchased successfully",
            "amount": float(amount),
            "phone": phone
        })
        
    except ValueError as e:
        return jsonify({"msg": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": str(e)}), 500

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def api_notifications():
    uid = get_jwt_identity()
    
    limit = request.args.get('limit', 20, type=int)
    unread_only = request.args.get('unread_only', False, type=bool)
    
    query = Notification.query.filter_by(user_id=uid)
    
    if unread_only:
        query = query.filter_by(is_read=False)
    
    notifications = query.order_by(Notification.created_at.desc()).limit(limit).all()
    
    return jsonify({
        "notifications": [{
            "id": n.id,
            "title": n.title,
            "message": n.message,
            "type": n.type,
            "is_read": n.is_read,
            "created_at": n.created_at.isoformat()
        } for n in notifications],
        "count": len(notifications)
    })

@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
@jwt_required()
def api_mark_notification_read(notif_id):
    uid = get_jwt_identity()
    notif = Notification.query.get_or_404(notif_id)
    
    if notif.user_id != uid:
        return jsonify({"msg": "Unauthorized"}), 403
    
    notif.is_read = True
    db.session.commit()
    
    return jsonify({"msg": "Notification marked as read"})

# ============== ERROR HANDLERS ==============
@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith('/api/'):
        return jsonify({"msg": "Forbidden"}), 403
    flash("⚠️ You don't have permission to access this page", "danger")
    return redirect(url_for('home'))

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"msg": "Not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({"msg": "Internal server error"}), 500
    flash("⚠️ An error occurred. Please try again.", "danger")
    return redirect(url_for('home'))

# ============== CONTEXT PROCESSORS ==============
@app.context_processor
def utility_processor():
    return {
        'format_currency': format_currency,
        'now': datetime.now
    }

# ============== INITIALIZATION ==============
def init_database():
    """Initialize database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create admin user
        if not User.query.filter_by(role='admin').first():
            admin = User(
                phone="254700000000",
                name="Administrator",
                role="admin",
                email="admin@mubea.com"
            )
            admin.set_password("Admin@123")
            admin.generate_referral_code()
            db.session.add(admin)
            db.session.commit()
            create_wallet_for_user(admin)
            print("✅ Admin user created: 254700000000 / Admin@123")
        
        # Create sample agent
        if not User.query.filter_by(phone="254711111111").first():
            agent = User(
                phone="254711111111",
                name="Sample Agent",
                role="agent",
                email="agent@mubea.com"
            )
            agent.set_password("Agent@123")
            agent.generate_referral_code()
            db.session.add(agent)
            db.session.commit()
            create_wallet_for_user(agent)
            
            # Create agent float
            agent_float = AgentFloat(agent_id=agent.id, float_balance=10000.00)
            db.session.add(agent_float)
            db.session.commit()
            print("✅ Agent user created: 254711111111 / Agent@123")
        
        # Create sample client
        if not User.query.filter_by(phone="254722222222").first():
            client = User(
                phone="254722222222",
                name="Demo User",
                role="client",
                email="demo@mubea.com"
            )
            client.set_password("Demo@123")
            client.generate_referral_code()
            db.session.add(client)
            db.session.commit()
            wallet = create_wallet_for_user(client)
            
            # Add sample balance
            add_wallet_tx(wallet, "deposit", Decimal("1000.00"), note="Welcome bonus")
            
            # Create sample notification
            create_notification(
                client.id,
                "👋 Welcome!",
                "Welcome to Mubea! Enjoy your welcome bonus of KSh 1,000",
                "success"
            )
            print("✅ Demo user created: 254722222222 / Demo@123")
        
        print("✅ Database initialized successfully!")

if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)
