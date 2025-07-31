# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import os
from decimal import Decimal

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    wallet = db.relationship('Wallet', backref='user', uselist=False, cascade='all, delete-orphan')
    deposits = db.relationship('Deposit', backref='user', lazy=True, cascade='all, delete-orphan')
    withdrawals = db.relationship('Withdrawal', backref='user', lazy=True, cascade='all, delete-orphan')

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Numeric(10, 2), default=0.00)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Deposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    screenshot_path = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    admin_comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    upi_id = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    admin_comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def approved_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_approved:
            flash('Your account is pending admin approval.', 'warning')
            return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_approved:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('pending_approval'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            phone=phone
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/pending_approval')
@login_required
def pending_approval():
    if current_user.is_approved:
        return redirect(url_for('dashboard'))
    return render_template('pending_approval.html')

@app.route('/dashboard')
@login_required
@approved_required
def dashboard():
    wallet = current_user.wallet
    recent_deposits = Deposit.query.filter_by(user_id=current_user.id).order_by(Deposit.created_at.desc()).limit(5).all()
    recent_withdrawals = Withdrawal.query.filter_by(user_id=current_user.id).order_by(Withdrawal.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                         wallet=wallet, 
                         deposits=recent_deposits, 
                         withdrawals=recent_withdrawals)

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
@approved_required
def deposit():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        screenshot = request.files['screenshot']
        
        if screenshot and screenshot.filename:
            filename = secure_filename(f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{screenshot.filename}")
            screenshot_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            screenshot.save(screenshot_path)
            
            deposit = Deposit(
                user_id=current_user.id,
                amount=amount,
                screenshot_path=screenshot_path
            )
            
            db.session.add(deposit)
            db.session.commit()
            
            flash('Deposit request submitted successfully! Awaiting admin approval.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Please upload a screenshot of the payment.', 'error')
    
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
@approved_required
def withdraw():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        upi_id = request.form['upi_id']
        
        # Check if user has sufficient balance
        if not current_user.wallet or current_user.wallet.balance < Decimal(str(amount)):
            flash('Insufficient balance', 'error')
            return redirect(url_for('withdraw'))
        
        withdrawal = Withdrawal(
            user_id=current_user.id,
            amount=amount,
            upi_id=upi_id
        )
        
        db.session.add(withdrawal)
        db.session.commit()
        
        flash('Withdrawal request submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('withdraw.html')

# Admin Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    pending_users = User.query.filter_by(is_approved=False, is_admin=False).all()
    pending_deposits = Deposit.query.filter_by(status='pending').all()
    pending_withdrawals = Withdrawal.query.filter_by(status='pending').all()
    
    return render_template('admin/dashboard.html',
                         pending_users=pending_users,
                         pending_deposits=pending_deposits,
                         pending_withdrawals=pending_withdrawals)

@app.route('/admin/approve_user/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    
    # Create wallet for the user
    if not user.wallet:
        wallet = Wallet(user_id=user.id)
        db.session.add(wallet)
    
    db.session.commit()
    flash(f'User {user.username} approved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_user/<int:user_id>')
@login_required
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User registration rejected and deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deposit/<int:deposit_id>/<action>')
@login_required
@admin_required
def process_deposit(deposit_id, action):
    deposit = Deposit.query.get_or_404(deposit_id)
    
    if action == 'approve':
        deposit.status = 'approved'
        deposit.processed_at = datetime.utcnow()
        
        # Add amount to user's wallet
        if not deposit.user.wallet:
            wallet = Wallet(user_id=deposit.user.id)
            db.session.add(wallet)
            db.session.flush()
        
        deposit.user.wallet.balance += deposit.amount
        deposit.user.wallet.updated_at = datetime.utcnow()
        
        flash(f'Deposit of ₹{deposit.amount} approved for {deposit.user.username}', 'success')
        
    elif action == 'reject':
        deposit.status = 'rejected'
        deposit.processed_at = datetime.utcnow()
        flash(f'Deposit of ₹{deposit.amount} rejected for {deposit.user.username}', 'success')
    
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/withdrawal/<int:withdrawal_id>/<action>')
@login_required
@admin_required
def process_withdrawal(withdrawal_id, action):
    withdrawal = Withdrawal.query.get_or_404(withdrawal_id)
    
    if action == 'approve':
        # Check if user still has sufficient balance
        if withdrawal.user.wallet.balance >= withdrawal.amount:
            withdrawal.status = 'approved'
            withdrawal.processed_at = datetime.utcnow()
            
            # Deduct amount from user's wallet
            withdrawal.user.wallet.balance -= withdrawal.amount
            withdrawal.user.wallet.updated_at = datetime.utcnow()
            
            flash(f'Withdrawal of ₹{withdrawal.amount} approved for {withdrawal.user.username}', 'success')
        else:
            flash('User has insufficient balance for this withdrawal', 'error')
            return redirect(url_for('admin_dashboard'))
            
    elif action == 'reject':
        withdrawal.status = 'rejected'
        withdrawal.processed_at = datetime.utcnow()
        flash(f'Withdrawal of ₹{withdrawal.amount} rejected for {withdrawal.user.username}', 'success')
    
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/transactions')
@login_required
@admin_required
def admin_transactions():
    deposits = Deposit.query.order_by(Deposit.created_at.desc()).all()
    withdrawals = Withdrawal.query.order_by(Withdrawal.created_at.desc()).all()
    return render_template('admin/transactions.html', deposits=deposits, withdrawals=withdrawals)

# Initialize database and create admin user
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                phone='1234567890',
                is_admin=True,
                is_approved=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created - Username: admin, Password: admin123")

if __name__ == '__main__':
    init_db()  # Initialize database before running the app
    app.run(debug=True)