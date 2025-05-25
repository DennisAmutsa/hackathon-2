from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from dotenv import load_dotenv
from functools import wraps
import speech_recognition as sr
import pytesseract
from PIL import Image
import io
import base64
import re

# Configure Tesseract path
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Load environment variables
load_dotenv()

# Database configuration
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_NAME = os.getenv('DB_NAME', 'storefront_builder')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create .env file if it doesn't exist
if not os.path.exists('.env'):
    with open('.env', 'w') as f:
        f.write(f"""# Database Configuration
DB_HOST={DB_HOST}
DB_USER={DB_USER}
DB_PASSWORD={DB_PASSWORD}
DB_NAME={DB_NAME}

# Flask Configuration
SECRET_KEY={app.config['SECRET_KEY']}
""")
    print("Created .env file with default configuration. Please update the values as needed.")

# Role-based access control
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    preferences = db.relationship('UserPreference', backref='user', uselist=False, lazy=True)
    categories = db.relationship('Category', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role):
        return self.role == role

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    source_type = db.Column(db.String(20))
    
    # Relationships
    categories = db.relationship('Category', secondary='transaction_categories', backref='transactions')

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'type': self.type,
            'description': self.description,
            'date': self.date.strftime('%Y-%m-%d %H:%M'),
            'user_id': self.user_id,
            'source_type': self.source_type
        }

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class UserPreference(db.Model):
    __tablename__ = 'user_preferences'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    currency = db.Column(db.String(3), default='USD')
    language = db.Column(db.String(5), default='en')
    theme = db.Column(db.String(20), default='light')
    notification_enabled = db.Column(db.Boolean, default=True)

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(50), nullable=False)
    table_name = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.relationship('User', backref='audit_logs', lazy=True)

# Create transaction_categories association table
transaction_categories = db.Table('transaction_categories',
    db.Column('transaction_id', db.Integer, db.ForeignKey('transactions.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('categories.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions for voice and photo input
def process_voice_input(audio_data):
    try:
        recognizer = sr.Recognizer()
        # Decode base64 audio data to bytes
        audio_data = audio_data.split(',')[1] if ',' in audio_data else audio_data
        audio_bytes = base64.b64decode(audio_data)
        # sr.AudioData expects bytes, sample_rate, and sample_width
        audio = sr.AudioData(audio_bytes, sample_rate=44100, sample_width=2)
        text = recognizer.recognize_google(audio)
        
        # Extract amount and type from voice input
        amount_match = re.search(r'\$?(\d+(?:\.\d{2})?)', text)
        amount = float(amount_match.group(1)) if amount_match else None
        
        type_match = re.search(r'(income|expense|spent|received)', text.lower())
        type = 'income' if type_match and type_match.group(1) in ['income', 'received'] else 'expense'
        
        return {
            'amount': amount,
            'type': type,
            'description': text
        }
    except Exception as e:
        return {'error': str(e)}

def process_photo_input(image_data):
    try:
        # Convert base64 to image
        image_data = image_data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        
        # Extract text using OCR
        text = pytesseract.image_to_string(image)
        
        # Extract amount and type from OCR text
        amount_match = re.search(r'\$?(\d+(?:\.\d{2})?)', text)
        amount = float(amount_match.group(1)) if amount_match else None
        
        type_match = re.search(r'(income|expense|spent|received)', text.lower())
        type = 'income' if type_match and type_match.group(1) in ['income', 'received'] else 'expense'
        
        return {
            'amount': amount,
            'type': type,
            'description': text[:200]  # Limit description length
        }
    except Exception as e:
        return {'error': str(e)}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')  # Default role is 'user'
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # Audit log for user creation
        log_audit(
            current_user.id if current_user.is_authenticated else user.id,
            'create',
            'users',
            user.id,
            old_value=None,
            new_value={
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        )
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            # Log login event
            log_audit(
                user.id,
                'login',
                'users',
                user.id,
                old_value=None,
                new_value=None
            )
            flash(f'Welcome back, {user.username}!', 'success')
            if user.role == 'admin':
                return redirect(url_for('dashboard'))
            elif user.role == 'manager':
                return redirect(url_for('manager_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    recent_transactions = Transaction.query.filter_by(user_id=current_user.id)\
        .order_by(Transaction.date.desc())\
        .limit(10)\
        .all()
    return render_template('profile.html', recent_transactions=recent_transactions)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    
    if username != current_user.username and User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('profile'))
    
    if email != current_user.email and User.query.filter_by(email=email).first():
        flash('Email already registered', 'danger')
        return redirect(url_for('profile'))
    
    current_user.username = username
    current_user.email = email
    db.session.commit()
    
    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))
    
    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/process_voice', methods=['POST'])
@login_required
def process_voice():
    audio_data = request.json.get('audio_data')
    if not audio_data:
        return jsonify({'error': 'No audio data provided'}), 400
    
    result = process_voice_input(audio_data)
    if 'error' in result:
        return jsonify({'error': result['error']}), 400
    
    return jsonify(result)

@app.route('/process_photo', methods=['POST'])
@login_required
def process_photo():
    image_data = request.json.get('image_data')
    if not image_data:
        return jsonify({'error': 'No image data provided'}), 400
    
    result = process_photo_input(image_data)
    if 'error' in result:
        return jsonify({'error': result['error']}), 400
    
    return jsonify(result)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        transactions = Transaction.query.order_by(Transaction.date.desc()).all()
        categories = Category.query.all()
        total_income = sum(t.amount for t in transactions if t.type == 'income')
        total_expense = sum(t.amount for t in transactions if t.type == 'expense')
        net_amount = total_income - total_expense
        return render_template(
            'dashboard.html',
            transactions=transactions,
            categories=categories,
            total_income=total_income,
            total_expense=total_expense,
            net_amount=net_amount
        )
    elif current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/manager/dashboard')
@login_required
@role_required(['admin', 'manager'])
def manager_dashboard():
    # Get all transactions (own and team)
    transactions = Transaction.query.filter(
        (Transaction.user_id == current_user.id) |
        (Transaction.user_id.in_([u.id for u in User.query.filter_by(role='user').all()]))
    ).order_by(Transaction.date.desc()).all()
    
    # Get categories (both income and expense)
    categories = Category.query.filter(
        (Category.user_id == current_user.id) |
        (Category.user_id == None)
    ).order_by(Category.type, Category.name).all()
    
    # Get user activity (recent transactions by users)
    user_activity = Transaction.query.join(User).filter(
        User.role == 'user'
    ).order_by(Transaction.date.desc()).limit(10).all()
    
    # Get transaction statistics
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expense = sum(t.amount for t in transactions if t.type == 'expense')
    net_amount = total_income - total_expense
    
    return render_template('manager_dashboard.html',
                         transactions=transactions,
                         categories=categories,
                         user_activity=user_activity,
                         total_income=total_income,
                         total_expense=total_expense,
                         net_amount=net_amount)

@app.route('/add_transaction', methods=['POST'])
@login_required
def add_transaction():
    amount_str = request.form.get('amount')
    if not amount_str:
        flash('Amount is required!', 'danger')
        return redirect(url_for('dashboard'))
    try:
        amount = float(amount_str)
    except ValueError:
        flash('Amount must be a number!', 'danger')
        return redirect(url_for('dashboard'))

    type = request.form.get('type')
    description = request.form.get('description')
    source_type = request.form.get('source_type', 'manual')
    category_id = request.form.get('category')
    category = Category.query.get(category_id) if category_id else None

    transaction = Transaction(
        amount=amount,
        type=type,
        description=description,
        user_id=current_user.id,
        source_type=source_type
    )
    if category:
        transaction.categories.append(category)
    db.session.add(transaction)
    db.session.commit()
    # Audit log for transaction creation
    log_audit(current_user.id, 'create', 'transactions', transaction.id, old_value=None, new_value=transaction.to_dict())

    flash('Transaction added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    data = request.get_json()
    name = data.get('name', '').strip()
    type_ = data.get('type', 'expense')
    
    # Validate type
    if type_ not in ['income', 'expense']:
        return jsonify({
            'success': False,
            'message': 'Invalid category type. Must be either "income" or "expense"'
        })
    
    if not name:
        return jsonify({'success': False, 'message': 'Category name is required'})
    
    # Check if category already exists for this user
    existing = Category.query.filter_by(
        name=name,
        user_id=current_user.id,
        type=type_
    ).first()
    
    if existing:
        return jsonify({
            'success': True,
            'id': existing.id,
            'name': existing.name,
            'type': existing.type
        })
    
    # Create new category
    category = Category(
        name=name,
        type=type_,
        user_id=current_user.id
    )
    
    try:
        db.session.add(category)
        db.session.commit()
        return jsonify({
            'success': True,
            'id': category.id,
            'name': category.name,
            'type': category.type
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/admin/users')
@login_required
@role_required(['admin'])
def admin_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/audit-log')
@login_required
@role_required(['admin', 'manager'])
def audit_log():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()
    return render_template('audit_log.html', logs=logs)

@app.route('/admin/dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    transactions = Transaction.query.order_by(Transaction.date.desc()).all()
    categories = Category.query.order_by(Category.type, Category.name).all()
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expense = sum(t.amount for t in transactions if t.type == 'expense')
    net_amount = total_income - total_expense
    return render_template('dashboard.html',
        transactions=transactions,
        categories=categories,
        total_income=total_income,
        total_expense=total_expense,
        net_amount=net_amount)

def log_audit(user_id, action, table_name, record_id, old_value=None, new_value=None):
    log = AuditLog(
        user_id=user_id,
        action=action,
        table_name=table_name,
        record_id=record_id,
        old_value=str(old_value) if old_value else None,
        new_value=str(new_value) if new_value else None
    )
    db.session.add(log)
    db.session.commit()

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        old = {
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        log_audit(
            current_user.id,
            'update',
            'users',
            user.id,
            old_value=old,
            new_value={
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        )
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    old = {
        'username': user.username,
        'email': user.email,
        'role': user.role
    }
    db.session.delete(user)
    db.session.commit()
    log_audit(
        current_user.id,
        'delete',
        'users',
        user.id,
        old_value=old,
        new_value=None
    )
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/logout')
@login_required
def logout():
    # Log logout event
    log_audit(
        current_user.id,
        'logout',
        'users',
        current_user.id,
        old_value=None,
        new_value=None
    )
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/manager/team')
@login_required
@role_required(['admin', 'manager'])
def team():
    team_members = User.query.filter_by(role='user').all()
    return render_template('team.html', team_members=team_members)

@app.route('/manager/user/<int:user_id>/transactions')
@login_required
@role_required(['admin', 'manager'])
def user_transactions(user_id):
    user = User.query.get_or_404(user_id)
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()
    return render_template('user_transactions.html', user=user, transactions=transactions)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('You do not have access to the user dashboard.', 'danger')
        return redirect(url_for('dashboard'))
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    categories = Category.query.filter((Category.user_id == current_user.id) | (Category.user_id == None)).all()
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expense = sum(t.amount for t in transactions if t.type == 'expense')
    net_amount = total_income - total_expense
    return render_template('user_dashboard.html',
        transactions=transactions,
        categories=categories,
        total_income=total_income,
        total_expense=total_expense,
        net_amount=net_amount)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
