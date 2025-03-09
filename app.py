from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import json
from flask_mail import Mail, Message as FlaskMessage
from itsdangerous import URLSafeTimedSerializer
import queue
import threading
from collections import deque
import time
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = '370245c7ef36438d947a8e5b3415c389b4e27326d72407c7'  # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Maximum upload size: 16MB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'abdullacoc40@gmail.com'
app.config['MAIL_PASSWORD'] = 'ozvd hzlc tqdh ycbt'
app.config['MAIL_DEFAULT_SENDER'] = 'abdullacoc40@gmail.com'

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Initialize Flask-Mail
mail = Mail(app)

# Create serializer for tokens
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# Allowed extensions for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Replace the existing get_queue function and message_queues definition
message_queues = {}  # Global dictionary to hold all queues

def get_queue(chat_id):
    """Get or create a queue for a specific chat"""
    if chat_id not in message_queues:
        message_queues[chat_id] = queue.Queue()
    return message_queues[chat_id]

# User model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique user ID
    username = db.Column(db.String(150), unique=True, nullable=False)  # Username
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    date_of_birth = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Email
    password = db.Column(db.String(150), nullable=False)  # Hashed password
    profile_pic = db.Column(db.String(300), default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)  # User's posts
    # Sent friend requests
    sent_friend_requests = db.relationship('Friendship',
        foreign_keys='Friendship.user_id',
        backref='sender',
        lazy='dynamic',
        overlaps="user"
    )
    # Received friend requests
    received_friend_requests = db.relationship('Friendship',
        foreign_keys='Friendship.friend_id',
        backref='receiver',
        lazy='dynamic',
        overlaps="friend"
    )
    notifications = db.relationship('Notification', backref='user', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    # Simplified comment relationship
    comments = db.relationship('Comment', backref='author', lazy=True)
    # Add these relationships for messages
    messages_sent = db.relationship('Message',
        foreign_keys='Message.sender_id',
        backref='sender_user',
        lazy='dynamic',
        overlaps="sent_messages,sender"
    )
    messages_received = db.relationship('Message',
        foreign_keys='Message.receiver_id',
        backref='receiver_user',
        lazy='dynamic',
        overlaps="received_messages,receiver"
    )
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_sent_at = db.Column(db.DateTime)
    # Add these new relationships
    admin_of_groups = db.relationship('GroupChat', backref='admin', lazy=True,
                                    foreign_keys='GroupChat.admin_id')
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)
    
    # This is already in Message but needs to be updated here as well
    sent_messages = db.relationship('Message',
        foreign_keys='Message.sender_id',
        primaryjoin="User.id==Message.sender_id",
        backref=db.backref('sender', overlaps="messages_sent,sender_user"),
        lazy='dynamic',
        overlaps="messages_sent,sender_user"
    )
    
    received_messages = db.relationship('Message',
        foreign_keys='Message.receiver_id',
        primaryjoin="User.id==Message.receiver_id",
        backref=db.backref('receiver', overlaps="messages_received,receiver_user"),
        lazy='dynamic',
        overlaps="messages_received,receiver_user"
    )

# Post model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique post ID
    content = db.Column(db.Text, nullable=False)  # Post content
    image = db.Column(db.String(300), nullable=True)  # Image filename
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Time of creation
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Author's user ID
    likes = db.relationship('Like', backref='post', lazy=True)
    comments = db.relationship('Comment', backref='post', lazy=True)

# Friendship model
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique friendship ID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # One user
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # The other user
    status = db.Column(db.String(10), default='pending')  # 'pending' or 'accepted'
    friend = db.relationship('User', 
        foreign_keys=[friend_id], 
        backref=db.backref('friend_friendships', overlaps="received_friend_requests,receiver"),
        overlaps="receiver"
    )
    user = db.relationship('User', 
        foreign_keys=[user_id], 
        backref=db.backref('user_friendships', overlaps="sent_friend_requests,sender"),
        overlaps="sender"
    )

# Notification model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(20))  # 'friend_request', 'like', 'comment'
    related_id = db.Column(db.Integer)  # ID of related object (post_id, friendship_id, etc.)

# Like model
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Remove the duplicate relationships and rely only on User's relationships
    # We don't need both User.sent_messages and Message.sender, etc.

# Load user callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# WTForms for Registration
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=150)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=150)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=150)])
    date_of_birth = StringField('Date of Birth', validators=[InputRequired()])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# WTForms for Login
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=150)])
    submit = SubmitField('Login')

# WTForms for creating a post
class PostForm(FlaskForm):
    content = TextAreaField('Content', validators=[InputRequired(), Length(max=500)])
    image = FileField('Image')
    submit = SubmitField('Post')

# Route for the home page
@app.route('/')
@login_required
def index():
    # Get all accepted friendships where current user is involved
    friendships = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) &
        (Friendship.status == 'accepted')
    ).all()
    
    # Get list of friend IDs
    friend_ids = []
    for friendship in friendships:
        if friendship.user_id == current_user.id:
            friend_ids.append(friendship.friend_id)
        else:
            friend_ids.append(friendship.user_id)
    
    # Add current user's ID to see their own posts too
    friend_ids.append(current_user.id)
    
    # Fetch posts from friends and current user, ordered by timestamp descending
    posts = Post.query.filter(Post.user_id.in_(friend_ids)).order_by(Post.timestamp.desc()).all()
    
    return render_template('index.html', posts=posts)

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Get form data
        username = form.username.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data
        bio = form.bio.data
        # Convert date string to Date object
        date_of_birth = datetime.strptime(form.date_of_birth.data, '%Y-%m-%d').date()

        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create a new user instance
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            bio=bio,
            date_of_birth=date_of_birth
        )

        # Add to the database
        db.session.add(new_user)
        db.session.commit()
        
        # Send verification email
        send_verification_email(new_user)
        
        flash('Registration successful! Please check your email (including spam folder) to verify your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                flash('Please verify your email address first. Check your inbox for the verification link.', 'warning')
                return render_template('login.html', form=form)
            
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form)

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route for user profile
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    user_posts = Post.query.filter_by(user_id=user.id).order_by(Post.timestamp.desc()).all()
    return render_template('profile.html', user=user, posts=user_posts)

# Route to create a new post
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        content = form.content.data
        image = form.image.data
        
        if image and allowed_file(image.filename):
            filename = secure_filename(f"post_{current_user.id}_{int(datetime.utcnow().timestamp())}.{image.filename.rsplit('.', 1)[1].lower()}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None
        
        post = Post(content=content, image=filename, author=current_user)
        db.session.add(post)
        db.session.commit()
        
        flash('Post created successfully!', 'success')
        return redirect(url_for('index'))
        
    return render_template('create_post.html', form=form)

# Route for friends management
@app.route('/friends')
@login_required
def friends():
    # Fetch all friendships where current user is involved and status is accepted
    friendships = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) & 
        (Friendship.status == 'accepted')
    ).all()

    friends = []
    for friendship in friendships:
        if friendship.user_id == current_user.id:
            friends.append(User.query.get(friendship.friend_id))
        else:
            friends.append(User.query.get(friendship.user_id))
    
    return render_template('friends.html', friends=friends)

# Route to send a friend request
@app.route('/send_friend_request/<int:user_id>')
@login_required
def send_friend_request(user_id):
    # Check if friendship already exists
    existing_friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user_id)) |
        ((Friendship.user_id == user_id) & (Friendship.friend_id == current_user.id))
    ).first()

    if existing_friendship:
        flash('Friend request already sent or you are already friends.', 'info')
    else:
        # Create a new friendship with status 'pending'
        new_friendship = Friendship(user_id=current_user.id, friend_id=user_id, status='pending')
        db.session.add(new_friendship)
        db.session.commit()
        
        # Create notification for friend request
        notification = Notification(
            user_id=user_id,
            content=f"{current_user.username} sent you a friend request",
            notification_type='friend_request',
            related_id=new_friendship.id
        )
        db.session.add(notification)
        db.session.commit()
        
        flash('Friend request sent.', 'success')
    
    return redirect(url_for('profile', user_id=user_id))

# Route to accept a friend request
@app.route('/accept_friend_request/<int:friendship_id>')
@login_required
def accept_friend_request(friendship_id):
    friendship = Friendship.query.get_or_404(friendship_id)
    if friendship.friend_id != current_user.id:
        flash('You are not authorized to accept this request.', 'danger')
        return redirect(url_for('friends'))
    
    friendship.status = 'accepted'
    
    # Create notification for the user who sent the request
    notification = Notification(
        user_id=friendship.user_id,
        content=f"{current_user.username} accepted your friend request",
        notification_type='friend_accepted',
        related_id=friendship.id
    )
    db.session.add(notification)
    db.session.commit()
    
    flash('Friend request accepted.', 'success')
    return redirect(url_for('friends'))

# Route for searching users and groups
@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('q')
    if query:
        # Search users
        users = User.query.filter(User.username.ilike(f'%{query}%')).all()
    else:
        users = []
    return render_template('search.html', users=users, query=query)

# Route for notifications
@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.timestamp.desc()).all()
    
    # Mark all notifications as read
    for notification in notifications:
        notification.read = True
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

# Route for friend requests
@app.route('/friend_requests')
@login_required
def friend_requests():
    pending_requests = Friendship.query.filter_by(
        friend_id=current_user.id,
        status='pending'
    ).all()
    return render_template('friend_requests.html', requests=pending_requests)

# Route for liking/unliking posts
@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(
        user_id=current_user.id,
        post_id=post_id
    ).first()

    if like:
        # Unlike
        db.session.delete(like)
        db.session.commit()
        return jsonify({'status': 'unliked', 'likes': len(post.likes)})
    else:
        # Like
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        
        # Create notification for post author
        if post.user_id != current_user.id:
            notification = Notification(
                user_id=post.user_id,
                content=f"{current_user.username} liked your post",
                notification_type='like',
                related_id=post_id
            )
            db.session.add(notification)
        
        db.session.commit()
        return jsonify({'status': 'liked', 'likes': len(post.likes)})

# Route for adding comments
@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form.get('content')
    if not content:
        flash('Comment cannot be empty', 'danger')
        return redirect(url_for('index'))

    post = Post.query.get_or_404(post_id)
    
    comment = Comment(
        content=content,
        user_id=current_user.id,
        post_id=post_id
    )
    db.session.add(comment)

    # Create notification for post author if it's not their own post
    if post.user_id != current_user.id:
        notification = Notification(
            user_id=post.user_id,
            content=f"{current_user.username} commented on your post",
            notification_type='comment',
            related_id=post_id
        )
        db.session.add(notification)

    db.session.commit()
    return redirect(url_for('index'))

# Route for rejecting a friend request
@app.route('/reject_friend_request/<int:friendship_id>')
@login_required
def reject_friend_request(friendship_id):
    friendship = Friendship.query.get_or_404(friendship_id)
    if friendship.friend_id != current_user.id:
        flash('You are not authorized to reject this request.', 'danger')
        return redirect(url_for('friend_requests'))
    
    # Delete the friendship request
    db.session.delete(friendship)
    db.session.commit()
    
    flash('Friend request rejected.', 'info')
    return redirect(url_for('friend_requests'))

# Add this after your models but before the routes
def get_friendship_status(user1_id, user2_id):
    """Check friendship status between two users"""
    return Friendship.query.filter(
        ((Friendship.user_id == user1_id) & (Friendship.friend_id == user2_id)) |
        ((Friendship.user_id == user2_id) & (Friendship.friend_id == user1_id))
    ).first()

# Add this to make the function available in templates
app.jinja_env.globals.update(get_friendship_status=get_friendship_status)

# Add this route for updating profile picture
@app.route('/update_profile_pic', methods=['POST'])
@login_required
def update_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('profile', user_id=current_user.id))
    
    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile', user_id=current_user.id))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"profile_{current_user.id}_{int(datetime.utcnow().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Update user's profile picture
        current_user.profile_pic = filename
        db.session.commit()
        
        flash('Profile picture updated successfully', 'success')
    else:
        flash('Invalid file type', 'danger')
    
    return redirect(url_for('profile', user_id=current_user.id))

# Add these routes
@app.route('/messages')
@login_required
def messages():
    # Get all friends
    friends = User.query.join(Friendship, (
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == User.id)) |
        ((Friendship.friend_id == current_user.id) & (Friendship.user_id == User.id))
    )).filter(Friendship.status == 'accepted').all()
    
    return render_template('messages.html', 
                         friends=friends,
                         current_chat=None,  # No chat selected initially
                         chat_user=None)     # No chat user initially

@app.route('/conversation/<int:user_id>')
@login_required
def conversation(user_id):
    chat_user = User.query.get_or_404(user_id)
    
    # Get messages between current user and chat user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Get all friends for the sidebar
    friends = User.query.join(Friendship, (
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == User.id)) |
        ((Friendship.friend_id == current_user.id) & (Friendship.user_id == User.id))
    )).filter(Friendship.status == 'accepted').all()
    
    # Mark messages as read
    for message in messages:
        if message.receiver_id == current_user.id and not message.read:
            message.read = True
    db.session.commit()
    
    return render_template('messages.html', 
                         friends=friends,
                         messages=messages,
                         current_chat=chat_user,
                         chat_user=chat_user)  # Pass chat_user for SSE

@app.route('/send_message/<int:receiver_id>', methods=['POST'])
@login_required
def send_message(receiver_id):
    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    message = Message(
        content=content,
        sender_id=current_user.id,
        receiver_id=receiver_id
    )
    db.session.add(message)
    db.session.commit()
    
    # Prepare message data for both sender and receiver
    message_data = {
        'id': message.id,
        'content': message.content,
        'sender_id': message.sender_id,
        'sender_username': current_user.username,
        'timestamp': message.timestamp.strftime('%H:%M'),
        'sender_profile_pic': current_user.profile_pic
    }
    
    # Add message to both users' queues
    for user_id in [current_user.id, receiver_id]:
        q = get_queue(f'private_{user_id}')
        q.put(message_data)
    
    return jsonify(message_data)

# Add new routes for email verification
@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = ts.loads(token, salt='email-verification-salt', max_age=86400)  # 24 hour expiration
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid verification link.', 'danger')
            return redirect(url_for('login'))
            
        user.email_verified = True
        db.session.commit()
        
        flash('Your email has been verified! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    except:
        flash('The verification link has expired or is invalid.', 'danger')
        return redirect(url_for('login'))

@app.route('/resend-verification')
def resend_verification():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    return render_template('resend_verification.html')

@app.route('/resend-verification', methods=['POST'])
def resend_verification_post():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('No account found with that email address.', 'danger')
        return redirect(url_for('resend_verification'))
        
    if user.email_verified:
        flash('This email is already verified.', 'info')
        return redirect(url_for('login'))
        
    # Check if we should allow resending (e.g., not too soon after last send)
    if user.email_verification_sent_at:
        time_since_last_send = datetime.utcnow() - user.email_verification_sent_at
        if time_since_last_send.total_seconds() < 300:  # 5 minutes
            flash('Please wait a few minutes before requesting another verification email.', 'warning')
            return redirect(url_for('resend_verification'))
    
    send_verification_email(user)
    flash('Verification email has been resent. Please check your inbox and spam folder.', 'success')
    return redirect(url_for('login'))

# Add these utility functions after the models
def send_verification_email(user):
    token = ts.dumps(user.email, salt='email-verification-salt')
    verification_url = url_for('verify_email', token=token, _external=True)
    
    subject = 'Verify your email address'
    sender = app.config['MAIL_DEFAULT_SENDER']
    recipients = [user.email]
    
    msg = FlaskMessage()
    msg.subject = subject
    msg.sender = sender
    msg.recipients = recipients
    msg.html = render_template('email/verify_email.html', 
        user=user,
        verification_url=verification_url,
        sender=sender  # Pass sender email to template
    )
    
    mail.send(msg)
    user.email_verification_sent_at = datetime.utcnow()
    db.session.commit()

# Add these new models after your existing models

class GroupChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    members = db.relationship('GroupMember', backref='group', lazy=True)
    messages = db.relationship('GroupMessage', backref='group', lazy=True)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group_chat.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Ensure each user is only in a group once
    __table_args__ = (db.UniqueConstraint('group_id', 'user_id'),)

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    group_id = db.Column(db.Integer, db.ForeignKey('group_chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.relationship('User', backref='group_messages')

# Add these new routes

@app.route('/groups')
@login_required
def groups():
    # Get groups where user is a member
    user_groups = GroupChat.query.join(GroupMember).filter(
        GroupMember.user_id == current_user.id
    ).all()
    return render_template('groups.html', groups=user_groups)

@app.route('/create-group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Group name is required.', 'danger')
            return redirect(url_for('create_group'))
        
        # Create new group
        group = GroupChat(name=name, admin_id=current_user.id)
        db.session.add(group)
        db.session.flush()  # Get group ID before committing
        
        # Add creator as member
        member = GroupMember(group_id=group.id, user_id=current_user.id)
        db.session.add(member)
        db.session.commit()
        
        flash('Group created successfully!', 'success')
        return redirect(url_for('group_chat', group_id=group.id))
    
    return render_template('create_group.html')

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    group = GroupChat.query.get_or_404(group_id)
    
    # Check if user is a member
    is_member = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=current_user.id
    ).first() is not None
    
    if not is_member:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('groups'))
    
    # Get all messages for this group
    messages = GroupMessage.query.filter_by(group_id=group.id).order_by(GroupMessage.timestamp.asc()).all()
    
    # Get all members
    members = User.query.join(GroupMember).filter(GroupMember.group_id == group.id).all()
    
    # Get current user's friends who aren't in the group
    friends = User.query.join(Friendship, (
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == User.id)) |
        ((Friendship.friend_id == current_user.id) & (Friendship.user_id == User.id))
    )).filter(
        Friendship.status == 'accepted',
        ~User.id.in_([member.id for member in members])
    ).all()
    
    return render_template('group_chat.html', 
                         group=group, 
                         messages=messages, 
                         members=members,
                         users=friends,
                         is_admin=group.admin_id == current_user.id)

@app.route('/group/<int:group_id>/send', methods=['POST'])
@login_required
def send_group_message(group_id):
    group = GroupChat.query.get_or_404(group_id)
    is_member = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=current_user.id
    ).first() is not None
    
    if not is_member:
        return jsonify({'error': 'Not a member'}), 403
    
    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Message cannot be empty'}), 400

    message = GroupMessage(
        content=content,
        group_id=group.id,
        sender_id=current_user.id
    )
    db.session.add(message)
    db.session.commit()
    
    # Prepare message data
    message_data = {
        'id': message.id,
        'content': message.content,
        'sender_id': message.sender_id,
        'sender_username': current_user.username,
        'timestamp': message.timestamp.strftime('%H:%M'),
        'sender_profile_pic': current_user.profile_pic if current_user.profile_pic else None,
        'group_id': group.id
    }
    
    # Add message to the broker to broadcast to all clients
    queue_id = f"group_{group_id}"
    message_broker.add_message(queue_id, message_data)
    
    # Return the message data as JSON response
    return jsonify({
        'status': 'success',
        'message': message_data
    })

@app.route('/group/<int:group_id>/members/add', methods=['POST'])
@login_required
def add_group_member(group_id):
    group = GroupChat.query.get_or_404(group_id)
    if group.admin_id != current_user.id:
        flash('Only the group admin can add members.', 'danger')
        return redirect(url_for('group_chat', group_id=group.id))
    
    user_id = request.form.get('user_id')
    user = User.query.get_or_404(user_id)
    
    # Check if user is already a member
    existing_member = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=user.id
    ).first()
    
    if existing_member:
        flash('User is already a member of this group.', 'warning')
    else:
        member = GroupMember(group_id=group.id, user_id=user.id)
        db.session.add(member)
        db.session.commit()
        flash('Member added successfully!', 'success')
    
    return redirect(url_for('group_chat', group_id=group.id))

@app.route('/group/<int:group_id>/members/remove/<int:user_id>')
@login_required
def remove_group_member(group_id, user_id):
    group = GroupChat.query.get_or_404(group_id)
    if group.admin_id != current_user.id:
        flash('Only the group admin can remove members.', 'danger')
        return redirect(url_for('group_chat', group_id=group.id))
    
    # Cannot remove the admin
    if user_id == group.admin_id:
        flash('Cannot remove the group admin.', 'danger')
        return redirect(url_for('group_chat', group_id=group.id))
    
    member = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=user_id
    ).first_or_404()
    
    db.session.delete(member)
    db.session.commit()
    flash('Member removed successfully!', 'success')
    
    return redirect(url_for('group_chat', group_id=group.id))

@app.route('/group/<int:group_id>/delete')
@login_required
def delete_group(group_id):
    group = GroupChat.query.get_or_404(group_id)
    if group.admin_id != current_user.id:
        flash('Only the group admin can delete the group.', 'danger')
        return redirect(url_for('group_chat', group_id=group.id))
    
    # Delete all messages and members first
    GroupMessage.query.filter_by(group_id=group.id).delete()
    GroupMember.query.filter_by(group_id=group.id).delete()
    db.session.delete(group)
    db.session.commit()
    
    flash('Group deleted successfully!', 'success')
    return redirect(url_for('groups'))

@app.route('/stream/private/<int:chat_id>')
@login_required
def stream_private(chat_id):
    """SSE stream for private chat updates"""
    def generate():
        q = get_queue(f'private_{chat_id}')
        while True:
            try:
                message = q.get(timeout=20)  # 20 second timeout
                yield f"data: {json.dumps(message)}\n\n"
            except queue.Empty:
                yield "data: {}\n\n"  # Keep-alive packet
    
    return Response(stream_with_context(generate()), 
                   mimetype='text/event-stream')

# First, let's create a better approach for our message queues
class MessageBroker:
    def __init__(self):
        self.queues = {}
        self.messages = {}
        self.clients = {}
    
    def register_client(self, queue_id, client_id):
        """Register a client for a specific queue"""
        if queue_id not in self.clients:
            self.clients[queue_id] = set()
        self.clients[queue_id].add(client_id)
        print(f"Registered client {client_id} for queue {queue_id}")
    
    def unregister_client(self, queue_id, client_id):
        """Unregister a client"""
        if queue_id in self.clients and client_id in self.clients[queue_id]:
            self.clients[queue_id].remove(client_id)
            print(f"Unregistered client {client_id} from queue {queue_id}")
    
    def add_message(self, queue_id, message):
        """Add a message to be broadcast to all clients"""
        if queue_id not in self.messages:
            self.messages[queue_id] = deque(maxlen=100)  # Keep last 100 messages
        
        # Add a unique timestamp to message ID to ensure uniqueness
        message_id = f"{int(time.time() * 1000)}_{message['id']}"
        message['_msg_id'] = message_id  # Add unique message ID for deduplication
        
        self.messages[queue_id].append(message)
        print(f"Added message {message_id} to queue {queue_id}")
        
        # Create individual client queues if they don't exist and broadcast immediately
        if queue_id in self.clients:
            for client_id in self.clients[queue_id]:
                queue_key = f"{queue_id}_{client_id}"
                if queue_key not in self.queues:
                    self.queues[queue_key] = queue.Queue()
                
                # Force immediate delivery
                self.queues[queue_key].put(message.copy())  # Use a copy to avoid reference issues
                print(f"Added message to client queue {queue_key}")
    
    def get_message(self, queue_id, client_id, timeout=30):
        """Get next message for a specific client"""
        queue_key = f"{queue_id}_{client_id}"
        if queue_key not in self.queues:
            self.queues[queue_key] = queue.Queue()
            # If we have message history, add it for the new client
            if queue_id in self.messages and self.messages[queue_id]:
                for msg in list(self.messages[queue_id])[-10:]:  # Send last 10 messages
                    self.queues[queue_key].put(msg)
                print(f"Added message history to new client queue {queue_key}")
        
        return self.queues[queue_key].get(timeout=timeout)

# Create a single message broker instance
message_broker = MessageBroker()

# Now, update the group chat routes to use the message broker
@app.route('/stream/group/<int:group_id>')
@login_required
def stream_group(group_id):
    """SSE stream for group chat updates"""
    def generate():
        # Generate a unique client ID for this connection
        client_id = f"user_{current_user.id}_{int(time.time() * 1000)}"
        
        # Make sure the user is a member of this group
        is_member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first() is not None
        
        if not is_member:
            # Return an error message if not a member
            yield f"data: {json.dumps({'error': 'Not a member of this group'})}\n\n"
            return
        
        # Register this client
        queue_id = f"group_{group_id}"
        message_broker.register_client(queue_id, client_id)
        
        # Send a connection established message
        yield f"data: {json.dumps({'type': 'connection', 'status': 'established'})}\n\n"
        
        try:
            while True:
                try:
                    message = message_broker.get_message(queue_id, client_id, timeout=30)
                    yield f"data: {json.dumps(message)}\n\n"
                except queue.Empty:
                    # Send a keep-alive message
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        finally:
            # Make sure to unregister the client when the connection ends
            message_broker.unregister_client(queue_id, client_id)
    
    return Response(stream_with_context(generate()), 
                   mimetype='text/event-stream')

@app.route('/group/<int:group_id>/leave')
@login_required
def leave_group(group_id):
    """Allow a user to leave a group chat"""
    group = GroupChat.query.get_or_404(group_id)
    
    # Check if the user is a member
    membership = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=current_user.id
    ).first()
    
    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('groups'))
    
    # Check if user is the admin
    if group.admin_id == current_user.id:
        flash('As the admin, you cannot leave the group. You must either delete the group or transfer admin rights first.', 'warning')
        return redirect(url_for('group_chat', group_id=group.id))
    
    # Remove user from the group
    db.session.delete(membership)
    db.session.commit()
    
    flash('You have left the group successfully.', 'success')
    return redirect(url_for('groups'))

# Run the application
if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'production':
        # Production settings
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
        app.wsgi_app = ProxyFix(app.wsgi_app)
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port)
    else:
        # Development settings
        app.run(debug=True) 
