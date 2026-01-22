from datetime import datetime
from flask import jsonify
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import and_, or_ 
import os
from flask_mail import Mail, Message as MailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets
from datetime import timedelta
import os
from openai import OpenAI
from zoneinfo import ZoneInfo
import re
from flask import jsonify, request, redirect, url_for
import traceback

COMMON_TIMEZONES = [
    "Asia/Beirut",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "America/New_York",
    "America/Los_Angeles",
    "Asia/Dubai",
    "Asia/Riyadh",
    "Asia/Istanbul",
]

client = OpenAI()  

app = Flask(__name__)
app.secret_key = "dev-secret-key"

DB_USER = ""
DB_PASSWORD = ""
DB_HOST = ""
DB_NAME = ""

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAIL_SERVER"] = ""
app.config["MAIL_PORT"] = 
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = ""
app.config["MAIL_PASSWORD"] = ""
app.config["MAIL_DEFAULT_SENDER"] = ""


mail = Mail(app)

reset_serializer = URLSafeTimedSerializer(app.secret_key)

db = SQLAlchemy(app)

openai_client = OpenAI()

AI_BOT_USER_ID = 4          
AI_BOT_USERNAME = "AI bot"  

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    timezone = db.Column(db.String(64), nullable=True)

    memberships = db.relationship("ChatMember", back_populates="user", cascade="all, delete-orphan")
    messages = db.relationship("Message", back_populates="sender", cascade="all, delete-orphan")


class Chat(db.Model):
    __tablename__ = "chat"

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False)

    title = db.Column(db.String(120), nullable=True)
    has_ai = db.Column(db.Boolean, default=False, nullable=False)
    timezone = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship("ChatMember", back_populates="chat", cascade="all, delete-orphan")
    messages = db.relationship("Message", back_populates="chat", cascade="all, delete-orphan")

class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)

    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User")

class ChatMember(db.Model):
    __tablename__ = "chat_member"

    id = db.Column(db.Integer, primary_key=True)

    chat_id = db.Column(db.Integer, db.ForeignKey("chat.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    role = db.Column(db.String(20), default="member", nullable=False)

    __table_args__ = (
        db.UniqueConstraint("chat_id", "user_id", name="uq_chat_member_chat_user"),
    )

    chat = db.relationship("Chat", back_populates="members")
    user = db.relationship("User", back_populates="memberships")

class FriendRequest(db.Model):
    __tablename__ = "friend_request"

    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("requester_id", "receiver_id", name="uq_friend_request_pair"),
    )


class Friendship(db.Model):
    """
    Stores accepted friendships once.
    We store (user_low_id, user_high_id) to avoid duplicates.
    """
    __tablename__ = "friendship"

    id = db.Column(db.Integer, primary_key=True)
    user_low_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user_high_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_low_id", "user_high_id", name="uq_friendship_pair"),
    )

class UserBlock(db.Model):
    __tablename__ = "user_block"

    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("blocker_id", "blocked_id", name="uq_user_block_pair"),
    )

class Message(db.Model):
    __tablename__ = "message"

    id = db.Column(db.Integer, primary_key=True)

    chat_id = db.Column(db.Integer, db.ForeignKey("chat.id"), nullable=False)

    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    chat = db.relationship("Chat", back_populates="messages")
    sender = db.relationship("User", back_populates="messages")


with app.app_context():
    db.create_all()


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)

def _pair(a: int, b: int):
    return (a, b) if a < b else (b, a)

def build_chat_context(chat_id: int, limit: int = 12):
    """
    Returns recent messages as OpenAI 'input' format.
    We keep it small so replies stay fast & cheap.
    """
    msgs = (
        Message.query
        .filter_by(chat_id=chat_id)
        .order_by(Message.created_at.desc())
        .limit(limit)
        .all()
    )
    msgs.reverse()

    context = []
    for m in msgs:
        role = "assistant" if m.sender_id == AI_BOT_USER_ID else "user"
        context.append({"role": role, "content": m.content})
    return context

def get_ai_user():
    """Return the AI bot User row (create it if missing)."""
    ai = User.query.filter_by(username="AI bot").first()
    if not ai:
        ai = User(username="AI bot", email="ai@smartchat.local", password_hash="")
        db.session.add(ai)
        db.session.commit()
    return ai

def clean_ai_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", text)
    return text.strip()

def build_chat_history(chat_id: int, limit: int = 12):
    """Return last N messages as plain text for context."""
    msgs = (
        Message.query.filter_by(chat_id=chat_id)
        .order_by(Message.created_at.asc())
        .all()
    )
    msgs = msgs[-limit:]
    lines = []
    for m in msgs:
        sender = User.query.get(m.sender_id)
        name = sender.username if sender else "User"
        lines.append(f"{name}: {m.content}")
    return "\n".join(lines)

def get_chat_timezone(chat_id: int, user_id: int):
    chat = db.session.get(Chat, chat_id)
    user = db.session.get(User, user_id)

    if chat and chat.type == "group":
        tz = getattr(chat, "timezone", None)
        if tz:
            return tz

    if user:
        tz = getattr(user, "timezone", None)
        if tz:
            return tz

    return None

from datetime import datetime
from zoneinfo import ZoneInfo
import traceback

def generate_ai_reply(chat_id: int, user_id: int, user_text: str, *, is_group: bool = False) -> str:
    tz = get_chat_timezone(chat_id, user_id)

    now_line = ""
    if tz:
        try:
            now_local = datetime.now(ZoneInfo(tz))
            now_line = f"Current local date/time: {now_local.strftime('%Y-%m-%d %H:%M')} ({tz})."
        except Exception:
            now_line = ""

    system_prompt = (
        "You are SmartChat's AI bot.\n"
        "Rules:\n"
        "- Answer the user's question FIRST.\n"
        "- Keep it concise (1–4 sentences).\n"
        "- If you give a list, use bullet points.\n"
        "- Ask at most ONE short follow-up question ONLY if truly necessary.\n"
        "- Do NOT ask for today's date or the current time; use the provided current date/time.\n"
        "- Use plain text ONLY.\n"
        "- Do NOT use markdown, bold, italics, asterisks (*), or formatting symbols.\n"
        "- Do not mention being an AI or policies.\n"
    )

    if now_line:
        system_prompt += f"\n{now_line}\n"

    if is_group:
        system_prompt += "\nGroup chat rule: be extra concise.\n"

    context = build_chat_context(chat_id, limit=10)

    response = openai_client.responses.create(
        model="gpt-5.2",
        input=[
            {"role": "system", "content": system_prompt},
            *context,
            {"role": "user", "content": user_text},
        ],
    )
    return (response.output_text or "").strip()

def friendship_exists(a: int, b: int) -> bool:
    low, high = _pair(a, b)
    return Friendship.query.filter_by(user_low_id=low, user_high_id=high).first() is not None

def create_reset_token(user_id: int) -> str:
    PasswordResetToken.query.filter_by(user_id=user_id, used=False).update(
        {"used": True}, synchronize_session=False
    )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=15)

    row = PasswordResetToken(user_id=user_id, token=token, expires_at=expires_at, used=False)
    db.session.add(row)
    db.session.commit()
    return token


def verify_reset_token(token: str):
    row = PasswordResetToken.query.filter_by(token=token).first()
    if not row:
        return None

    if row.used:
        return None

    if row.expires_at < datetime.utcnow():
        return None

    return row

def delete_dm_for_both_users(chat_id: int):
    """
    Deletes a DM chat completely (messages + memberships + chat row).
    Intended to be used when unfriend/block happens.
    """
    chat = Chat.query.get(chat_id)
    if not chat:
        return

    if chat.type != "dm":
        return

    Message.query.filter_by(chat_id=chat_id).delete(synchronize_session=False)

    ChatMember.query.filter_by(chat_id=chat_id).delete(synchronize_session=False)

    db.session.delete(chat)
    db.session.commit()

def request_state(me_id: int, other_id: int) -> str:
    """
    Returns:
      'friends'
      'pending_sent'
      'pending_received'
      'none'
    """
    if friendship_exists(me_id, other_id):
        return "friends"

    sent = FriendRequest.query.filter_by(
        requester_id=me_id, receiver_id=other_id, status="pending"
    ).first()
    if sent:
        return "pending_sent"

    received = FriendRequest.query.filter_by(
        requester_id=other_id, receiver_id=me_id, status="pending"
    ).first()
    if received:
        return "pending_received"

    return "none"


from sqlalchemy import func

def is_blocking(blocker_id: int, blocked_id: int) -> bool:
    return UserBlock.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id).first() is not None

def is_blocked_either_way(a: int, b: int) -> bool:
    return is_blocking(a, b) or is_blocking(b, a)

def delete_dm_chats_between(a: int, b: int):
    dm_two_member_chat_ids = (
        db.session.query(ChatMember.chat_id)
        .group_by(ChatMember.chat_id)
        .having(func.count(ChatMember.id) == 2)
        .subquery()
    )

    chat_ids = (
        db.session.query(Chat.id)
        .filter(Chat.type == "dm")
        .filter(Chat.id.in_(db.select(dm_two_member_chat_ids.c.chat_id)))
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(ChatMember.user_id.in_([a, b]))
        .group_by(Chat.id)
        .having(func.count(func.distinct(ChatMember.user_id)) == 2)
        .all()
    )

    for (cid,) in chat_ids:
        chat = Chat.query.get(cid)
        if chat:
            db.session.delete(chat)

    db.session.commit()

def get_friends(me_id: int):
    """
    Returns a list of User objects that are friends with me_id.
    """
    rows = Friendship.query.filter(
        (Friendship.user_low_id == me_id) | (Friendship.user_high_id == me_id)
    ).all()

    friend_ids = []
    for r in rows:
        other_id = r.user_high_id if r.user_low_id == me_id else r.user_low_id
        friend_ids.append(other_id)

    if not friend_ids:
        return []

    return User.query.filter(User.id.in_(friend_ids)).order_by(User.username.asc()).all()

def chat_display_title(chat: Chat, me_id: int) -> str:
    if chat.type == "ai":
        return chat.title or "AI"

    if chat.type == "group":
        return chat.title or "Group Chat"

    other = (
        db.session.query(User)
        .join(ChatMember, ChatMember.user_id == User.id)
        .filter(ChatMember.chat_id == chat.id)
        .filter(User.id != me_id)
        .first()
    )
    return other.username if other else "Private Chat"

def find_dm_chat(me_id: int, other_id: int):
    """
    Finds an existing DM chat between two users (type='dm').
    Returns Chat or None.
    """
    dm = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(Chat.type == "dm")
        .filter(ChatMember.user_id.in_([me_id, other_id]))
        .group_by(Chat.id)
        .having(db.func.count(db.distinct(ChatMember.user_id)) == 2)
        .first()
    )
    return dm

def login_required():
    if "user_id" not in session:
        flash("Please sign in first.", "info")
        return redirect(url_for("login"))
    return None

def is_group_admin(chat_id: int, user_id: int) -> bool:
    m = ChatMember.query.filter_by(chat_id=chat_id, user_id=user_id).first()
    return bool(m and m.role == "admin")

def require_group_admin(chat_id: int, user_id: int):
    chat = Chat.query.get_or_404(chat_id)
    if chat.type != "group":
        flash("This is not a group chat.", "error")
        return None, redirect(url_for("open_chat", chat_id=chat_id))

    if not is_group_admin(chat_id, user_id):
        flash("Only the group admin can manage this group.", "error")
        return None, redirect(url_for("open_chat", chat_id=chat_id))

    return chat, None

def get_group_members(chat_id: int):
    rows = (
        db.session.query(User, ChatMember)
        .join(ChatMember, ChatMember.user_id == User.id)
        .filter(ChatMember.chat_id == chat_id)
        .order_by(
            db.case((ChatMember.role == "admin", 0), else_=1),
            User.username.asc()
        )
        .all()
    )
    return [{"id": u.id, "username": u.username, "role": m.role} for u, m in rows]

def ensure_ai_chat_for_user(user_id: int) -> int:
    ai_chat = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(Chat.type == "ai", ChatMember.user_id == user_id)
        .first()
    )
    if ai_chat:
        return ai_chat.id

    chat = Chat(type="ai", title="AI")
    db.session.add(chat)
    db.session.commit()

    db.session.add(ChatMember(chat_id=chat.id, user_id=user_id, role="member"))
    db.session.commit()
    return chat.id

def create_ai_chat_for_user(user_id: int) -> int:
    existing_count = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(Chat.type == "ai", ChatMember.user_id == user_id)
        .count()
    )

    title = "AI" if existing_count == 0 else f"AI {existing_count + 1}"

    chat = Chat(type="ai", title=title)
    db.session.add(chat)
    db.session.commit()

    db.session.add(ChatMember(chat_id=chat.id, user_id=user_id, role="member"))
    db.session.commit()

    return chat.id


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill all fields.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "error")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully. You can now sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["username"] = user.username

        return redirect(url_for("home"))

    return render_template("login.html")


from flask_mail import Mail, Message as MailMessage

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        user = User.query.filter(db.func.lower(User.email) == email).first()

        flash("If the email exists, a reset link was sent.", "info")

        if user:
            token = create_reset_token(user.id)
            reset_link = url_for("reset_password", token=token, _external=True)

            msg = MailMessage(
                subject="SmartChat Password Reset",
                recipients=[user.email],
                body=f"""Hello,

We received a request to reset your SmartChat password.

Reset link (valid for 15 minutes):
{reset_link}

If you didn’t request this, ignore this email.
"""
            )
            mail.send(msg)

        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    row = verify_reset_token(token)
    if not row:
        flash("This reset link is invalid or expired.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not password:
            flash("Password cannot be empty.", "error")
            return redirect(url_for("reset_password", token=token))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password", token=token))

        user = User.query.get(row.user_id)
        user.password_hash = generate_password_hash(password)

        row.used = True
        db.session.commit()

        flash("Password updated! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/settings/location", methods=["POST"])
def update_location():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    location_label = request.form.get("location_label", "").strip()
    timezone = request.form.get("timezone", "").strip()

    if timezone and timezone not in COMMON_TIMEZONES:
        flash("Invalid timezone selected.", "error")
        return redirect(url_for("settings"))

    user.location_label = location_label or None
    user.timezone = timezone or None
    db.session.commit()

    flash("Location updated.", "success")
    return redirect(url_for("settings"))

@app.route("/group/<int:chat_id>/location", methods=["POST"])
def update_group_location(chat_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    chat = Chat.query.get_or_404(chat_id)

    admin = ChatMember.query.filter_by(chat_id=chat_id, user_id=user.id, role="admin").first()
    if not admin:
        flash("Only the group admin can do that.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    loc = request.form.get("group_location_label", "").strip()
    tz = request.form.get("group_timezone", "").strip()

    if tz and tz not in COMMON_TIMEZONES:
        flash("Invalid timezone selected.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    chat.location_label = loc or None
    chat.timezone = tz or None
    db.session.commit()

    flash("Group location updated.", "success")
    return redirect(url_for("open_chat", chat_id=chat_id))

@app.route("/home")
def home():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    chats = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(ChatMember.user_id == user.id)
        .order_by(Chat.created_at.desc())
        .all()
    )
    chat_items = []
    for c in chats:
        chat_items.append({
            "id": c.id,
            "type": c.type,
            "title": chat_display_title(c, user.id),
        })

    return render_template(
    "home.html",
    user=user,
    chats=chats,
    chat_items=chat_items,
    active_chat_id=None,
    active_chat=None,
    messages=[],
    membership=None
    )

@app.route("/ai/new", methods=["POST"])
def new_ai_chat():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    new_chat_id = create_ai_chat_for_user(user.id)
    return redirect(url_for("open_chat", chat_id=new_chat_id))

@app.route("/dm/<int:friend_id>")
def open_dm_with_friend(friend_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    if friend_id == user.id:
        return redirect(url_for("friends"))

    if is_blocked_either_way(user.id, friend_id):
        flash("You can’t open a chat because one of you blocked the other.", "error")
        return redirect(url_for("friends"))

    if not friendship_exists(user.id, friend_id):
        flash("You can only message friends.", "error")
        return redirect(url_for("friends"))

    dm_chat = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(Chat.type == "dm")
        .group_by(Chat.id)
        .having(db.func.sum(db.case((ChatMember.user_id == user.id, 1), else_=0)) > 0)
        .having(db.func.sum(db.case((ChatMember.user_id == friend_id, 1), else_=0)) > 0)
        .first()
    )

    if not dm_chat:
        dm_chat = Chat(type="dm", title=None)
        db.session.add(dm_chat)
        db.session.commit()

        db.session.add(ChatMember(chat_id=dm_chat.id, user_id=user.id, role="member"))
        db.session.add(ChatMember(chat_id=dm_chat.id, user_id=friend_id, role="member"))
        db.session.commit()

    return redirect(url_for("open_chat", chat_id=dm_chat.id))

@app.route("/friends")
def friends():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    q = request.args.get("q", "").strip()

    friendships = Friendship.query.filter(
        (Friendship.user_low_id == user.id) | (Friendship.user_high_id == user.id)
    ).all()

    friend_ids = []
    for f in friendships:
        friend_ids.append(f.user_high_id if f.user_low_id == user.id else f.user_low_id)

    friends_q = User.query.filter(User.id.in_(friend_ids))

    if q:
        friends_q = friends_q.filter(User.username.ilike(f"%{q}%"))

    friends_list = friends_q.order_by(User.username.asc()).all()

    return render_template(
        "friends.html",
        user=user,
        friends=friends_list,
        q=q,
        common_timezones=COMMON_TIMEZONES,   
        active_tab="friends"
    )

@app.route("/group/create", methods=["POST"])
def create_group():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    title = request.form.get("group_title", "").strip()
    ai_enabled = request.form.get("ai_enabled") == "1"

    group_timezone = request.form.get("group_timezone", "").strip() or None

    friend_ids = request.form.getlist("friend_ids")

    if not title:
        flash("Group name can't be empty.", "error")
        return redirect(url_for("friends"))

    try:
        friend_ids = [int(x) for x in friend_ids]
    except ValueError:
        friend_ids = []

    if len(friend_ids) == 0:
        flash("Please select at least 1 friend.", "error")
        return redirect(url_for("friends"))

    valid_friend_ids = []
    for fid in friend_ids:
        if fid != user.id and friendship_exists(user.id, fid):
            valid_friend_ids.append(fid)

    if len(valid_friend_ids) == 0:
        flash("No valid friends selected.", "error")
        return redirect(url_for("friends"))

    new_chat = Chat(type="group", title=title)

    if hasattr(Chat, "ai_enabled"):
        new_chat.ai_enabled = ai_enabled

    if hasattr(Chat, "timezone"):
        new_chat.timezone = group_timezone

    db.session.add(new_chat)
    db.session.commit()

    db.session.add(ChatMember(chat_id=new_chat.id, user_id=user.id, role="admin"))

    for fid in valid_friend_ids:
        db.session.add(ChatMember(chat_id=new_chat.id, user_id=fid, role="member"))

    db.session.commit()

    flash("Group created!", "success")
    return redirect(url_for("open_chat", chat_id=new_chat.id))

@app.route("/notifications")
def notifications():
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()

    incoming = (
        db.session.query(FriendRequest, User)
        .join(User, User.id == FriendRequest.requester_id)
        .filter(FriendRequest.receiver_id == me.id, FriendRequest.status == "pending")
        .order_by(FriendRequest.created_at.desc())
        .all()
    )

    return render_template(
        "notifications.html",
        user=me,
        incoming=incoming,
        active_tab="notifications"
    )

@app.route("/friend-request/<int:req_id>/accept", methods=["POST"])
def accept_friend_request(req_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()

    fr = FriendRequest.query.get_or_404(req_id)

    if fr.receiver_id != me.id or fr.status != "pending":
        flash("Invalid friend request.", "error")
        return redirect(url_for("notifications"))

    low, high = _pair(fr.requester_id, fr.receiver_id)
    if not Friendship.query.filter_by(user_low_id=low, user_high_id=high).first():
        db.session.add(Friendship(user_low_id=low, user_high_id=high))

    db.session.delete(fr)

    opposite = FriendRequest.query.filter_by(
        requester_id=me.id,
        receiver_id=fr.requester_id,
        status="pending"
    ).first()
    if opposite:
        db.session.delete(opposite)

    db.session.commit()
    flash("Friend request accepted!", "success")
    return redirect(url_for("notifications"))


@app.route("/friend-request/<int:req_id>/decline", methods=["POST"])
def decline_friend_request(req_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    fr = FriendRequest.query.get_or_404(req_id)

    if fr.receiver_id != me.id or fr.status != "pending":
        flash("Invalid friend request.", "error")
        return redirect(url_for("notifications"))

    db.session.delete(fr)
    db.session.commit()

    flash("Friend request declined.", "info")
    return redirect(url_for("notifications"))


@app.route("/settings")
def settings():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    return render_template(
        "settings.html",
        user=user,
        common_timezones=COMMON_TIMEZONES,
        active_tab="settings",
    )


@app.route("/chat/<int:chat_id>")
def open_chat(chat_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user.id).first()
    if not membership:
        flash("You don't have access to that chat.", "error")
        return redirect(url_for("home"))

    chats = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(ChatMember.user_id == user.id)
        .order_by(Chat.created_at.desc())
        .all()
    )
    chat_items = []
    for c in chats:
        chat_items.append({
            "id": c.id,
            "type": c.type,
            "title": chat_display_title(c, user.id),
        })

    active_chat = Chat.query.get_or_404(chat_id)

    other_user_id = None
    group_members = []
    sender_map = {}

    if active_chat.type == "dm":
        other = (
            db.session.query(User)
            .join(ChatMember, ChatMember.user_id == User.id)
            .filter(ChatMember.chat_id == chat_id, User.id != user.id)
            .first()
        )
        if other:
            other_user_id = other.id

    if active_chat.type == "group":
        members = (
            db.session.query(User.username)
            .join(ChatMember, ChatMember.user_id == User.id)
            .filter(ChatMember.chat_id == chat_id)
            .order_by(User.username.asc())
            .all()
        )
        group_members = [row[0] for row in members]

    sender_ids = (
        db.session.query(Message.sender_id)
        .filter(Message.chat_id == chat_id)
        .distinct()
        .all()
    )
    sender_ids = [row[0] for row in sender_ids]

    if sender_ids:
        senders = User.query.filter(User.id.in_(sender_ids)).all()
        sender_map = {u.id: u.username for u in senders}

    messages = (
        Message.query.filter_by(chat_id=chat_id)
        .order_by(Message.created_at.asc())
        .all()
    )

    chat_display_name = active_chat.title or "Chat"
    other_user_id = None
    if active_chat.type == "dm":
        other_member = (
            db.session.query(User)
            .join(ChatMember, ChatMember.user_id == User.id)
            .filter(ChatMember.chat_id == chat_id, User.id != user.id)
            .first()
        )
        if other_member:
           chat_display_name = other_member.username
           other_user_id = other_member.id
    elif active_chat.type == "ai":
        chat_display_name = active_chat.title or "AI"
    elif active_chat.type == "group":
        chat_display_name = active_chat.title or "Group Chat"
    
    group_members = []
    is_admin = False

    if active_chat.type == "group":
        group_members = get_group_members(chat_id)
        is_admin = (membership.role == "admin")
    
    friends_for_group_add = []

    if active_chat.type == "group" and membership.role == "admin":
        friendships = Friendship.query.filter(
            (Friendship.user_low_id == user.id) | (Friendship.user_high_id == user.id)
        ).all()
        friend_ids = []
        for f in friendships:
            friend_ids.append(f.user_high_id if f.user_low_id == user.id else f.user_low_id)

        existing_ids = [gm["id"] for gm in get_group_members(chat_id)]
        friend_ids = [fid for fid in friend_ids if fid not in existing_ids]

        friends_for_group_add = User.query.filter(User.id.in_(friend_ids)).order_by(User.username.asc()).all()


    return render_template(
    "home.html",
    user=user,
    chats=chats,
    chat_items=chat_items,
    active_chat_id=chat_id,
    active_chat=active_chat,
    messages=messages,
    membership=membership,
    chat_display_name=chat_display_name,
    other_user_id=other_user_id,
    sender_map=sender_map,
    group_members=group_members,
    is_admin=is_admin,
    friends_for_group_add=friends_for_group_add,
    )


@app.route("/chat/<int:chat_id>/delete", methods=["POST"])
def delete_chat(chat_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user.id).first()
    if not membership:
        flash("You don't have access to that chat.", "error")
        return redirect(url_for("home"))
    
    chat = Chat.query.get_or_404(chat_id)

    if chat.type == "group":
       flash("You can't delete a group chat. Leave the group first.", "info")
       return redirect(url_for("open_chat", chat_id=chat_id))

    Message.query.filter_by(chat_id=chat_id, sender_id=user.id).delete(synchronize_session=False)

    db.session.delete(membership)
    db.session.commit()

    remaining = ChatMember.query.filter_by(chat_id=chat_id).count()
    if remaining == 0:
        chat = Chat.query.get(chat_id)
        if chat:
            db.session.delete(chat)
            db.session.commit()

    flash("Chat deleted.", "success")
    return redirect(url_for("home"))

@app.route("/chat/<int:chat_id>/leave", methods=["POST"])
def leave_group(chat_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    chat = Chat.query.get_or_404(chat_id)

    if chat.type != "group":
        flash("You can only leave group chats.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user.id).first()
    if not membership:
        flash("You are not a member of this group.", "error")
        return redirect(url_for("home"))

    Message.query.filter_by(chat_id=chat_id, sender_id=user.id).delete(synchronize_session=False)

    db.session.delete(membership)
    db.session.commit()

    remaining = ChatMember.query.filter_by(chat_id=chat_id).count()
    if remaining == 0:
        db.session.delete(chat)
        db.session.commit()

    flash("You left the group.", "success")
    return redirect(url_for("home"))

@app.route("/search")
def search_tab():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    q = request.args.get("q", "").strip()

    results = []
    if q:
        users = (
            User.query
            .filter(User.username.ilike(f"%{q}%"))
            .filter(User.id != user.id)
            .order_by(User.username.asc())
            .limit(30)
            .all()
        )

        results = [{"u": u, "state": request_state(user.id, u.id)} for u in users]

    return render_template(
        "search.html",
        user=user,
        q=q,
        results=results
    )


@app.route("/friend-request/<int:other_id>/toggle", methods=["POST"])
def toggle_friend_request(other_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    if is_blocked_either_way(me.id, other_id):
        flash("You can't send a friend request because one of you blocked the other.", "error")
        return redirect(url_for("search_tab", q=request.args.get("q", "")))
    if other_id == me.id:
        return jsonify({"ok": False, "error": "self"}) , 400

    wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def json_response():
        return jsonify({
            "ok": True,
            "state": request_state(me.id, other_id)
        })

    if friendship_exists(me.id, other_id):
        if wants_json:
            return json_response()
        flash("You are already friends.", "info")
        return redirect(url_for("search_tab", q=request.args.get("q", "")))

    sent = FriendRequest.query.filter_by(
        requester_id=me.id, receiver_id=other_id, status="pending"
    ).first()
    if sent:
        db.session.delete(sent)
        db.session.commit()
        if wants_json:
            return json_response()
        flash("Friend request cancelled.", "info")
        return redirect(url_for("search_tab", q=request.args.get("q", "")))

    incoming = FriendRequest.query.filter_by(
        requester_id=other_id, receiver_id=me.id, status="pending"
    ).first()
    if incoming:
        if wants_json:
            return jsonify({"ok": True, "state": "pending_received"})
        flash("This user already sent you a request. Check Notifications.", "info")
        return redirect(url_for("search_tab", q=request.args.get("q", "")))

    fr = FriendRequest(requester_id=me.id, receiver_id=other_id, status="pending")
    db.session.add(fr)
    db.session.commit()

    if wants_json:
        return json_response()

    flash("Friend request sent.", "success")
    return redirect(url_for("search_tab", q=request.args.get("q", "")))

@app.route("/chat/<int:chat_id>/send", methods=["POST"])
def send_message(chat_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user.id).first()
    if not membership:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "No access"}), 403
        return redirect(url_for("home"))

    chat = Chat.query.get_or_404(chat_id)

    if chat.type == "dm":
        other_member = (
            db.session.query(User)
            .join(ChatMember, ChatMember.user_id == User.id)
            .filter(ChatMember.chat_id == chat_id, User.id != user.id)
            .first()
        )
        if other_member and is_blocked_either_way(user.id, other_member.id):
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"ok": False, "error": "Blocked"}), 403
            flash("You can’t send messages because one of you blocked the other.", "error")
            return redirect(url_for("home"))

    content = request.form.get("content", "").strip()
    if not content:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "Empty message"}), 400
        return redirect(url_for("open_chat", chat_id=chat_id))

    msg = Message(chat_id=chat_id, sender_id=user.id, content=content)
    db.session.add(msg)
    db.session.commit()

    ai_reply = None
    ai_msg = None

    try:
        if chat.type == "ai":
            ai_reply = generate_ai_reply(chat_id, user.id, content, is_group=False)

        elif chat.type == "group":
            text_lower = content.lower()

            bot_tag_1 = "@ai"
            bot_tag_2 = f"@{AI_BOT_USERNAME.lower()}"
            is_tagged = (bot_tag_1 in text_lower) or (bot_tag_2 in text_lower)

            if is_tagged:
                cleaned = content

                if bot_tag_2 in text_lower:
                    idx = text_lower.find(bot_tag_2)
                    cleaned = (content[:idx] + content[idx + len(bot_tag_2):]).strip()
                elif bot_tag_1 in text_lower:
                    idx = text_lower.find(bot_tag_1)
                    cleaned = (content[:idx] + content[idx + len(bot_tag_1):]).strip()

                if not cleaned:
                    cleaned = "Hi! What can I help with?"

                ai_reply = generate_ai_reply(chat_id, user.id, cleaned, is_group=True)

        if ai_reply:
            ai_reply = clean_ai_text(ai_reply)
            ai_msg = Message(chat_id=chat_id, sender_id=AI_BOT_USER_ID, content=ai_reply)
            db.session.add(ai_msg)
            db.session.commit()

    except Exception as e:
        print("AI ERROR:", e)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        payload = {
            "ok": True,
            "chat_type": chat.type,
            "user_message": {
                "content": msg.content,
                "time": msg.created_at.strftime("%I:%M %p"),
                "date": msg.created_at.strftime("%d/%m/%y"),
                "sender_id": user.id,
                "sender_name": user.username,
            },
            "ai_message": None
        }

        if ai_msg is not None:
            payload["ai_message"] = {
                "content": ai_msg.content,
                "time": ai_msg.created_at.strftime("%I:%M %p"),
                "date": ai_msg.created_at.strftime("%d/%m/%y"),
                "sender_id": AI_BOT_USER_ID,
                "sender_name": AI_BOT_USERNAME,
            }

        return jsonify(payload)

    return redirect(url_for("open_chat", chat_id=chat_id))


@app.route("/dm/<int:other_id>/send", methods=["POST"])
def send_dm(other_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()

    if not friendship_exists(me.id, other_id):
        flash("You can only message friends.", "error")
        return redirect(url_for("friends"))

    content = request.form.get("content", "").strip()
    if not content:
        return redirect(url_for("friends", u=other_id))

    dm = find_dm_chat(me.id, other_id)

    if not dm:
        dm = Chat(type="dm", title=None)
        db.session.add(dm)
        db.session.commit()

        db.session.add(ChatMember(chat_id=dm.id, user_id=me.id, role="member"))
        db.session.add(ChatMember(chat_id=dm.id, user_id=other_id, role="member"))
        db.session.commit()

    msg = Message(chat_id=dm.id, sender_id=me.id, content=content)
    db.session.add(msg)
    db.session.commit()

    return redirect(url_for("open_chat", chat_id=dm.id))

@app.route("/settings/blocked")
def settings_blocked():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()

    blocked = (
        db.session.query(User, UserBlock)
        .join(UserBlock, UserBlock.blocked_id == User.id)
        .filter(UserBlock.blocker_id == user.id)
        .order_by(User.username.asc())
        .all()
    )

    return render_template("settings_blocked.html", user=user, blocked=blocked, active_tab="settings")


@app.route("/user/<int:other_id>/unblock", methods=["POST"])
def unblock_user(other_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()

    UserBlock.query.filter_by(blocker_id=me.id, blocked_id=other_id).delete(synchronize_session=False)
    db.session.commit()

    flash("User unblocked.", "success")
    return redirect(url_for("settings_blocked"))

from sqlalchemy import and_, or_

@app.route("/user/<int:other_id>/unfriend", methods=["POST"])
def unfriend_user(other_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    if other_id == me.id:
        return redirect(url_for("home"))

    low, high = _pair(me.id, other_id)
    Friendship.query.filter_by(user_low_id=low, user_high_id=high).delete(synchronize_session=False)

    FriendRequest.query.filter(
        ((FriendRequest.requester_id == me.id) & (FriendRequest.receiver_id == other_id)) |
        ((FriendRequest.requester_id == other_id) & (FriendRequest.receiver_id == me.id))
    ).delete(synchronize_session=False)

    dm_chat = (
        db.session.query(Chat)
        .join(ChatMember, ChatMember.chat_id == Chat.id)
        .filter(Chat.type == "dm")
        .group_by(Chat.id)
        .having(db.func.sum(db.case((ChatMember.user_id == me.id, 1), else_=0)) > 0)
        .having(db.func.sum(db.case((ChatMember.user_id == other_id, 1), else_=0)) > 0)
        .first()
    )

    if dm_chat:
        Message.query.filter_by(chat_id=dm_chat.id).delete(synchronize_session=False)
        ChatMember.query.filter_by(chat_id=dm_chat.id).delete(synchronize_session=False)
        db.session.delete(dm_chat)

    db.session.commit()
    flash("Unfriended. Chat deleted for both of you.", "success")
    return redirect(url_for("home"))


@app.route("/user/<int:other_id>/block", methods=["POST"])
def block_user(other_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    if other_id == me.id:
        return redirect(url_for("home"))

    low, high = _pair(me.id, other_id)
    Friendship.query.filter_by(user_low_id=low, user_high_id=high).delete(synchronize_session=False)

    FriendRequest.query.filter(
        ((FriendRequest.requester_id == me.id) & (FriendRequest.receiver_id == other_id)) |
        ((FriendRequest.requester_id == other_id) & (FriendRequest.receiver_id == me.id))
    ).delete(synchronize_session=False)

    if not is_blocking(me.id, other_id):
        db.session.add(UserBlock(blocker_id=me.id, blocked_id=other_id))

    db.session.commit()

    delete_dm_chats_between(me.id, other_id)

    flash("User blocked. Your DM chat with them was removed.", "success")
    return redirect(url_for("home"))


@app.route("/group/<int:chat_id>/toggle-ai", methods=["POST"])
def group_toggle_ai(chat_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    chat, redirect_resp = require_group_admin(chat_id, me.id)
    if redirect_resp:
        return redirect_resp

    chat.has_ai = not chat.has_ai
    db.session.commit()

    flash("AI updated for the group.", "success")
    return redirect(url_for("open_chat", chat_id=chat_id))

@app.route("/group/<int:chat_id>/add-members", methods=["POST"])
def group_add_members(chat_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    chat, redirect_resp = require_group_admin(chat_id, me.id)
    if redirect_resp:
        return redirect_resp

    ids = request.form.getlist("member_ids")
    if not ids:
        flash("Select at least one friend to add.", "info")
        return redirect(url_for("open_chat", chat_id=chat_id))

    for raw in ids:
        try:
            uid = int(raw)
        except:
            continue

        if uid == me.id:
            continue

        if not friendship_exists(me.id, uid):
            continue

        already = ChatMember.query.filter_by(chat_id=chat_id, user_id=uid).first()
        if already:
            continue

        db.session.add(ChatMember(chat_id=chat_id, user_id=uid, role="member"))

    db.session.commit()
    flash("Members added.", "success")
    return redirect(url_for("open_chat", chat_id=chat_id))

@app.route("/settings/timezone", methods=["POST"])
def update_timezone():
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    tz = request.form.get("timezone", "").strip()

    if not tz:
        flash("Please select a timezone.", "error")
        return redirect(url_for("settings"))

    user.timezone = tz
    db.session.commit()
    flash("Timezone saved.", "success")
    return redirect(url_for("settings"))

@app.route("/group/<int:chat_id>/remove-member/<int:user_id>", methods=["POST"])
def group_remove_member(chat_id, user_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    chat, redirect_resp = require_group_admin(chat_id, me.id)
    if redirect_resp:
        return redirect_resp

    if user_id == me.id:
        flash("You can’t remove yourself. Use 'Leave group'.", "info")
        return redirect(url_for("open_chat", chat_id=chat_id))

    target = ChatMember.query.filter_by(chat_id=chat_id, user_id=user_id).first()
    if not target:
        flash("Member not found.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    if target.role == "admin":
        flash("You can’t remove the admin. Transfer admin first.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    Message.query.filter_by(chat_id=chat_id, sender_id=user_id).delete(synchronize_session=False)

    db.session.delete(target)
    db.session.commit()

    flash("Member removed.", "success")
    return redirect(url_for("open_chat", chat_id=chat_id))

@app.route("/group/<int:chat_id>/transfer-admin/<int:new_admin_id>", methods=["POST"])
def group_transfer_admin(chat_id, new_admin_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    chat, redirect_resp = require_group_admin(chat_id, me.id)
    if redirect_resp:
        return redirect_resp

    if new_admin_id == me.id:
        flash("You are already admin.", "info")
        return redirect(url_for("open_chat", chat_id=chat_id))

    new_admin = ChatMember.query.filter_by(chat_id=chat_id, user_id=new_admin_id).first()
    if not new_admin:
        flash("That user is not in this group.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    current_admin = ChatMember.query.filter_by(chat_id=chat_id, role="admin").first()
    if current_admin:
        current_admin.role = "member"

    new_admin.role = "admin"
    db.session.commit()

    flash("Admin transferred.", "success")
    return redirect(url_for("open_chat", chat_id=chat_id))

@app.route("/group/<int:chat_id>/delete", methods=["POST"])
def group_delete(chat_id):
    guard = login_required()
    if guard:
        return guard

    me = get_current_user()
    chat, redirect_resp = require_group_admin(chat_id, me.id)
    if redirect_resp:
        return redirect_resp

    db.session.delete(chat)
    db.session.commit()

    flash("Group deleted for everyone.", "success")
    return redirect(url_for("home"))

@app.route("/chat/<int:chat_id>/rename", methods=["POST"])
def rename_group(chat_id):
    guard = login_required()
    if guard:
        return guard

    user = get_current_user()
    new_title = request.form.get("title", "").strip()

    if not new_title:
        flash("Group name can't be empty.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    chat = Chat.query.get_or_404(chat_id)

    if chat.type != "group":
        flash("Only group chats can be renamed.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user.id).first()
    if not membership or membership.role != "admin":
        flash("Only the group admin can rename the group.", "error")
        return redirect(url_for("open_chat", chat_id=chat_id))

    chat.title = new_title
    db.session.commit()

    flash("Group renamed successfully!", "success")
    return redirect(url_for("open_chat", chat_id=chat_id))


if __name__ == "__main__":
    app.run(debug=True)
