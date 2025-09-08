import os
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import smtplib
import ssl
import certifi
import re
from email.mime.text import MIMEText
import requests

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from sqlalchemy import or_, text, func
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables from .env if present
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret')

# Normalize DATABASE_URL for SQLAlchemy (supports postgres:// -> postgresql://)
db_url = os.getenv('DATABASE_URL', 'sqlite:///escalations.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Respect reverse proxy headers (scheme, host, prefix) on PaaS / behind Nginx
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

TEAMS = [
    'International Operations',
    'Domestic Operations',
]

PRIORITIES = ['Low', 'Medium', 'High', 'Urgent']

STATUSES = ['Open', 'In Progress', 'Resolved']


class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)

    source = db.Column(db.String(50))  # Gmail, LinkedIn, WhatsApp, Other
    customer_name = db.Column(db.String(120))
    contact = db.Column(db.String(120))  # email or phone
    booking_id = db.Column(db.String(80))

    team = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), default='Medium', nullable=False)
    status = db.Column(db.String(20), default='Open', nullable=False)

    assigned_to = db.Column(db.String(120))
    # Lead assignee - a single user responsible for the ticket
    lead_assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Comma-separated notification emails for this ticket
    notify_emails = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Track last update time; ensures NOT NULL insert and auto-update on changes
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(120))
    # Relationships
    comments = db.relationship('Comment', backref='ticket', lazy=True, cascade='all, delete-orphan')
    assignees = db.relationship('User', secondary='ticket_assignees', backref='assigned_tickets')
    lead_assignee = db.relationship('User', foreign_keys=[lead_assignee_id], lazy=True)


# Association table for many-to-many Ticket<->User
ticket_assignees = db.Table(
    'ticket_assignees',
    db.Column('ticket_id', db.Integer, db.ForeignKey('tickets.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='agent', nullable=False)  # 'admin' or 'agent'
    department = db.Column(db.String(80))  # International Operations / Domestic Operations

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        # Primary: verify using Werkzeug hash (pbkdf2/scrypt). Handle invalid/legacy hashes safely.
        try:
            if self.password_hash and check_password_hash(self.password_hash, password):
                return True
        except ValueError:
            # e.g., "Invalid hash method ''" from legacy/empty hashes
            pass

        # Fallback: if DB stored plaintext historically, allow once and upgrade hash
        try:
            if self.password_hash == password and password:
                # Upgrade to a secure hash transparently
                self.set_password(password)
                try:
                    db.session.commit()
                except Exception as e:
                    print(f"[warn] failed to upgrade password hash for user {self.id}: {e}")
                return True
        except Exception:
            pass

        return False


class Founder(db.Model):
    __tablename__ = 'founders'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    author = db.Column(db.String(120))
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50))
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'))
    message = db.Column(db.Text)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)


class AppMeta(db.Model):
    __tablename__ = 'app_meta'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(200))


def ensure_schema():
    """Minimal migration to add missing columns when using SQLite."""
    try:
        eng = db.engine
        # Only run these PRAGMA-based adjustments for SQLite
        try:
            dialect = getattr(eng, 'dialect', None)
            name = getattr(dialect, 'name', '') if dialect else ''
            if name and name.lower() == 'postgresql':
                with eng.connect() as conn:
                    # Add column to tickets if missing
                    conn.execute(text("""
                        ALTER TABLE tickets
                        ADD COLUMN IF NOT EXISTS lead_assignee_id INTEGER
                    """))
                    # Create notifications table
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS notifications (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL REFERENCES users(id),
                            type VARCHAR(50),
                            ticket_id INTEGER REFERENCES tickets(id) ON DELETE SET NULL,
                            message TEXT,
                            actor_id INTEGER REFERENCES users(id),
                            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
                            is_read BOOLEAN NOT NULL DEFAULT FALSE
                        )
                    """))
                    # Create app_meta table
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS app_meta (
                            key VARCHAR(50) PRIMARY KEY,
                            value VARCHAR(200)
                        )
                    """))
                    # Helpful indexes
                    conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_notifications_user_created
                        ON notifications(user_id, created_at DESC)
                    """))
                    conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_notifications_ticket
                        ON notifications(ticket_id)
                    """))
                    conn.commit()
                return
            if name and name.lower() != 'sqlite':
                return
        except Exception:
            # If detection fails, proceed conservatively
            pass
        with eng.connect() as conn:
            cols = [row[1] for row in conn.execute(text("PRAGMA table_info(tickets)"))]
            if 'notify_emails' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN notify_emails TEXT"))
                conn.commit()
            if 'updated_at' not in cols:
                # Provide a server default to satisfy NOT NULL on existing rows
                conn.execute(text("ALTER TABLE tickets ADD COLUMN updated_at DATETIME DEFAULT (CURRENT_TIMESTAMP) NOT NULL"))
                conn.commit()
            if 'resolved_at' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN resolved_at DATETIME"))
                conn.commit()
            if 'resolved_by' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN resolved_by VARCHAR(120)"))
                conn.commit()
            if 'lead_assignee_id' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN lead_assignee_id INTEGER"))
                conn.commit()
            # Backfill any NULL updated_at values (covers legacy rows or prior schema)
            try:
                conn.execute(text("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"))
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        print(f"[warn] ensure_schema failed: {e}")


with app.app_context():
    db.create_all()
    ensure_schema()
    # One-time IST migration (optional, guarded by env var and meta flag)
    try:
        do_ist = (os.getenv('APPLY_IST_MIGRATION') or '').strip().lower() in {'1','true','yes','on'}
        done = AppMeta.query.get('ist_shift_done') is not None
        if do_ist and not done:
            shift = timedelta(hours=5, minutes=30)
            # Shift tickets
            try:
                for t in Ticket.query.all():
                    if t.created_at:
                        t.created_at = t.created_at + shift
                    if t.updated_at:
                        t.updated_at = t.updated_at + shift
                    if t.resolved_at:
                        t.resolved_at = t.resolved_at + shift
                db.session.commit()
            except Exception as e:
                print(f"[warn] IST shift tickets failed: {e}")
            # Shift comments
            try:
                for c in Comment.query.all():
                    if c.created_at:
                        c.created_at = c.created_at + shift
                db.session.commit()
            except Exception as e:
                print(f"[warn] IST shift comments failed: {e}")
            try:
                db.session.add(AppMeta(key='ist_shift_done', value=datetime.utcnow().isoformat()))
                db.session.commit()
            except Exception as e:
                print(f"[warn] IST shift meta save failed: {e}")
    except Exception as e:
        print(f"[warn] IST migration block failed: {e}")
    # Bootstrap initial admin if no users exist
    if User.query.count() == 0:
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@deyor.local')
        admin_pass = os.getenv('ADMIN_PASSWORD', 'admin123')
        admin = User(name='Admin', email=admin_email, role='admin', department='International Operations')
        admin.set_password(admin_pass)
        db.session.add(admin)
        db.session.commit()

    # Optional: one-time password reset and role promotion via environment variables
    try:
        reset_email = (os.getenv('RESET_USER_EMAIL') or '').strip()
        reset_pass = (os.getenv('RESET_USER_PASSWORD') or '').strip()
        reset_make_admin = (os.getenv('RESET_USER_MAKE_ADMIN') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
        if reset_email and reset_pass:
            u = None
            try:
                u = User.query.filter(func.lower(User.email) == reset_email.lower()).first()
            except Exception as e:
                print(f"[warn] reset email lookup failed for {reset_email}: {e}")
            if u:
                u.set_password(reset_pass)
                db.session.commit()
                print(f"[info] Password reset via env for user {u.email}")
            else:
                print(f"[warn] RESET_USER_EMAIL specified but no user found: {reset_email}")

        # Allow admin promotion separately (does not require providing a password)
        if reset_email and reset_make_admin:
            u2 = None
            try:
                u2 = User.query.filter(func.lower(User.email) == reset_email.lower()).first()
            except Exception as e:
                print(f"[warn] admin promotion lookup failed for {reset_email}: {e}")
            if u2:
                if u2.role != 'admin':
                    u2.role = 'admin'
                    db.session.commit()
                    print(f"[info] Role promotion via env: {u2.email} -> admin")
                else:
                    print(f"[info] Role promotion skipped: {u2.email} already admin")
            else:
                print(f"[warn] RESET_USER_MAKE_ADMIN set but no user found for: {reset_email}")
    except Exception as e:
        print(f"[warn] env-based password reset failed: {e}")


# Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---- Jinja filter to format datetimes in IST ----
def fmt_dt_ist(dt: datetime, fmt: str = '%Y-%m-%d %H:%M') -> str:
    if not dt:
        return '—'
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo('UTC'))
        return dt.astimezone(ZoneInfo('Asia/Kolkata')).strftime(fmt)
    except Exception:
        try:
            return dt.strftime(fmt)
        except Exception:
            return str(dt)

app.jinja_env.filters['fmt_ist'] = fmt_dt_ist


# ---- Navbar notifications context ----
@app.context_processor
def inject_nav_notifications():
    try:
        if current_user.is_authenticated:
            # Scope navbar dropdown to ONLY the current user's notifications to avoid duplicates
            base_q = Notification.query.filter_by(user_id=current_user.id)
            # Show only unread items in the bell dropdown
            notes = (
                base_q
                .filter_by(is_read=False)
                .order_by(Notification.created_at.desc())
                .limit(10)
                .all()
            )
            unread_count = base_q.filter_by(is_read=False).count()
            return dict(nav_notifications=notes, nav_unread_count=unread_count)
    except Exception as e:
        print(f"[warn] inject_nav_notifications failed: {e}")
    return dict(nav_notifications=[], nav_unread_count=0)


@app.route('/')
def index():
    # If served on support.deyor.in, land users directly on the public submit form
    try:
        host = (request.host or '').lower()
    except Exception:
        host = ''
    if 'support.deyor.in' in host:
        return redirect(url_for('public_submit'))
    return redirect(url_for('list_tickets'))


@app.route('/tickets')
@login_required
def list_tickets():
    team = request.args.get('team', '')
    status = request.args.get('status', '')
    q = request.args.get('q', '').strip()
    date_range = request.args.get('date_range', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()

    # Admin sees all, agents see only tickets assigned to them
    if getattr(current_user, 'role', None) == 'admin':
        query = Ticket.query
    else:
        query = Ticket.query.join(ticket_assignees).filter(ticket_assignees.c.user_id == current_user.id)
    if team:
        query = query.filter(Ticket.team == team)
    if status:
        query = query.filter(Ticket.status == status)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Ticket.subject.ilike(like),
                Ticket.description.ilike(like),
                Ticket.customer_name.ilike(like),
                Ticket.contact.ilike(like),
                Ticket.booking_id.ilike(like),
            )
        )

    # Date range filtering
    start_dt = None
    end_dt = None
    now = datetime.utcnow()
    if date_range == 'today':
        start_dt = datetime(now.year, now.month, now.day)
        end_dt = now
    elif date_range == 'yesterday':
        y = now - timedelta(days=1)
        start_dt = datetime(y.year, y.month, y.day)
        end_dt = datetime(now.year, now.month, now.day)
    elif date_range == 'last7':
        start_dt = now - timedelta(days=7)
        end_dt = now
    elif date_range == 'this_month':
        start_dt = datetime(now.year, now.month, 1)
        end_dt = now
    elif date_range == 'last_month':
        # First day of this month -> go back one day to get last month
        first_this_month = datetime(now.year, now.month, 1)
        last_month_last_day = first_this_month - timedelta(days=1)
        start_dt = datetime(last_month_last_day.year, last_month_last_day.month, 1)
        end_dt = first_this_month
    elif date_range == 'custom':
        try:
            if start_date:
                y, m, d = [int(x) for x in start_date.split('-')]
                start_dt = datetime(y, m, d)
            if end_date:
                y2, m2, d2 = [int(x) for x in end_date.split('-')]
                # end of day
                end_dt = datetime(y2, m2, d2, 23, 59, 59)
        except Exception:
            pass

    if start_dt:
        query = query.filter(Ticket.created_at >= start_dt)
    if end_dt:
        query = query.filter(Ticket.created_at <= end_dt)

    # Compute summary counts on the (possibly) filtered base query
    total_count = query.count()
    open_count = query.filter(Ticket.status == 'Open').count()
    inprog_count = query.filter(Ticket.status == 'In Progress').count()
    resolved_count = query.filter(Ticket.status == 'Resolved').count()

    # Derived metrics
    closed_pct = None
    if total_count > 0:
        try:
            closed_pct = round((resolved_count / total_count) * 100)
        except Exception:
            closed_pct = None

    # Average time to close among resolved tickets within the filtered query
    avg_close_human = '—'
    try:
        resolved_tickets = query.filter(Ticket.status == 'Resolved', Ticket.resolved_at.isnot(None)).all()
        deltas = [
            (t.resolved_at - t.created_at).total_seconds()
            for t in resolved_tickets
            if t.resolved_at and t.created_at and t.resolved_at >= t.created_at
        ]
        if deltas:
            avg_sec = sum(deltas) / len(deltas)
            minutes = int(avg_sec // 60)
            if minutes < 60:
                avg_close_human = f"{minutes}m"
            else:
                hours = minutes // 60
                minutes = minutes % 60
                if hours < 24:
                    avg_close_human = f"{hours}h {minutes}m"
                else:
                    days = hours // 24
                    hours = hours % 24
                    avg_close_human = f"{days}d {hours}h"
    except Exception:
        avg_close_human = '—'

    tickets = query.order_by(Ticket.created_at.desc()).all()
    # Notifications for the dashboard bar
    try:
        # Admins and Founders (by email) see all notifications
        founder_emails = set(e[0].lower() for e in db.session.query(Founder.email).all())
        is_founder_user = (getattr(current_user, 'email', '') or '').lower() in founder_emails
        if getattr(current_user, 'role', None) == 'admin' or is_founder_user:
            notes = Notification.query.order_by(Notification.created_at.desc()).limit(20).all()
        else:
            notes = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(20).all()
        unread_count = sum(1 for n in notes if not n.is_read)
    except Exception:
        notes = []
        unread_count = 0
    return render_template(
        'tickets_list.html',
        tickets=tickets,
        TEAMS=TEAMS,
        PRIORITIES=PRIORITIES,
        STATUSES=STATUSES,
        current_team=team,
        current_status=status,
        q=q,
        total_count=total_count,
        open_count=open_count,
        inprog_count=inprog_count,
        resolved_count=resolved_count,
        closed_pct=closed_pct,
        avg_close_time=avg_close_human,
        current_date_range=date_range,
        start_date=start_date,
        end_date=end_date,
        notifications=notes,
        unread_count=unread_count,
    )


@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        team = request.form.get('team', '').strip() or 'Other'
        priority = request.form.get('priority', 'Medium')
        source = request.form.get('source', '').strip()
        customer_name = request.form.get('customer_name', '').strip()
        contact = request.form.get('contact', '').strip()
        booking_id = request.form.get('booking_id', '').strip()
        assigned_to = request.form.get('assigned_to', '').strip()  # legacy single assignee
        assignee_ids_raw = request.form.getlist('assignees')  # from multi-select/checkboxes
        assignee_ids = [int(x) for x in assignee_ids_raw if x and str(x).isdigit()]
        notify_emails = request.form.get('notify_emails', '').strip()  # legacy
        lead_assignee_raw = (request.form.get('lead_assignee') or '').strip()
        lead_assignee_id = int(lead_assignee_raw) if lead_assignee_raw.isdigit() else None

        # Lead assignee is mandatory
        if not lead_assignee_id:
            flash('Please select a lead assignee.', 'danger')
            return redirect(url_for('new_ticket'))

        # Validate: if a lead is chosen, it must be in selected assignees
        if lead_assignee_id and (lead_assignee_id not in assignee_ids):
            flash('Lead assignee must be one of the selected assignees.', 'danger')
            return redirect(url_for('new_ticket'))

        if not booking_id or not description:
            flash('Booking ID and description are required.', 'danger')
            return redirect(url_for('new_ticket'))

        t = Ticket(
            subject=booking_id,
            description=description,
            team=team if team in TEAMS else 'Domestic Operations',
            priority=priority if priority in PRIORITIES else 'Medium',
            source=source,
            customer_name=customer_name,
            contact=contact,
            booking_id=booking_id,
            assigned_to=assigned_to,
            notify_emails=notify_emails or None,
        )
        # Ensure updated_at is populated on insert to satisfy NOT NULL in SQLite
        t.updated_at = datetime.utcnow()
        if lead_assignee_id:
            t.lead_assignee_id = lead_assignee_id
        # Attach selected assignees
        users = []
        if assignee_ids:
            users = User.query.filter(User.id.in_(assignee_ids)).all()
            for u in users:
                t.assignees.append(u)
        db.session.add(t)
        db.session.commit()
        try:
            notify_created(t)
        except Exception as e:
            print(f"[warn] Failed to send creation notification: {e}")
        # Create in-app notifications
        try:
            create_notifications_for_event('ticket_created', t, f"New ticket #{t.id} created", actor=current_user if getattr(current_user, 'is_authenticated', False) else None)
        except Exception as e:
            print(f"[warn] Failed to create in-app notifications: {e}")
        # Send customer confirmation if email provided or derivable from contact
        try:
            cust_email = extract_email_from_contact(contact)
            if cust_email:
                notify_customer_created(t, cust_email)
        except Exception as e:
            print(f"[warn] Failed to send customer creation email: {e}")
        flash(f'Ticket #{t.id} created.', 'success')
        return redirect(url_for('ticket_detail', ticket_id=t.id))

    agents = User.query.order_by(User.name.asc()).all()
    return render_template('ticket_form.html', TEAMS=TEAMS, PRIORITIES=PRIORITIES, agents=agents)


@app.route('/tickets/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id: int):
    t = Ticket.query.get_or_404(ticket_id)
    if getattr(current_user, 'role', None) != 'admin':
        # Ensure agent is assigned
        assigned_ids = {u.id for u in t.assignees}
        if current_user.id not in assigned_ids:
            flash('You do not have access to this ticket.', 'danger')
            return redirect(url_for('list_tickets'))
    agents = User.query.order_by(User.name.asc()).all()
    return render_template('ticket_detail.html', t=t, STATUSES=STATUSES, agents=agents)


@app.route('/tickets/<int:ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id: int):
    t = Ticket.query.get_or_404(ticket_id)
    body = request.form.get('body', '').strip()
    if not body:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    author = getattr(current_user, 'name', None)
    c = Comment(ticket_id=t.id, author=author or None, body=body)
    db.session.add(c)
    db.session.commit()
    # In-app notifications for comment
    try:
        create_notifications_for_event('comment_added', t, f"New comment on ticket #{t.id}", actor=current_user)
    except Exception as e:
        print(f"[warn] Failed to create comment notifications: {e}")
    flash('Comment added.', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))

 


@app.route('/tickets/<int:ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id: int):
    t = Ticket.query.get_or_404(ticket_id)
    if t.status != 'Resolved':
        t.status = 'Resolved'
        t.resolved_at = datetime.utcnow()
        t.resolved_by = getattr(current_user, 'name', None)
        db.session.commit()
        try:
            notify_resolved(t)
        except Exception as e:
            # Do not block resolution on email errors
            print(f"[warn] Failed to send notification: {e}")
        # In-app notifications
        try:
            create_notifications_for_event('ticket_resolved', t, f"Ticket #{t.id} resolved", actor=current_user)
        except Exception as e:
            print(f"[warn] Failed to create resolve notifications: {e}")
        # Notify customer if we have an email
        try:
            cust_email = extract_email_from_contact(t.contact)
            if cust_email:
                notify_customer_resolved(t, cust_email)
        except Exception as e:
            print(f"[warn] Failed to send customer resolution email: {e}")
        flash('Ticket marked as resolved.', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))


@app.route('/tickets/<int:ticket_id>/status', methods=['POST'])
@login_required
def update_status(ticket_id: int):
    t = Ticket.query.get_or_404(ticket_id)
    new_status = request.form.get('status', '').strip()
    actor = getattr(current_user, 'name', None)
    if new_status not in STATUSES:
        flash('Invalid status.', 'danger')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))

    t.status = new_status
    if new_status == 'Resolved':
        t.resolved_at = datetime.utcnow()
        t.resolved_by = actor
        db.session.commit()
        try:
            notify_resolved(t)
        except Exception as e:
            print(f"[warn] Failed to send notification: {e}")
        try:
            create_notifications_for_event('ticket_resolved', t, f"Ticket #{t.id} resolved", actor=current_user)
        except Exception as e:
            print(f"[warn] Failed to create resolve notifications: {e}")
        # Notify customer if we have an email
        try:
            cust_email = extract_email_from_contact(t.contact)
            if cust_email:
                notify_customer_resolved(t, cust_email)
        except Exception as e:
            print(f"[warn] Failed to send customer resolution email: {e}")
        flash('Ticket marked as resolved.', 'success')
    else:
        # Clear resolution metadata when reopening or moving to in-progress
        t.resolved_at = None
        t.resolved_by = None
        db.session.commit()
        try:
            create_notifications_for_event('status_changed', t, f"Ticket #{t.id} status: {new_status}", actor=current_user)
        except Exception as e:
            print(f"[warn] Failed to create status notifications: {e}")
        flash(f'Status updated to {new_status}.', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))


@app.route('/tickets/<int:ticket_id>/delete', methods=['POST'])
@login_required
def delete_ticket(ticket_id: int):
    if not admin_required():
        return redirect(url_for('list_tickets'))
    t = Ticket.query.get_or_404(ticket_id)
    # Clean up association rows to avoid orphans
    try:
        db.session.execute(text("DELETE FROM ticket_assignees WHERE ticket_id = :tid"), {"tid": t.id})
    except Exception as e:
        print(f"[warn] failed to clean ticket_assignees for ticket {t.id}: {e}")
    db.session.delete(t)
    db.session.commit()
    flash('Ticket deleted.', 'success')
    return redirect(url_for('list_tickets'))


# ---- Ticket transfer (change lead assignee) ----
@app.route('/tickets/<int:ticket_id>/transfer', methods=['POST'])
@login_required
def transfer_ticket(ticket_id: int):
    t = Ticket.query.get_or_404(ticket_id)
    # Permission: must be admin or currently assigned on ticket
    if getattr(current_user, 'role', None) != 'admin':
        assigned_ids = {u.id for u in t.assignees}
        if current_user.id not in assigned_ids:
            flash('You do not have permission to transfer this ticket.', 'danger')
            return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    new_lead_raw = (request.form.get('new_lead') or '').strip()
    if not new_lead_raw.isdigit():
        flash('Invalid selection.', 'danger')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    new_lead_id = int(new_lead_raw)
    try:
        new_lead = User.query.get(new_lead_id)
        if not new_lead:
            raise ValueError('User not found')
        t.lead_assignee_id = new_lead_id
        # Ensure new lead is in assignees
        if new_lead not in t.assignees:
            t.assignees.append(new_lead)
        db.session.commit()
        try:
            create_notifications_for_event('ticket_transferred', t, f"Ticket #{t.id} lead transferred to {new_lead.name}", actor=current_user)
        except Exception as e:
            print(f"[warn] Failed to create transfer notifications: {e}")
        flash('Lead transferred.', 'success')
    except Exception as e:
        print(f"[warn] transfer failed: {e}")
        flash('Transfer failed.', 'danger')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))


# ---- Notifications helpers & endpoints ----
def recipients_for_ticket(ticket: Ticket) -> list[int]:
    ids = set()
    # All assignees
    for u in ticket.assignees:
        if u and u.id:
            ids.add(u.id)
    # Lead
    if ticket.lead_assignee_id:
        ids.add(ticket.lead_assignee_id)
    # Admins get all
    try:
        for u in User.query.filter_by(role='admin').all():
            if u and u.id:
                ids.add(u.id)
        # Founders: map by email to user accounts, include them
        founder_emails = set(e[0].lower() for e in db.session.query(Founder.email).all())
        if founder_emails:
            for u in User.query.filter(func.lower(User.email).in_(founder_emails)).all():
                if u and u.id:
                    ids.add(u.id)
    except Exception:
        pass
    return list(ids)


def create_notifications_for_event(kind: str, ticket: Ticket, message: str, actor: User | None = None) -> None:
    try:
        ids = recipients_for_ticket(ticket)
        for uid in ids:
            # Deduplicate: if an unread notification of same type/ticket already exists for this user, skip creating another
            try:
                exists = (
                    Notification.query
                    .filter_by(user_id=uid, type=kind, ticket_id=ticket.id, is_read=False)
                    .first()
                )
            except Exception:
                exists = None
            if exists is None:
                n = Notification(
                    user_id=uid,
                    type=kind,
                    ticket_id=ticket.id,
                    message=message,
                    actor_id=(actor.id if actor else None),
                )
                db.session.add(n)
        db.session.commit()
    except Exception as e:
        print(f"[warn] create_notifications_for_event failed: {e}")


@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        q = Notification.query.filter_by(user_id=current_user.id)
        for n in q.filter_by(is_read=False).all():
            n.is_read = True
        db.session.commit()
        flash('Notifications marked as read.', 'success')
    except Exception as e:
        print(f"[warn] mark_all_notifications_read failed: {e}")
    # Return user to the same page/dropdown context when possible
    return redirect(request.referrer or url_for('list_tickets'))


# ---- Notifications UI ----
@app.route('/notifications')
@login_required
def notifications_list():
    """List notifications for the current user with pagination.
    The bell dropdown only shows unread; this page can show unread or all.
    """
    try:
        status = (request.args.get('status') or 'unread').strip().lower()
        page = int((request.args.get('page') or '1').strip() or '1')
        per_page = 20
    except Exception:
        status = 'unread'
        page = 1
        per_page = 20

    base_q = Notification.query.filter_by(user_id=current_user.id)
    if status == 'all':
        q = base_q
    else:
        q = base_q.filter_by(is_read=False)

    total = q.count()
    pages = (total + per_page - 1) // per_page if per_page else 1
    items = (
        q.order_by(Notification.created_at.desc())
         .offset((page - 1) * per_page)
         .limit(per_page)
         .all()
    )

    return render_template(
        'notifications.html',
        items=items,
        status=status,
        page=page,
        pages=pages,
        total=total,
    )


@app.route('/notifications/<int:nid>/read', methods=['POST'])
@login_required
def mark_notification_read(nid: int):
    """Mark a single notification as read if it belongs to the current user."""
    try:
        n = Notification.query.get_or_404(nid)
        if n.user_id == current_user.id:
            n.is_read = True
            db.session.commit()
            flash('Notification marked as read.', 'success')
    except Exception as e:
        print(f"[warn] mark_notification_read failed: {e}")
    return redirect(request.referrer or url_for('notifications_list'))


@app.route('/notifications/<int:nid>/go')
@login_required
def go_notification(nid: int):
    """Open a notification target (ticket) and mark it read for the current user."""
    try:
        n = Notification.query.get_or_404(nid)
        if n.user_id == current_user.id and not n.is_read:
            n.is_read = True
            db.session.commit()
        if n.ticket_id:
            return redirect(url_for('ticket_detail', ticket_id=n.ticket_id))
    except Exception as e:
        print(f"[warn] go_notification failed: {e}")
    return redirect(url_for('notifications_list'))


def notify_resolved(ticket: Ticket) -> None:
    # Recipients: assigned users + all admins only
    recipients = set()
    # Include legacy single assignee if present
    if ticket.assigned_to and '@' in ticket.assigned_to:
        recipients.add(ticket.assigned_to.strip())
    for u in ticket.assignees:
        if u.email:
            recipients.add(u.email)
    # Include all admins
    admin_emails = [u.email for u in User.query.filter_by(role='admin').all() if u.email]
    recipients.update(admin_emails)
    # Include per-ticket extra recipients (comma-separated)
    recipients.update(parse_emails(getattr(ticket, 'notify_emails', None)))
    # Include team default recipients from env, e.g. TEAM_EMAILS_INTERNATIONAL_OPERATIONS
    recipients.update(get_team_default_emails(ticket.team))
    # Include global notify list if provided via NOTIFY_EMAILS env
    recipients.update(parse_emails(os.getenv('NOTIFY_EMAILS', '')))
    if not recipients:
        print("[info] notify_resolved: no recipients; skipping send")
        return  # notifications disabled entirely

    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    if not smtp_host or not smtp_user or not smtp_pass:
        print("[info] notify_resolved: SMTP config incomplete; skipping send")
        return

    subject = f"Ticket #{ticket.id} resolved: {ticket.subject}"
    link = os.getenv('BASE_URL', 'http://localhost:5000') + url_for('ticket_detail', ticket_id=ticket.id)
    body = (
        f"Ticket #{ticket.id} has been resolved.\n\n"
        f"Subject: {ticket.subject}\n"
        f"Team: {ticket.team}\n"
        f"Priority: {ticket.priority}\n"
        f"Resolved by: {ticket.resolved_by or 'Unknown'} at {ticket.resolved_at}\n\n"
        f"Link: {link}\n\n"
        f"--- Description ---\n{ticket.description}\n"
    )
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = f"Undisclosed recipients <{smtp_user}>"

    context = ssl.create_default_context(cafile=certifi.where())
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=sorted(recipients))
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=sorted(recipients))


def notify_customer_created(ticket: Ticket, to_email: str) -> None:
    """Send a confirmation email to the end-customer after ticket creation."""
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    if not smtp_host or not smtp_user or not smtp_pass:
        print("[info] notify_customer_created: SMTP config incomplete; skipping send")
        return

    subject = f"Your Deyor ticket #{ticket.id} has been created"
    body = (
        f"Hello{(' ' + ticket.customer_name) if ticket.customer_name else ''},\n\n"
        f"Thanks for reaching out. Your ticket has been created and sent to our {ticket.team} team.\n\n"
        f"Ticket ID: {ticket.id}\n"
        f"Subject: {ticket.subject}\n"
        f"Team: {ticket.team}\n"
        f"Priority: {ticket.priority}\n"
        f"Created: {ticket.created_at}\n\n"
        f"--- Details you submitted ---\n{ticket.description}\n\n"
        f"We’ll update you as soon as possible.\n"
    )
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_email

    context = ssl.create_default_context(cafile=certifi.where())
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=[to_email])
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=[to_email])


def notify_customer_resolved(ticket: Ticket, to_email: str) -> None:
    """Send a resolution email to the end-customer when ticket is resolved."""
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    if not smtp_host or not smtp_user or not smtp_pass:
        print("[info] notify_customer_resolved: SMTP config incomplete; skipping send")
        return

    subject = f"Your Deyor ticket #{ticket.id} has been resolved"
    body = (
        f"Hello{(' ' + ticket.customer_name) if ticket.customer_name else ''},\n\n"
        f"We’re writing to let you know your ticket has been marked resolved.\n\n"
        f"Ticket ID: {ticket.id}\n"
        f"Subject: {ticket.subject}\n"
        f"Team: {ticket.team}\n"
        f"Resolved by: {ticket.resolved_by or 'Team'} at {ticket.resolved_at}\n\n"
        f"If this doesn’t address your concern, just reply to this email and we’ll reopen it.\n"
    )
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_email

    context = ssl.create_default_context(cafile=certifi.where())
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=[to_email])
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=[to_email])

def parse_emails(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [e.strip() for e in raw.split(',') if e.strip()]


def extract_email_from_contact(contact: str | None) -> str | None:
    """Best-effort extraction of a single email from a free-form contact string."""
    if not contact:
        return None
    m = re.search(r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', contact)
    return m.group(1) if m else None


def get_team_default_emails(team: str) -> list[str]:
    """Read default email recipients for a team from environment.
    Team name is converted to upper snake-case, e.g. 'International Operations' -> TEAM_EMAILS_INTERNATIONAL_OPERATIONS
    """
    env_key = 'TEAM_EMAILS_' + (team or '').upper().replace(' ', '_')
    return parse_emails(os.getenv(env_key, ''))


def notify_created(ticket: Ticket) -> None:
    # Recipients: assigned users + all admins only
    recipients = set()
    # Include legacy single assignee if present
    if ticket.assigned_to and '@' in ticket.assigned_to:
        recipients.add(ticket.assigned_to.strip())
    for u in ticket.assignees:
        if u.email:
            recipients.add(u.email)
    # Include all admins
    admin_emails = [u.email for u in User.query.filter_by(role='admin').all() if u.email]
    recipients.update(admin_emails)
    # Include per-ticket extra recipients (comma-separated)
    recipients.update(parse_emails(getattr(ticket, 'notify_emails', None)))
    # Include team default recipients from env, e.g. TEAM_EMAILS_INTERNATIONAL_OPERATIONS
    recipients.update(get_team_default_emails(ticket.team))
    # Include global notify list if provided via NOTIFY_EMAILS env
    recipients.update(parse_emails(os.getenv('NOTIFY_EMAILS', '')))
    if not recipients:
        print("[info] notify_created: no recipients; skipping send")
        return

    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    if not smtp_host or not smtp_user or not smtp_pass:
        print("[info] notify_created: SMTP config incomplete; skipping send")
        return

    subject = f"New Ticket #{ticket.id}: {ticket.subject}"
    link = os.getenv('BASE_URL', 'http://localhost:5000') + url_for('ticket_detail', ticket_id=ticket.id)
    body = (
        f"A new escalation has been created.\n\n"
        f"Subject: {ticket.subject}\n"
        f"Team: {ticket.team}\n"
        f"Priority: {ticket.priority}\n"
        f"Created: {ticket.created_at}\n\n"
        f"Link: {link}\n\n"
        f"--- Details ---\n{ticket.description}\n"
    )
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = f"Undisclosed recipients <{smtp_user}>"

    context = ssl.create_default_context(cafile=certifi.where())
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=sorted(recipients))
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg, from_addr=smtp_user, to_addrs=sorted(recipients))


# Admin: manage users (team members)
def admin_required():
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return False
    return True


@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not admin_required():
        return redirect(url_for('list_tickets'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        role = request.form.get('role', 'agent')
        department = request.form.get('department', '')
        password = request.form.get('password', '').strip()
        if not name or not email or not password:
            flash('Name, email and password are required.', 'danger')
            return redirect(url_for('admin_users'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('admin_users'))
        u = User(name=name, email=email, role=role, department=department)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Team member added.', 'success')
        return redirect(url_for('admin_users'))
    users = User.query.order_by(User.role.desc(), User.name.asc()).all()
    return render_template('admin_users.html', users=users, TEAMS=TEAMS)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id: int):
    if not admin_required():
        return redirect(url_for('list_tickets'))
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("You can't delete your own account.", 'danger')
        return redirect(url_for('admin_users'))
    if u.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
        flash("Can't delete the last admin.", 'danger')
        return redirect(url_for('admin_users'))
    # Detach from any assigned tickets and clean association rows
    try:
        db.session.execute(text("DELETE FROM ticket_assignees WHERE user_id = :uid"), {'uid': u.id})
    except Exception as e:
        print(f"[warn] failed to clean ticket_assignees for user {u.id}: {e}")
    db.session.delete(u)
    db.session.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/founders', methods=['GET', 'POST'])
@login_required
def admin_founders():
    if not admin_required():
        return redirect(url_for('list_tickets'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        if not name or not email:
            flash('Name and email are required.', 'danger')
            return redirect(url_for('admin_founders'))
        f = Founder(name=name, email=email)
        db.session.add(f)
        db.session.commit()
        flash('Founder added.', 'success')
        return redirect(url_for('admin_founders'))
    founders = Founder.query.order_by(Founder.name.asc()).all()
    return render_template('admin_founders.html', founders=founders)


# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        user = None
        try:
            if email:
                user = User.query.filter(func.lower(User.email) == email.lower()).first()
        except Exception as e:
            print(f"[warn] login email lookup failed for {email}: {e}")
        ok = False
        if user:
            try:
                ok = user.check_password(password)
            except Exception as e:
                # Do not leak details to the user; log and treat as invalid
                print(f"[warn] password verification error for {email}: {e}")
                ok = False
        if ok:
            login_user(user)
            return redirect(url_for('list_tickets'))
        flash('Invalid credentials.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Health and readiness endpoints for Render
@app.route('/health')
def health():
    return {'status': 'ok'}


@app.route('/ready')
def ready():
    try:
        db.session.execute(text('SELECT 1'))
        return {'status': 'ready'}
    except Exception:
        return {'status': 'degraded'}, 503


# Temporary debug endpoint to verify DB connection target and data presence
@app.route('/debug/db')
def debug_db():
    try:
        # Identify current database name
        with db.engine.connect() as conn:
            dbname = conn.execute(text('SELECT current_database()')).scalar()

        # Check counts for expected tables; mark as 'missing' if table not found
        tables = ['tickets', 'users', 'comments', 'founders', 'ticket_assignees']
        counts = {}
        for t in tables:
            try:
                counts[t] = db.session.execute(text(f'SELECT COUNT(*) FROM {t}')).scalar()
            except Exception:
                counts[t] = 'missing'

        return {
            'database': dbname,
            'counts': counts,
        }
    except Exception as e:
        return {'error': str(e)}, 500


# Temporary debug endpoint to list users (read-only)
@app.route('/debug/users')
def debug_users():
    try:
        q = (request.args.get('q') or '').strip()
        query = User.query
        if q:
            like = f"%{q.lower()}%"
            query = query.filter(func.lower(User.email).like(like) | func.lower(User.name).like(like))
        rows = query.with_entities(User.id, User.email, User.role, User.name).order_by(User.id.asc()).all()
        return {
            'users': [
                {'id': r[0], 'email': r[1], 'role': r[2], 'name': r[3]}
                for r in rows
            ]
        }
    except Exception as e:
        return {'error': str(e)}, 500

# -------- Public submission + auto-assignment helpers --------
INTERNATIONAL_KEYWORDS = {
    # Countries/regions and popular cities (non-exhaustive)
    'maldives', 'bali', 'indonesia', 'vietnam', 'thailand', 'dubai', 'uae', 'united arab emirates',
    'malaysia', 'sri lanka', 'srilanka', 'singapore', 'turkey', 'istanbul', 'antalya', 'georgia',
    'tbilisi', 'azerbaijan', 'baku', 'armenia', 'almaty', 'kazakhstan', 'mauritius', 'seychelles',
    'phuket', 'krabi', 'bangkok', 'pattaya', 'hanoi', 'da nang', 'danang', 'ho chi minh', 'saigon',
    'hoi an', 'kuala lumpur', 'langkawi', 'colombo', 'bentota', 'negombo', 'male', 'maafushi',
    'phu quoc', 'doha', 'qatar', 'oman', 'muscat', 'jordan', 'amman', 'egypt', 'cairo', 'sharm',
}

DOMESTIC_KEYWORDS = {
    # India markers
    'india', 'indian', '+91',
    # States/UTs
    'ladakh', 'jammu', 'kashmir', 'jk', 'himachal', 'uttarakhand', 'punjab', 'haryana', 'rajasthan',
    'gujarat', 'maharashtra', 'goa', 'karnataka', 'kerala', 'tamil nadu', 'andhra pradesh',
    'telangana', 'odisha', 'chhattisgarh', 'madhya pradesh', 'bihar', 'jharkhand', 'west bengal',
    'sikkim', 'assam', 'meghalaya', 'arunachal', 'nagaland', 'manipur', 'mizoram', 'tripura',
    'andaman', 'nicobar', 'puducherry', 'pondicherry', 'delhi', 'ncr',
    # Popular domestic destinations & localities
    'manali', 'shimla', 'kasol', 'spiti', 'kaza', 'kibber', 'kinnaur', 'sangla', 'kalpa', 'jibhi',
    'tirthan', 'rishikesh', 'haridwar', 'nainital', 'mussoorie', 'auli', 'kasauli', 'dharamshala',
    'mcleodganj', 'dalhousie', 'khajjiar', 'leh', 'nubra', 'pangong', 'kargil', 'sonamarg', 'gulmarg',
    'pahalgam', 'srinagar', 'goa', 'jaipur', 'udaipur', 'jodhpur', 'jaisalmer', 'agra', 'varanasi',
    'khajuraho', 'rann of kutch', 'kutch', 'somnath', 'dwarka', 'saputara', 'mumbai', 'pune',
    'lonavala', 'mahabaleshwar', 'alibaug', 'bangalore', 'bengaluru', 'mysore', 'coorg', 'ooty',
    'kodaikanal', 'pondy', 'pondicherry', 'chennai', 'hyderabad', 'ahmedabad', 'surat', 'kolkata',
    'darjeeling', 'sundarbans', 'gangtok', 'lachung', 'lachen', 'pelling', 'kaziranga', 'shillong',
    'cherrapunji', 'cherrapunjee', 'dawki', 'tawang', 'bomdila', 'ziro', 'kohima', 'imphal', 'aizawl',
    'agartala', 'bhubaneswar', 'puri', 'konark', 'gokarna', 'hampi', 'hamta', 'bir', 'billing',
    'andaman', 'port blair', 'havelock', 'neil island', 'lakshadweep', 'minicoy',
}

def _norm_text(s: str | None) -> str:
    return re.sub(r'[^a-z0-9\s]', ' ', (s or '').lower())


def detect_team_from_text(text: str) -> str:
    s = _norm_text(text)
    # Domestic if any Indian indicator matches
    for kw in DOMESTIC_KEYWORDS:
        if kw in s:
            return 'Domestic Operations'
    # International if any foreign indicator matches
    for kw in INTERNATIONAL_KEYWORDS:
        if kw in s:
            return 'International Operations'
    # Heuristics
    if 'visa' in s or 'passport' in s or 'international' in s:
        return 'International Operations'
    # Default: treat as International per brief (any other international destination)
    return 'International Operations'


def assign_all_in_team(ticket: Ticket, team: str) -> None:
    users = User.query.filter_by(department=team).all()
    for u in users:
        if u not in ticket.assignees:
            ticket.assignees.append(u)


@app.route('/submit', methods=['GET', 'POST'])
def public_submit():
    provider = (os.getenv('CAPTCHA_PROVIDER') or '').strip().lower()
    site_key = (os.getenv('CAPTCHA_SITE_KEY') or '').strip()
    secret = (os.getenv('CAPTCHA_SECRET') or '').strip()
    if request.method == 'POST':
        # Honeypot anti-spam field: real users won't see/fill this
        honeypot = (request.form.get('website') or '').strip()
        if honeypot:
            flash('Thanks! We will get back to you shortly.', 'success')
            return redirect(url_for('public_submit'))

        # Optional CAPTCHA verification (only if provider and keys are present)
        if provider in ('turnstile', 'hcaptcha') and site_key and secret:
            try:
                if provider == 'turnstile':
                    token = (request.form.get('cf-turnstile-response') or '').strip()
                    if not token:
                        raise ValueError('captcha_missing')
                    resp = requests.post(
                        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                        data={
                            'secret': secret,
                            'response': token,
                            'remoteip': request.remote_addr or ''
                        },
                        timeout=5
                    )
                    data = {}
                    try:
                        data = resp.json() if resp is not None else {}
                    except Exception:
                        data = {}
                    ok = resp.ok and data.get('success') is True
                    if not ok:
                        print(f"[warn] turnstile verify failed: status={getattr(resp, 'status_code', 'n/a')} body={data}")
                        flash('Please complete the verification and try again.', 'danger')
                        return redirect(url_for('public_submit'))
                elif provider == 'hcaptcha':
                    token = (request.form.get('h-captcha-response') or '').strip()
                    if not token:
                        raise ValueError('captcha_missing')
                    resp = requests.post(
                        'https://hcaptcha.com/siteverify',
                        data={
                            'secret': secret,
                            'response': token,
                            'remoteip': request.remote_addr or ''
                        },
                        timeout=5
                    )
                    data = {}
                    try:
                        data = resp.json() if resp is not None else {}
                    except Exception:
                        data = {}
                    ok = resp.ok and data.get('success') is True
                    if not ok:
                        print(f"[warn] hcaptcha verify failed: status={getattr(resp, 'status_code', 'n/a')} body={data}")
                        flash('Please complete the verification and try again.', 'danger')
                        return redirect(url_for('public_submit'))
            except Exception as e:
                # Fail closed with a friendly message (but do not 500)
                print(f"[warn] captcha exception: {e}")
                flash('Verification failed. Please try again.', 'danger')
                return redirect(url_for('public_submit'))

        customer_name = (request.form.get('customer_name') or '').strip()
        phone = (request.form.get('phone') or '').strip()
        email = (request.form.get('email') or '').strip()
        booking_id = (request.form.get('booking_id') or '').strip()
        destination = (request.form.get('destination') or '').strip()
        concerns = (request.form.get('concerns') or '').strip()

        if not (destination or concerns):
            flash('Please provide a destination or concerns for your escalation.', 'danger')
            return redirect(url_for('public_submit'))

        # Build a combined contact string for storage
        contact_parts = []
        if phone:
            contact_parts.append(f"Phone: {phone}")
        if email:
            contact_parts.append(f"Email: {email}")
        contact = ', '.join(contact_parts)

        subject = (booking_id or destination or (customer_name and f"Escalation from {customer_name}") or 'Escalation')[:200]
        detection_text = ' '.join([booking_id, destination, concerns, phone, email])
        team = detect_team_from_text(detection_text)

        t = Ticket(
            subject=subject,
            description=(f"Destination: {destination}\n\nConcerns: {concerns}" if destination else f"Concerns: {concerns}"),
            team=team,
            priority='Medium',
            source='Public Form',
            customer_name=customer_name or None,
            contact=contact or None,
            booking_id=booking_id or None,
        )
        t.updated_at = datetime.utcnow()
        assign_all_in_team(t, team)
        db.session.add(t)
        db.session.commit()

        try:
            notify_created(t)
        except Exception as e:
            print(f"[warn] Failed to send creation notification: {e}")
        # In-app notifications for public-created ticket
        try:
            create_notifications_for_event('ticket_created', t, f"New ticket #{t.id} created", actor=None)
        except Exception as e:
            print(f"[warn] Failed to create public ticket notifications: {e}")
        # Send customer confirmation if email provided or derivable from contact
        try:
            cust_email = (email or '').strip() or extract_email_from_contact(contact)
            if cust_email:
                notify_customer_created(t, cust_email)
        except Exception as e:
            print(f"[warn] Failed to send customer creation email: {e}")

        return render_template('public_thanks.html', ticket=t)

    return render_template('public_submit.html', CAPTCHA_PROVIDER=provider, CAPTCHA_SITE_KEY=site_key, CAPTCHA_SECRET=secret)


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=True)
