import os
from datetime import datetime, timedelta
import smtplib
import ssl
import certifi
from email.mime.text import MIMEText

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from sqlalchemy import or_, text
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
        return check_password_hash(self.password_hash, password)


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


def ensure_schema():
    """Minimal migration to add missing columns when using SQLite."""
    try:
        eng = db.engine
        with eng.connect() as conn:
            cols = [row[1] for row in conn.execute(text("PRAGMA table_info(tickets)"))]
            if 'notify_emails' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN notify_emails TEXT"))
                conn.commit()
            if 'updated_at' not in cols:
                # Provide a server default to satisfy NOT NULL on existing rows
                conn.execute(text("ALTER TABLE tickets ADD COLUMN updated_at DATETIME DEFAULT (CURRENT_TIMESTAMP) NOT NULL"))
                conn.commit()
            # Backfill any NULL updated_at values (covers legacy rows or prior schema)
            try:
                conn.execute(text("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"))
                conn.commit()
            except Exception:
                pass
            if 'resolved_at' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN resolved_at DATETIME"))
                conn.commit()
            if 'resolved_by' not in cols:
                conn.execute(text("ALTER TABLE tickets ADD COLUMN resolved_by VARCHAR(120)"))
                conn.commit()
    except Exception as e:
        print(f"[warn] ensure_schema failed: {e}")


with app.app_context():
    db.create_all()
    ensure_schema()
    # Bootstrap initial admin if no users exist
    if User.query.count() == 0:
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@deyor.local')
        admin_pass = os.getenv('ADMIN_PASSWORD', 'admin123')
        admin = User(name='Admin', email=admin_email, role='admin', department='International Operations')
        admin.set_password(admin_pass)
        db.session.add(admin)
        db.session.commit()


# Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
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
    return render_template('tickets_list.html', tickets=tickets, TEAMS=TEAMS, PRIORITIES=PRIORITIES, STATUSES=STATUSES, current_team=team, current_status=status, q=q, total_count=total_count, open_count=open_count, inprog_count=inprog_count, resolved_count=resolved_count, closed_pct=closed_pct, avg_close_time=avg_close_human, current_date_range=date_range, start_date=start_date, end_date=end_date)


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
    return render_template('ticket_detail.html', t=t, STATUSES=STATUSES)


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
        flash('Ticket marked as resolved.', 'success')
    else:
        # Clear resolution metadata when reopening or moving to in-progress
        t.resolved_at = None
        t.resolved_by = None
        db.session.commit()
        flash(f'Status updated to {new_status}.', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))


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


def parse_emails(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [e.strip() for e in raw.split(',') if e.strip()]


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
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
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


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=True)
