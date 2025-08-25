# Deyor Escalations

Flask + SQLite app to capture, track, and resolve customer escalations with authentication, roles, multi‑assignee support, and email notifications.

## Features
- Create tickets with Booking ID, team, priority, and description
- Multi-select assignees (agents); ticket visibility is role/assignee-based
- List and filter by team, status, and search (subject/description/customer/contact/booking)
- Ticket detail with comments (author auto-filled from logged-in user)
- Status updates (Open/In Progress/Resolved) with resolution metadata
- Email notifications on creation and resolution
  - Team default recipients + explicit per-ticket notify emails
  - Assignees included; founders CC on creation
- Admin pages to manage team members and founders CC list

## Quickstart

1) Create a Python virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2) Configure environment. Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
```

- `FLASK_SECRET_KEY`: any random string
- `DATABASE_URL`: default uses SQLite in the project directory
- `BASE_URL`: keep default `http://localhost:5000` for local testing
- SMTP (optional for notifications): `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`
- Team default recipients for creation emails:
  - `TEAM_EMAILS_INTERNATIONAL_OPERATIONS`
  - `TEAM_EMAILS_DOMESTIC_OPERATIONS`
  - Values are comma-separated emails, e.g. `ops@deyor,lead@deyor`
- Initial admin bootstrap (auto-created on first run if no users exist):
  - `ADMIN_EMAIL`, `ADMIN_PASSWORD`

3) Run the app:

```bash
python app.py
```

Open http://localhost:5000

4) Login
- Visit `/login` and use the initial admin credentials you set in `.env`.
- Admin can add team members and founders via the navbar Admin menu.

5) Branding (optional)
- Place `Deyor` logo at `static/css/img/deyor-logo.png` (navbar uses this path).

## Notes
- SQLite DB path defaults to `escalations.db` in the project. You can point `DATABASE_URL` to Postgres/MySQL later.
- Emails: on ticket creation we include team defaults, per-ticket notify emails, all assignees, and CC founders. On resolution we include team defaults, per-ticket notify emails, assignees, and optionally use global `NOTIFY_EMAILS` as a fallback.
