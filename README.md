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

## Public Submission (No Login)

- Route: `GET/POST /submit`
- Purpose: let customers create a ticket without logging in. They can provide their destination in free text; the system auto-detects the correct team.
- Form fields:
  - Booking/Trip ID (optional)
  - Destination (free text, optional)
  - Details/Description (optional but recommended)
  - Customer Name (optional)
  - Contact (email or phone, optional)

### Destination detection and auto-assignment

- Keyword-based detection decides team:
  - International markers: see `INTERNATIONAL_KEYWORDS` in `app.py`.
  - Domestic (India) markers: see `DOMESTIC_KEYWORDS` in `app.py`.
  - Extra heuristics: mentions like `visa`, `passport`, or `international` force International.
  - Default fallback: International if nothing matches.
- Assignment strategy:
  - The helper `assign_all_in_team(ticket, team)` assigns the ticket to all `User`s whose `department` matches the detected team.
  - Email notifications go to all assignees and all admins.

### Customize keywords/rules

- Edit the sets `INTERNATIONAL_KEYWORDS` and `DOMESTIC_KEYWORDS` in `app.py`.
- Add/remove cities, countries, and Indian states/regions as needed.
- You can also adjust the fallback or heuristics in `detect_team_from_text()`.

### Test locally

1) Run the app and open `http://localhost:5000/submit`.
2) Try a few examples:
   - Destination: `Phuket` (should assign International Operations)
   - Destination: `Manali` (should assign Domestic Operations)
   - Description contains `visa` (assigns International Operations)
3) After submission, you’ll see a thank-you page with the ticket ID and team.

4) Login
- Visit `/login` and use the initial admin credentials you set in `.env`.
- Admin can add team members and founders via the navbar Admin menu.

5) Branding (optional)
- Place `Deyor` logo at `static/css/img/Deyor Logo 2025.png` (navbar uses this path).

## Notes
- SQLite DB path defaults to `escalations.db` in the project. You can point `DATABASE_URL` to Postgres/MySQL later.
- Emails: creation and resolution notifications currently go to all assignees and all admins. Team default recipient lists and founders CC are not used in the current implementation.

## Health & Readiness

- Endpoints:
  - Health: `GET /health` → `{ "status": "ok" }`
  - Readiness: `GET /ready` → `{ "status": "ready" }` (503 if DB not ready)
- Render: set Health Check Path to `/health` (already in `render.yaml`).

## Runbook (Operations)

- Redeploy
  - Push to `main` → Render auto-deploys.
  - Or click “Deploy latest commit” in Render Web Service.

- Environment changes
  - Update env vars in Render → Save → redeploy.
  - `BASE_URL` should be `https://escalations.deyor.in` in production.

- Reset a user’s password (admin or agent)
  - Option A (Python script using `DATABASE_URL`):
    ```python
    # reset_password.py
    import os
    from sqlalchemy import create_engine, text
    from werkzeug.security import generate_password_hash
    db = create_engine(os.environ['DATABASE_URL'].replace('postgres://','postgresql://',1))
    email = 'admin@deyor.local'
    new_hash = generate_password_hash('NEW_PASSWORD')
    with db.begin() as cx:
        cx.execute(text('UPDATE users SET password_hash=:h WHERE email=:e'), {'h': new_hash, 'e': email})
    print('done')
    ```
    Run locally with `DATABASE_URL` exported (from Render DB page) or via a one-off job.

- Backups / Restore (Render Postgres)
  - Verify automatic backups/snapshots in the Render Postgres dashboard.
  - Create on-demand snapshot before major changes.
  - Note the restore procedure from a snapshot to a new DB and re-point `DATABASE_URL`.

- Uptime monitoring
  - Add an HTTPS monitor in UptimeRobot/BetterStack for `https://escalations.deyor.in` every 1–5 min.
  - Alert contacts: ops team emails and/or Slack webhook.

## Production Tips

- Keep `BASE_URL` in Render set to your custom domain so email links are correct.
- Use an app-password-enabled SMTP or switch to SES/Resend/SendGrid for better deliverability.
