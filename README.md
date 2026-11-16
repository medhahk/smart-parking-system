# SmartPark — Smart Parking Management

A faculty-presentation-ready parking management web application built with Flask and MySQL. It includes a responsive operations dashboard with charts, a customer portal, role-based workflows, reservation/parking/payment records, and audit history.

## What it demonstrates

- A normalized, relational MySQL schema with primary/foreign keys, unique constraints, indexes, and status enums
- Role-based access for administrators, parking staff, and customers
- Smart slot allocation for cars, motorcycles, trucks, and EVs
- Transactional booking, check-in, checkout, payment, and reservation-expiry workflows
- Time-based parking charges, occupancy/revenue analytics, and an audit log
- Password hashing, CSRF-protected forms, parameterized SQL, and secure session-cookie defaults

## Requirements

- Python 3.10+
- MySQL Server 8.0+

## Setup on Windows

1. Start MySQL Server and create an application user. For example, from a MySQL administrator account:

   ```sql
   CREATE USER 'smartpark'@'127.0.0.1' IDENTIFIED BY 'choose-a-password';
   GRANT ALL PRIVILEGES ON smartpark.* TO 'smartpark'@'127.0.0.1';
   GRANT CREATE ON *.* TO 'smartpark'@'localhost';
   ```

   The extra `CREATE` privilege is needed only for the initial `init-db` command, which creates the `smartpark` database. It can be revoked after initialization.

2. In PowerShell, from the project folder:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   $env:MYSQL_HOST = "127.0.0.1"
   $env:MYSQL_PORT = "3306"
   $env:MYSQL_USER = "smartpark"
   $env:MYSQL_PASSWORD = "choose-a-password"
   $env:MYSQL_DATABASE = "smartpark"
   $env:FLASK_SECRET_KEY = "set-a-long-random-secret"
   flask --app app init-db
   python app.py
   ```

3. Open `http://127.0.0.1:5000`.

The schema is in `db/schema.sql`. Running `flask --app app init-db` creates the database and tables, then inserts sample accounts and parking spaces only if the users table is empty. The command is safe to rerun.

## Demo accounts

The initial demo data provides these sign-ins (all use the sample password `SmartPark@123`):

| Role | Username |
|---|---|
| Administrator | `admin` |
| Parking staff | `staff` |
| Customer | `aisha` |

Change or remove these demo passwords before exposing the app beyond a local classroom demonstration. New self-service registrations receive the customer role only.

## Core workflows

1. Sign in as a customer and register a vehicle.
2. Create a booking; the system locks and reserves a compatible available space.
3. Sign in as staff, check in the booking, then check out the active session using Cash, Card, or UPI.
4. Review the calculated charge, payment ledger, occupancy, revenue charts, and audit log.
5. Unused reservations expire after 15 minutes; expired reservations release their spaces when the dashboard or booking list is opened.

## Project layout

- `app.py` — Flask routes, MySQL access, booking logic, authorization, and database initialization
- `db/schema.sql` — MySQL 8 schema
- `templates/` — server-rendered pages
- `static/app.css` — responsive visual design
- `static/app.js` — small browser-side form interactions
- `.env.example` — environment variable reference (copy values into your shell; secrets are not committed)

Charts use Chart.js from jsDelivr and web fonts use Google Fonts, so those two visual enhancements require internet access. The rest of the app runs locally.

Run the unit and route tests with:

```powershell
python -m unittest discover -s tests -v
```

## Notes

The app now uses MySQL; it does not read or update the old `smartpark.db` SQLite file. MySQL connection settings are supplied through environment variables. For deployment, use a production WSGI server, HTTPS, a strong persistent Flask secret, and least-privilege database credentials.
