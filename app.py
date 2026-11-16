import os
import secrets
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

import click
import mysql.connector
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = BASE_DIR / "db" / "schema.sql"
ALLOWED_VEHICLE_TYPES = {"car", "bike", "truck", "ev_car"}
ALLOWED_SLOT_TYPES = {"compact", "large", "bike", "ev", "vip"}
PAYMENT_METHODS = {"Cash", "Card", "UPI"}
SLOT_PREFERENCES = {
    "bike": ("bike", "compact"),
    "car": ("compact", "large", "ev"),
    "truck": ("large",),
    "ev_car": ("ev", "large", "compact"),
}


def mysql_config(include_database=True):
    config = {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "smartpark"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "connection_timeout": 5,
    }
    if include_database:
        config["database"] = os.environ.get("MYSQL_DATABASE", "smartpark")
    return config


def get_db():
    if "db" not in g:
        g.db = mysql.connector.connect(**mysql_config(), autocommit=True)
    return g.db


def query_all(sql, params=()):
    cursor = get_db().cursor(dictionary=True)
    try:
        cursor.execute(sql, params)
        return cursor.fetchall()
    finally:
        cursor.close()


def query_one(sql, params=()):
    cursor = get_db().cursor(dictionary=True)
    try:
        cursor.execute(sql, params)
        return cursor.fetchone()
    finally:
        cursor.close()


def execute(sql, params=()):
    connection = get_db()
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
        connection.commit()
        return cursor.lastrowid or cursor.rowcount
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()


def write_audit(user_id, action, entity_type, entity_id, details):
    execute(
        "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, %s, %s, %s, %s)",
        (user_id, action, entity_type, entity_id, details[:500]),
    )


def parse_positive_int(value, label, maximum=100000):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.") from None
    if parsed <= 0 or parsed > maximum:
        raise ValueError(f"{label} must be between 1 and {maximum}.")
    return parsed


def parse_rate(value):
    try:
        rate = Decimal(value)
    except (InvalidOperation, TypeError):
        raise ValueError("Hourly rate must be a valid amount.") from None
    if not rate.is_finite() or rate <= 0 or rate > Decimal("100000"):
        raise ValueError("Hourly rate must be greater than zero and at most 100,000.")
    return rate.quantize(Decimal("0.01"))


def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def require_roles(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.get("user"):
                return redirect(url_for("login", next=request.path))
            if roles and g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def register_routes(app):
    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        user_id = session.get("user_id")
        if user_id:
            g.user = query_one(
                "SELECT id, username, full_name, role FROM users WHERE id = %s",
                (user_id,),
            )
            if g.user is None:
                session.clear()
        if request.method == "POST":
            submitted = request.form.get("_csrf_token", "")
            expected = session.get("_csrf_token", "")
            if not expected or not secrets.compare_digest(submitted, expected):
                abort(400, description="The form expired or could not be verified. Reload and try again.")

    @app.context_processor
    def inject_template_helpers():
        return {"csrf_token": csrf_token, "current_user": g.get("user"), "now": datetime.now}

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = query_one(
                "SELECT id, username, password_hash, full_name, role FROM users WHERE username = %s",
                (username,),
            )
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["_csrf_token"] = secrets.token_urlsafe(32)
                write_audit(user["id"], "LOGIN", "user", user["id"], "User signed in")
                return redirect(url_for("dashboard"))
            flash("The username or password was not recognized.", "error")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            if not name or len(name) > 120 or len(username) < 3 or len(username) > 80:
                flash("Enter a name and a username with at least 3 characters.", "error")
            elif len(password) < 8:
                flash("Choose a password with at least 8 characters.", "error")
            else:
                try:
                    user_id = execute(
                        "INSERT INTO users (username, password_hash, full_name, role) VALUES (%s, %s, %s, 'customer')",
                        (username, generate_password_hash(password), name),
                    )
                    session["user_id"] = user_id
                    flash("Your customer account is ready.", "success")
                    return redirect(url_for("dashboard"))
                except mysql.connector.IntegrityError:
                    flash("That username is already in use.", "error")
        return render_template("login.html", registration=True)

    @app.route("/logout", methods=["POST"])
    @require_roles()
    def logout():
        write_audit(g.user["id"], "LOGOUT", "user", g.user["id"], "User signed out")
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @require_roles()
    def dashboard():
        expire_reservations()
        stats = query_one(
            """
            SELECT COUNT(*) AS total_slots,
                COALESCE(SUM(status = 'available'), 0) AS available,
                COALESCE(SUM(status = 'occupied'), 0) AS occupied,
                COALESCE(SUM(status = 'reserved'), 0) AS reserved
            FROM parking_slots
            """
        )
        scope, scope_params = customer_scope("b.customer_id")
        customer_bookings = query_one(
            f"SELECT COUNT(*) AS total FROM bookings b WHERE 1=1 {scope}",
            scope_params,
        )["total"]
        session_scope, session_params = customer_session_scope()
        active_sessions = query_one(
            f"SELECT COUNT(*) AS total FROM parking_sessions s JOIN vehicles v ON v.id=s.vehicle_id WHERE s.status = 'active' {session_scope}",
            session_params,
        )["total"]
        revenue_scope = " AND p.status = 'paid'"
        revenue_params = ()
        if g.user["role"] == "customer":
            revenue_scope += " AND v.owner_id = %s"
            revenue_params = (g.user["id"],)
        revenue = query_one(
            f"SELECT COALESCE(SUM(p.amount), 0) AS total FROM payments p JOIN parking_sessions s ON s.id=p.session_id JOIN vehicles v ON v.id=s.vehicle_id WHERE 1=1 {revenue_scope}",
            revenue_params,
        )["total"]
        stats.update(
            booking_count=customer_bookings,
            active_sessions=active_sessions,
            revenue=revenue,
        )
        occupancy = query_all(
            "SELECT slot_type, COUNT(*) AS total, SUM(status = 'available') AS available FROM parking_slots GROUP BY slot_type ORDER BY slot_type"
        )
        revenue_scope = ""
        revenue_params = ()
        if g.user["role"] == "customer":
            revenue_scope = " AND v.owner_id = %s"
            revenue_params = (g.user["id"],)
        revenue_days = query_all(
            f"""
            SELECT DATE(p.paid_at) AS day, SUM(p.amount) AS total
            FROM payments p
            JOIN parking_sessions s ON s.id = p.session_id
            JOIN vehicles v ON v.id = s.vehicle_id
            WHERE p.status = 'paid' AND p.paid_at >= CURRENT_DATE - INTERVAL 6 DAY
            {revenue_scope}
            GROUP BY DATE(p.paid_at)
            ORDER BY day
            """,
            revenue_params,
        )
        occupancy = [
            {**row, "total": int(row["total"] or 0), "available": int(row["available"] or 0)}
            for row in occupancy
        ]
        revenue_days = [
            {"day": row["day"].isoformat(), "total": float(row["total"] or 0)}
            for row in revenue_days
        ]
        recent_sessions = query_all(
            f"""
            SELECT s.id, s.status, s.check_in, s.amount, s.payment_status,
                   v.registration_no, p.slot_no
            FROM parking_sessions s
            JOIN vehicles v ON v.id = s.vehicle_id
            JOIN parking_slots p ON p.id = s.slot_id
            WHERE 1=1 {session_scope}
            ORDER BY s.id DESC LIMIT 6
            """,
            session_params,
        )
        return render_template(
            "dashboard.html",
            stats=stats,
            occupancy=occupancy,
            revenue_days=revenue_days,
            recent_sessions=recent_sessions,
        )

    @app.route("/slots", methods=["GET", "POST"])
    @require_roles("admin", "staff")
    def slots():
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "add":
                    slot_no = request.form.get("slot_no", "").strip().upper()
                    floor_no = parse_positive_int(request.form.get("floor_no"), "Floor", 100)
                    slot_type = request.form.get("slot_type", "")
                    rate = parse_rate(request.form.get("hourly_rate", ""))
                    is_ev = int(request.form.get("is_ev_charger") == "on")
                    if not slot_no or len(slot_no) > 24 or slot_type not in ALLOWED_SLOT_TYPES:
                        raise ValueError("Enter a slot number and choose a valid slot type.")
                    if is_ev and slot_type != "ev":
                        raise ValueError("Only EV slots can have an EV charger.")
                    slot_id = execute(
                        "INSERT INTO parking_slots (slot_no, floor_no, slot_type, hourly_rate, is_ev_charger) VALUES (%s, %s, %s, %s, %s)",
                        (slot_no, floor_no, slot_type, rate, is_ev),
                    )
                    write_audit(g.user["id"], "ADD_SLOT", "parking_slot", slot_id, f"Added slot {slot_no}")
                    flash(f"Parking slot {slot_no} added.", "success")
                elif action == "maintenance":
                    slot_id = parse_positive_int(request.form.get("slot_id"), "Slot ID")
                    result = execute(
                        "UPDATE parking_slots SET status = IF(status = 'maintenance', 'available', 'maintenance') WHERE id = %s AND status IN ('available', 'maintenance')",
                        (slot_id,),
                    )
                    if not result:
                        raise ValueError("Only available or maintenance slots can be changed.")
                    write_audit(g.user["id"], "TOGGLE_MAINTENANCE", "parking_slot", slot_id, "Updated slot maintenance status")
                    flash("Slot status updated.", "success")
                else:
                    raise ValueError("Choose a valid slot action.")
            except (ValueError, mysql.connector.IntegrityError) as error:
                flash(str(error) if isinstance(error, ValueError) else "That slot number already exists.", "error")
            return redirect(url_for("slots"))
        rows = query_all(
            """
            SELECT p.*, (SELECT v.registration_no FROM parking_sessions s JOIN vehicles v ON v.id=s.vehicle_id
                WHERE s.slot_id=p.id AND s.status='active' ORDER BY s.id DESC LIMIT 1) AS registration_no
            FROM parking_slots p ORDER BY p.floor_no, p.slot_no
            """
        )
        return render_template("list.html", page="slots", rows=rows)

    @app.route("/vehicles", methods=["GET", "POST"])
    @require_roles()
    def vehicles():
        if request.method == "POST":
            owner_id = g.user["id"]
            if g.user["role"] in {"admin", "staff"}:
                try:
                    owner_id = parse_positive_int(request.form.get("owner_id"), "Owner ID")
                except ValueError as error:
                    flash(str(error), "error")
                    return redirect(url_for("vehicles"))
            registration = request.form.get("registration_no", "").strip().upper()
            make = request.form.get("make", "").strip()
            model = request.form.get("model", "").strip()
            vehicle_type = request.form.get("vehicle_type", "")
            is_ev = int(vehicle_type == "ev_car")
            if (
                not registration
                or len(registration) > 24
                or not make
                or len(make) > 80
                or not model
                or len(model) > 80
                or vehicle_type not in ALLOWED_VEHICLE_TYPES
            ):
                flash("Complete all vehicle fields and choose a valid type.", "error")
            else:
                try:
                    vehicle_id = execute(
                        "INSERT INTO vehicles (owner_id, registration_no, make, model, vehicle_type, is_ev) VALUES (%s, %s, %s, %s, %s, %s)",
                        (owner_id, registration, make, model, vehicle_type, is_ev),
                    )
                    write_audit(g.user["id"], "REGISTER_VEHICLE", "vehicle", vehicle_id, f"Registered {registration}")
                    flash(f"Vehicle {registration} registered.", "success")
                except mysql.connector.IntegrityError:
                    flash("Registration number is already in use, or the owner account does not exist.", "error")
            return redirect(url_for("vehicles"))
        scope, params = customer_scope("v.owner_id")
        rows = query_all(
            f"""
            SELECT v.id, v.registration_no, v.make, v.model, v.vehicle_type, v.is_ev, v.status,
                   u.full_name AS owner_name
            FROM vehicles v JOIN users u ON u.id=v.owner_id
            WHERE 1=1 {scope} ORDER BY v.id DESC
            """,
            params,
        )
        return render_template("list.html", page="vehicles", rows=rows)

    @app.route("/bookings", methods=["GET", "POST"])
    @require_roles()
    def bookings():
        expire_reservations()
        if request.method == "POST":
            try:
                vehicle_id = parse_positive_int(request.form.get("vehicle_id"), "Vehicle ID")
                duration = parse_positive_int(request.form.get("duration_minutes"), "Duration", 1440)
                if duration < 15:
                    raise ValueError("Booking duration must be at least 15 minutes.")
                booking_id = create_booking(vehicle_id, duration)
                flash(f"Booking confirmed. Reference: {booking_id['booking_code']}", "success")
            except ValueError as error:
                flash(str(error), "error")
            return redirect(url_for("bookings"))
        scope, params = customer_scope("b.customer_id")
        rows = query_all(
            f"""
            SELECT b.id, b.booking_code, b.status, b.slot_type, b.start_time, b.end_time, b.expires_at,
                   b.amount_due, u.full_name AS customer, v.registration_no, p.slot_no,
                   (b.status='active' AND NOT EXISTS(SELECT 1 FROM parking_sessions s WHERE s.booking_id=b.id AND s.status='active')) AS can_check_in
            FROM bookings b
            JOIN users u ON u.id=b.customer_id
            JOIN vehicles v ON v.id=b.vehicle_id
            LEFT JOIN parking_slots p ON p.id=b.slot_id
            WHERE 1=1 {scope} ORDER BY b.id DESC
            """,
            params,
        )
        vehicle_scope, vehicle_params = customer_scope("owner_id")
        vehicles = query_all(
            f"SELECT id, registration_no, make, model, vehicle_type FROM vehicles WHERE status='active' {vehicle_scope} ORDER BY registration_no",
            vehicle_params,
        )
        return render_template("list.html", page="bookings", rows=rows, vehicles=vehicles)

    @app.route("/bookings/<int:booking_id>/check-in", methods=["POST"])
    @require_roles("admin", "staff")
    def check_in(booking_id):
        expire_reservations()
        connection = get_db()
        cursor = connection.cursor(dictionary=True)
        try:
            connection.start_transaction()
            cursor.execute(
                "SELECT * FROM bookings WHERE id=%s AND status='active' FOR UPDATE",
                (booking_id,),
            )
            booking = cursor.fetchone()
            if not booking:
                raise ValueError("This booking is no longer active.")
            cursor.execute(
                "SELECT id, status FROM parking_slots WHERE id=%s FOR UPDATE",
                (booking["slot_id"],),
            )
            slot = cursor.fetchone()
            if not slot or slot["status"] != "reserved":
                raise ValueError("The reserved slot is no longer available.")
            cursor.execute("SELECT id FROM parking_sessions WHERE booking_id=%s AND status='active'", (booking_id,))
            if cursor.fetchone():
                raise ValueError("This booking already has an active parking session.")
            cursor.execute(
                "INSERT INTO parking_sessions (booking_id, vehicle_id, slot_id, check_in, status) VALUES (%s, %s, %s, NOW(), 'active')",
                (booking_id, booking["vehicle_id"], booking["slot_id"]),
            )
            session_id = cursor.lastrowid
            cursor.execute("UPDATE parking_slots SET status='occupied' WHERE id=%s", (booking["slot_id"],))
            cursor.execute(
                "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, 'CHECK_IN', 'parking_session', %s, %s)",
                (g.user["id"], session_id, f"Checked in booking {booking['booking_code']}"),
            )
            connection.commit()
            flash("Vehicle checked in. The parking session is now active.", "success")
        except ValueError as error:
            connection.rollback()
            flash(str(error), "error")
        finally:
            cursor.close()
        return redirect(url_for("sessions"))

    @app.route("/bookings/<int:booking_id>/cancel", methods=["POST"])
    @require_roles()
    def cancel_booking(booking_id):
        connection = get_db()
        cursor = connection.cursor(dictionary=True)
        try:
            connection.start_transaction()
            ownership = "" if g.user["role"] != "customer" else " AND customer_id=%s"
            params = (booking_id,) if not ownership else (booking_id, g.user["id"])
            cursor.execute(
                f"SELECT * FROM bookings WHERE id=%s AND status='active'{ownership} FOR UPDATE",
                params,
            )
            booking = cursor.fetchone()
            if not booking:
                raise ValueError("This booking is no longer active or does not belong to you.")
            cursor.execute("SELECT id FROM parking_sessions WHERE booking_id=%s AND status='active'", (booking_id,))
            if cursor.fetchone():
                raise ValueError("A checked-in booking cannot be cancelled. Check out the vehicle instead.")
            cursor.execute("UPDATE bookings SET status='cancelled' WHERE id=%s", (booking_id,))
            cursor.execute(
                "UPDATE parking_slots SET status='available' WHERE id=%s AND status='reserved'",
                (booking["slot_id"],),
            )
            cursor.execute(
                "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, 'CANCEL_BOOKING', 'booking', %s, %s)",
                (g.user["id"], booking_id, f"Cancelled booking {booking['booking_code']}"),
            )
            connection.commit()
            flash("Booking cancelled and its reserved slot released.", "success")
        except ValueError as error:
            connection.rollback()
            flash(str(error), "error")
        finally:
            cursor.close()
        return redirect(url_for("bookings"))

    @app.route("/sessions", methods=["GET"])
    @require_roles()
    def sessions_page():
        scope, params = customer_session_scope()
        rows = query_all(
            f"""
            SELECT s.id, s.status, s.check_in, s.check_out, s.duration_minutes, s.amount, s.payment_status,
                   v.registration_no, p.slot_no, b.booking_code
            FROM parking_sessions s
            JOIN vehicles v ON v.id=s.vehicle_id
            JOIN parking_slots p ON p.id=s.slot_id
            LEFT JOIN bookings b ON b.id=s.booking_id
            WHERE 1=1 {scope} ORDER BY s.id DESC
            """,
            params,
        )
        return render_template("list.html", page="sessions", rows=rows)

    @app.route("/sessions/<int:session_id>/check-out", methods=["POST"])
    @require_roles("admin", "staff")
    def check_out(session_id):
        method = request.form.get("payment_method", "")
        if method not in PAYMENT_METHODS:
            flash("Choose a valid payment method.", "error")
            return redirect(url_for("sessions_page"))
        connection = get_db()
        cursor = connection.cursor(dictionary=True)
        try:
            connection.start_transaction()
            cursor.execute(
                """
                SELECT s.*, p.hourly_rate, v.registration_no
                FROM parking_sessions s
                JOIN parking_slots p ON p.id=s.slot_id
                JOIN vehicles v ON v.id=s.vehicle_id
                WHERE s.id=%s FOR UPDATE
                """,
                (session_id,),
            )
            active = cursor.fetchone()
            if not active or active["status"] != "active":
                raise ValueError("This parking session is no longer active.")
            cursor.execute("SELECT status FROM parking_slots WHERE id=%s FOR UPDATE", (active["slot_id"],))
            slot = cursor.fetchone()
            if not slot or slot["status"] != "occupied":
                raise ValueError("The session's slot is not marked occupied.")
            cursor.execute("SELECT NOW() AS db_now")
            now = cursor.fetchone()["db_now"]
            minutes = max(1, int((now - active["check_in"]).total_seconds() // 60))
            amount = (Decimal(str(active["hourly_rate"])) * minutes / Decimal(60)).quantize(Decimal("0.01"))
            cursor.execute(
                "UPDATE parking_sessions SET check_out=%s, duration_minutes=%s, amount=%s, status='completed', payment_status='paid' WHERE id=%s",
                (now, minutes, amount, session_id),
            )
            cursor.execute(
                "INSERT INTO payments (session_id, amount, payment_method, status) VALUES (%s, %s, %s, 'paid')",
                (session_id, amount, method),
            )
            cursor.execute("UPDATE parking_slots SET status='available' WHERE id=%s", (active["slot_id"],))
            if active["booking_id"]:
                cursor.execute("UPDATE bookings SET status='completed' WHERE id=%s", (active["booking_id"],))
            cursor.execute(
                "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, 'CHECK_OUT', 'parking_session', %s, %s)",
                (g.user["id"], session_id, f"Checked out {active['registration_no']}; amount {amount}"),
            )
            connection.commit()
            flash(f"Checkout complete — ₹{amount:.2f} collected via {method}.", "success")
        except ValueError as error:
            connection.rollback()
            flash(str(error), "error")
        finally:
            cursor.close()
        return redirect(url_for("sessions_page"))

    @app.route("/payments")
    @require_roles("admin", "staff")
    def payments():
        rows = query_all(
            """
            SELECT p.id, p.amount, p.payment_method, p.status, p.paid_at,
                   v.registration_no, s.id AS session_id, b.booking_code
            FROM payments p
            JOIN parking_sessions s ON s.id=p.session_id
            JOIN vehicles v ON v.id=s.vehicle_id
            LEFT JOIN bookings b ON b.id=s.booking_id
            ORDER BY p.id DESC
            """
        )
        return render_template("list.html", page="payments", rows=rows)

    @app.route("/reports")
    @require_roles("admin", "staff")
    def reports():
        occupancy = query_all(
            "SELECT slot_type, status, COUNT(*) AS total FROM parking_slots GROUP BY slot_type, status ORDER BY slot_type, status"
        )
        revenue = query_all(
            """
            SELECT DATE(paid_at) AS day, payment_method, SUM(amount) AS total
            FROM payments WHERE status='paid'
            GROUP BY DATE(paid_at), payment_method ORDER BY day DESC LIMIT 30
            """
        )
        audit = query_all(
            """
            SELECT a.action, a.entity_type, a.entity_id, a.details, a.created_at, u.full_name
            FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
            ORDER BY a.id DESC LIMIT 20
            """
        )
        return render_template("list.html", page="reports", occupancy=occupancy, revenue= revenue, audit=audit)

    @app.errorhandler(mysql.connector.Error)
    def database_error(error):
        app.logger.exception("MySQL database operation failed", exc_info=error)
        return render_template("error.html", message="The MySQL database could not complete this request. Check the server and connection settings."), 503


def customer_scope(column):
    if g.user["role"] == "customer":
        return f" AND {column} = %s", (g.user["id"],)
    return "", ()


def customer_session_scope():
    if g.user["role"] == "customer":
        return " AND v.owner_id = %s", (g.user["id"],)
    return "", ()


def expire_reservations():
    connection = get_db()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        cursor.execute(
            """
            SELECT b.id, b.slot_id, b.booking_code
            FROM bookings b
            WHERE b.status='active' AND b.expires_at <= NOW()
                AND NOT EXISTS (
                    SELECT 1 FROM parking_sessions s
                    WHERE s.booking_id=b.id AND s.status='active'
                )
            FOR UPDATE
            """
        )
        expired = cursor.fetchall()
        for booking in expired:
            cursor.execute("UPDATE bookings SET status='expired' WHERE id=%s", (booking["id"],))
            cursor.execute(
                """
                UPDATE parking_slots AS p SET status='available'
                WHERE p.id=%s AND p.status='reserved'
                    AND NOT EXISTS (
                        SELECT 1 FROM bookings b
                        WHERE b.slot_id=p.id AND b.status='active'
                    )
                """,
                (booking["slot_id"],),
            )
            cursor.execute(
                "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, 'EXPIRE_BOOKING', 'booking', %s, %s)",
                (g.user["id"] if g.get("user") else None, booking["id"], f"Reservation {booking['booking_code']} expired"),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()


def create_booking(vehicle_id, duration_minutes):
    connection = get_db()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        if g.user["role"] == "customer":
            cursor.execute(
                "SELECT id, owner_id, vehicle_type, is_ev, registration_no FROM vehicles WHERE id=%s AND owner_id=%s AND status='active' FOR UPDATE",
                (vehicle_id, g.user["id"]),
            )
        else:
            cursor.execute(
                "SELECT id, owner_id, vehicle_type, is_ev, registration_no FROM vehicles WHERE id=%s AND status='active' FOR UPDATE",
                (vehicle_id,),
            )
        vehicle = cursor.fetchone()
        if not vehicle:
            raise ValueError("Select an active vehicle that belongs to your account.")
        preferences = SLOT_PREFERENCES.get(vehicle["vehicle_type"], ("compact", "large"))
        slot = None
        for preferred in preferences:
            cursor.execute(
                "SELECT id, slot_type, hourly_rate FROM parking_slots WHERE slot_type=%s AND status='available' ORDER BY floor_no, slot_no LIMIT 1 FOR UPDATE",
                (preferred,),
            )
            slot = cursor.fetchone()
            if slot:
                break
        if not slot:
            raise ValueError("No compatible parking slots are currently available.")
        cursor.execute("SELECT NOW() AS db_now")
        now = cursor.fetchone()["db_now"]
        end_time = now + timedelta(minutes=duration_minutes)
        booking_code = f"SP-{now:%y%m%d%H%M%S}-{secrets.token_hex(2).upper()}"
        amount_due = (Decimal(str(slot["hourly_rate"])) * duration_minutes / Decimal(60)).quantize(Decimal("0.01"))
        cursor.execute(
            """
            INSERT INTO bookings (customer_id, vehicle_id, slot_id, booking_code, slot_type,
                start_time, end_time, status, expires_at, amount_due)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s, %s)
            """,
            (vehicle["owner_id"], vehicle_id, slot["id"], booking_code, slot["slot_type"],
             now, end_time, now + timedelta(minutes=15), amount_due),
        )
        booking_id = cursor.lastrowid
        cursor.execute("UPDATE parking_slots SET status='reserved' WHERE id=%s", (slot["id"],))
        cursor.execute(
            "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, 'CREATE_BOOKING', 'booking', %s, %s)",
            (g.user["id"], booking_id, f"Booked {vehicle['registration_no']} in slot {slot['id']}"),
        )
        connection.commit()
        return {"id": booking_id, "booking_code": booking_code}
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()


def initialize_database():
    settings = mysql_config()
    database = settings["database"]
    if not database.replace("_", "").isalnum():
        raise ValueError("MYSQL_DATABASE may contain only letters, numbers, and underscores.")
    server = mysql.connector.connect(**mysql_config(include_database=False))
    try:
        cursor = server.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci")
        cursor.close()
    finally:
        server.close()
    connection = mysql.connector.connect(**settings)
    try:
        cursor = connection.cursor()
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        for statement in schema.split(";"):
            if statement.strip():
                cursor.execute(statement)
        cursor.execute("SELECT COUNT(*) FROM users")
        has_users = cursor.fetchone()[0] > 0
        if not has_users:
            seed_demo_data(connection)
        connection.commit()
        cursor.close()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def seed_demo_data(connection):
    cursor = connection.cursor()
    demo_accounts = (
        ("admin", "SmartPark@123", "System Administrator", "admin"),
        ("staff", "SmartPark@123", "Parking Staff", "staff"),
        ("aisha", "SmartPark@123", "Aisha Khan", "customer"),
    )
    cursor.executemany(
        "INSERT INTO users (username, password_hash, full_name, role) VALUES (%s, %s, %s, %s)",
        [(name, generate_password_hash(password), full_name, role) for name, password, full_name, role in demo_accounts],
    )
    cursor.execute("SELECT id, username FROM users WHERE username IN ('admin', 'staff', 'aisha')")
    users = {row[1]: row[0] for row in cursor.fetchall()}
    cursor.executemany(
        "INSERT INTO vehicles (owner_id, registration_no, make, model, vehicle_type, is_ev) VALUES (%s, %s, %s, %s, %s, %s)",
        [
            (users["aisha"], "MH12AB1234", "Tesla", "Model 3", "ev_car", True),
            (users["aisha"], "DL08CD5678", "Honda", "City", "car", False),
            (users["admin"], "KA01EF9012", "Royal Enfield", "Classic 350", "bike", False),
        ],
    )
    cursor.executemany(
        "INSERT INTO parking_slots (slot_no, floor_no, slot_type, status, hourly_rate, is_ev_charger) VALUES (%s, %s, %s, %s, %s, %s)",
        [
            ("A-101", 1, "compact", "available", 60, False),
            ("A-102", 1, "compact", "available", 60, False),
            ("A-103", 1, "compact", "available", 60, False),
            ("A-104", 1, "large", "available", 90, False),
            ("A-105", 1, "large", "reserved", 90, False),
            ("B-201", 2, "bike", "available", 40, False),
            ("B-202", 2, "bike", "occupied", 40, False),
            ("C-301", 3, "ev", "available", 120, True),
            ("C-302", 3, "ev", "available", 120, True),
            ("C-303", 3, "ev", "available", 120, True),
            ("VIP-1", 4, "vip", "available", 180, False),
            ("VIP-2", 4, "vip", "maintenance", 180, False),
        ],
    )
    cursor.execute(
        "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (%s, 'INITIALIZED_SYSTEM', 'system', 1, 'SmartPark MySQL database initialized with demo accounts and parking slots')",
        (users["admin"],),
    )
    cursor.execute("SELECT id FROM vehicles WHERE registration_no='MH12AB1234'")
    ev_vehicle_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM vehicles WHERE registration_no='DL08CD5678'")
    car_vehicle_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM vehicles WHERE registration_no='KA01EF9012'")
    bike_vehicle_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM parking_slots WHERE slot_no='C-301'")
    ev_slot_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM parking_slots WHERE slot_no='A-105'")
    reserved_slot_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM parking_slots WHERE slot_no='B-202'")
    occupied_slot_id = cursor.fetchone()[0]
    cursor.execute(
        """
        INSERT INTO bookings (customer_id, vehicle_id, slot_id, booking_code, slot_type,
            start_time, end_time, status, expires_at, amount_due)
        VALUES (%s, %s, %s, 'SP-DEMO-PAID-001', 'ev', NOW() - INTERVAL 1 DAY,
            DATE_ADD(NOW() - INTERVAL 1 DAY, INTERVAL 2 HOUR), 'completed', NOW() - INTERVAL 1 DAY, 240.00)
        """,
        (users["aisha"], ev_vehicle_id, ev_slot_id),
    )
    completed_booking_id = cursor.lastrowid
    cursor.execute(
        """
        INSERT INTO parking_sessions (booking_id, vehicle_id, slot_id, check_in, check_out,
            duration_minutes, status, amount, payment_status)
        VALUES (%s, %s, %s, NOW() - INTERVAL 1 DAY - INTERVAL 2 HOUR,
            NOW() - INTERVAL 1 DAY, 120, 'completed', 240.00, 'paid')
        """,
        (completed_booking_id, ev_vehicle_id, ev_slot_id),
    )
    completed_session_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO payments (session_id, amount, payment_method, status, paid_at) VALUES (%s, 240.00, 'UPI', 'paid', NOW() - INTERVAL 1 DAY)",
        (completed_session_id,),
    )
    cursor.execute(
        """
        INSERT INTO bookings (customer_id, vehicle_id, slot_id, booking_code, slot_type,
            start_time, end_time, status, expires_at, amount_due)
        VALUES (%s, %s, %s, 'SP-DEMO-RES-002', 'large', NOW(),
            NOW() + INTERVAL 2 HOUR, 'active', NOW() + INTERVAL 15 MINUTE, 180.00)
        """,
        (users["aisha"], car_vehicle_id, reserved_slot_id),
    )
    cursor.execute(
        """
        INSERT INTO parking_sessions (vehicle_id, slot_id, check_in, status, amount, payment_status)
        VALUES (%s, %s, NOW() - INTERVAL 35 MINUTE, 'active', 0.00, 'unpaid')
        """,
        (bike_vehicle_id, occupied_slot_id),
    )
    cursor.close()


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_HTTPS_ONLY", "").lower() == "true",
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    register_routes(app)

    @app.cli.command("init-db")
    def init_db_command():
        """Create the MySQL schema and insert demo data when the database is empty."""
        initialize_database()
        click.echo("SmartPark MySQL database initialized.")

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() == "true")
