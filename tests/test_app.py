import unittest
from decimal import Decimal
from datetime import date
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import app as smartpark


class SmartParkValidationTests(unittest.TestCase):
    def test_positive_integer_rejects_zero_and_non_integer(self):
        self.assertEqual(smartpark.parse_positive_int("12", "Duration"), 12)
        with self.assertRaisesRegex(ValueError, "whole number"):
            smartpark.parse_positive_int("1.5", "Duration")
        with self.assertRaisesRegex(ValueError, "between"):
            smartpark.parse_positive_int("0", "Duration")

    def test_hourly_rate_is_validated_and_normalized(self):
        self.assertEqual(smartpark.parse_rate("60"), Decimal("60.00"))
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            smartpark.parse_rate("0")

    def test_vehicle_slot_preferences_prioritize_compatible_spaces(self):
        self.assertEqual(smartpark.SLOT_PREFERENCES["ev_car"][0], "ev")
        self.assertEqual(smartpark.SLOT_PREFERENCES["bike"][0], "bike")
        self.assertEqual(smartpark.SLOT_PREFERENCES["truck"], ("large",))


class SmartParkRouteTests(unittest.TestCase):
    def setUp(self):
        self.application = smartpark.create_app()
        self.application.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = self.application.test_client()

    def test_all_templates_compile(self):
        for template in self.application.jinja_env.list_templates():
            with self.subTest(template=template):
                self.application.jinja_env.get_template(template)

    def test_login_rejects_post_without_csrf_token(self):
        response = self.client.post("/login", data={"username": "admin", "password": "nope"})
        self.assertEqual(response.status_code, 400)

    def test_login_authenticates_and_rotates_session(self):
        user = {
            "id": 8,
            "username": "admin",
            "password_hash": generate_password_hash("correct-password"),
            "full_name": "System Administrator",
            "role": "admin",
        }
        with patch.object(smartpark, "query_one", return_value=user), patch.object(smartpark, "write_audit"):
            page = self.client.get("/login")
            token = self._csrf_token(page.get_data(as_text=True))
            response = self.client.post(
                "/login",
                data={"_csrf_token": token, "username": "admin", "password": "correct-password"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")
        with self.client.session_transaction() as browser_session:
            self.assertEqual(browser_session["user_id"], 8)
            self.assertNotEqual(browser_session["_csrf_token"], token)

    def test_customer_is_forbidden_from_staff_slot_management(self):
        customer = {"id": 3, "username": "aisha", "full_name": "Aisha Khan", "role": "customer"}
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = 3
            browser_session["_csrf_token"] = "test-token"
        with patch.object(smartpark, "query_one", return_value=customer):
            response = self.client.get("/slots")
        self.assertEqual(response.status_code, 403)

    def test_dashboard_renders_chart_data_and_activity(self):
        admin = {"id": 1, "username": "admin", "full_name": "System Administrator", "role": "admin"}
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = 1
            browser_session["_csrf_token"] = "test-token"

        def find_one(sql, params=()):
            if "FROM users WHERE id" in sql:
                return admin
            if "AS total_slots" in sql:
                return {"total_slots": 12, "available": 8, "occupied": 2, "reserved": 1}
            if "FROM bookings b" in sql:
                return {"total": 3}
            if "FROM parking_sessions s JOIN vehicles v" in sql:
                return {"total": 1}
            return {"total": Decimal("240.00")}

        def find_all(sql, params=()):
            if "GROUP BY slot_type" in sql:
                return [{"slot_type": "compact", "total": 3, "available": 2}]
            if "DATE(p.paid_at)" in sql:
                return [{"day": date(2026, 11, 16), "total": Decimal("240.00")}]
            return []

        with (
            patch.object(smartpark, "query_one", side_effect=find_one),
            patch.object(smartpark, "query_all", side_effect=find_all),
            patch.object(smartpark, "expire_reservations"),
        ):
            response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Occupancy at a glance", page)
        self.assertIn("revenueChart", page)
        self.assertIn("2026-11-16", page)

    def test_customer_dashboard_filters_active_sessions_by_vehicle_owner(self):
        customer = {"id": 3, "username": "aisha", "full_name": "Aisha Khan", "role": "customer"}
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = 3
            browser_session["_csrf_token"] = "test-token"

        seen_active_session_query = []

        def find_one(sql, params=()):
            if "FROM users WHERE id" in sql:
                return customer
            if "AS total_slots" in sql:
                return {"total_slots": 12, "available": 8, "occupied": 2, "reserved": 1}
            if "FROM bookings b" in sql:
                return {"total": 2}
            if "FROM parking_sessions s JOIN vehicles v" in sql:
                seen_active_session_query.append(sql)
                return {"total": 1}
            return {"total": Decimal("240.00")}

        def find_all(sql, params=()):
            if "GROUP BY slot_type" in sql:
                return [{"slot_type": "ev", "total": 3, "available": 2}]
            if "DATE(p.paid_at)" in sql:
                return [{"day": date(2026, 11, 16), "total": Decimal("240.00")}]
            return []

        with (
            patch.object(smartpark, "query_one", side_effect=find_one),
            patch.object(smartpark, "query_all", side_effect=find_all),
            patch.object(smartpark, "expire_reservations"),
        ):
            response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(seen_active_session_query)
        self.assertIn("v.owner_id = %s", seen_active_session_query[0])

    @staticmethod
    def _csrf_token(page):
        marker = 'name="_csrf_token" value="'
        return page.split(marker, 1)[1].split('"', 1)[0]


if __name__ == "__main__":
    unittest.main()
