
import os
import secrets
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify
)

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import razorpay

from database import get_connection, create_tables


# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")

if not secret_key and __name__ == "__main__":
    secret_key = secrets.token_hex(32)
    print("Using a temporary local SECRET_KEY.")

if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable is missing.")

app.config["SECRET_KEY"] = secret_key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

create_tables()

# Razorpay credentials from environment variables
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")


def get_razorpay_client():
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise RuntimeError("Razorpay credentials are not configured.")

    return razorpay.Client(
        auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
    )


# ==========================================
# USER MODEL
# ==========================================

class User(UserMixin):

    def __init__(self, user_data):
        self.id = user_data["id"]
        self.name = user_data["name"]
        self.email = user_data["email"]
        self.role = user_data["role"]


# ==========================================
# LOAD USER
# ==========================================

@login_manager.user_loader
def load_user(user_id):

    conn = get_connection()

    try:
        user_data = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        return User(user_data) if user_data else None

    finally:
        conn.close()


# ==========================================
# ADMIN SECURITY
# ==========================================

def admin_required(function):

    @wraps(function)
    @login_required
    def decorated_function(*args, **kwargs):

        if current_user.role != "admin":
            flash("Access denied. Admin permission required.")
            return redirect(url_for("dashboard"))

        return function(*args, **kwargs)

    return decorated_function


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ==========================================
# USER REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_connection()

        try:
            conn.execute(
                """
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
                """,
                (name, email, hashed_password)
            )

            conn.commit()

            flash("Registration successful! Please login.")
            return redirect(url_for("login"))

        except Exception:
            flash("This email may already be registered.")

        finally:
            conn.close()

    return render_template("register.html")


# ==========================================
# USER LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_connection()

        try:
            user_data = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if user_data and check_password_hash(
                user_data["password"], password
            ):

                conn.execute(
                    """
                    UPDATE users
                    SET last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (user_data["id"],)
                )

                conn.commit()

                user = User(user_data)

            else:
                user = None

        finally:
            conn.close()

        if user:
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


# ==========================================
# USER DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()

    try:
        subscription = conn.execute(
            """
            SELECT
                subscriptions.*,
                plans.name AS plan_name,
                plans.price AS plan_price,
                plans.duration_days
            FROM subscriptions
            LEFT JOIN plans ON subscriptions.plan_id = plans.id
            WHERE subscriptions.user_id = ?
            ORDER BY subscriptions.id DESC
            LIMIT 1
            """,
            (current_user.id,)
        ).fetchone()

        plans = conn.execute(
            "SELECT * FROM plans ORDER BY price ASC"
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        user=current_user,
        subscription=subscription,
        plans=plans,
        razorpay_key_id=RAZORPAY_KEY_ID
    )


# ==========================================
# CREATE RAZORPAY ORDER
# ==========================================

@app.route("/create-order/<int:plan_id>", methods=["POST"])
@login_required
def create_order(plan_id):

    if current_user.role == "admin":
        return jsonify({
            "error": "Admin accounts cannot purchase plans."
        }), 403

    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return jsonify({
            "error": "Payment service is not configured."
        }), 503

    conn = get_connection()

    try:
        plan = conn.execute(
            "SELECT * FROM plans WHERE id = ?",
            (plan_id,)
        ).fetchone()

        if not plan:
            return jsonify({
                "error": "Selected plan was not found."
            }), 404

        amount_paise = int(round(float(plan["price"]) * 100))

        if amount_paise <= 0:
            return jsonify({
                "error": "This plan does not require payment."
            }), 400

        client = get_razorpay_client()

        order = client.order.create(data={
            "amount": amount_paise,
            "currency": "INR",
            "receipt": (
                f"user{current_user.id}plan{plan_id}"
                f"{int(datetime.now().timestamp())}"
            )[:40],
            "notes": {
                "user_id": str(current_user.id),
                "plan_id": str(plan_id)
            }
        })

        conn.execute(
            """
            INSERT INTO payments
                (user_id, amount, status, razorpay_order_id, plan_id)
            VALUES (?, ?, 'pending', ?, ?)
            """,
            (
                current_user.id,
                float(plan["price"]),
                order["id"],
                plan_id
            )
        )

        conn.commit()

        return jsonify({
            "key_id": RAZORPAY_KEY_ID,
            "order_id": order["id"],
            "amount": amount_paise,
            "currency": "INR",
            "plan_name": plan["name"],
            "user_name": current_user.name,
            "user_email": current_user.email
        })

    except Exception:
        conn.rollback()
        app.logger.exception("Could not create Razorpay order")

        return jsonify({
            "error": "Unable to create payment order. Please try again."
        }), 500

    finally:
        conn.close()


# ==========================================
# VERIFY RAZORPAY PAYMENT
# ==========================================

@app.route("/verify-payment", methods=["POST"])
@login_required
def verify_payment():

    if current_user.role == "admin":
        return jsonify({
            "error": "Admin accounts cannot make payments."
        }), 403

    data = request.get_json(silent=True) or {}

    order_id = data.get("razorpay_order_id", "")
    payment_id = data.get("razorpay_payment_id", "")
    signature = data.get("razorpay_signature", "")

    if not order_id or not payment_id or not signature:
        return jsonify({
            "error": "Payment verification details are incomplete."
        }), 400

    conn = get_connection()

    try:
        payment = conn.execute(
            """
            SELECT * FROM payments
            WHERE razorpay_order_id = ? AND user_id = ?
            """,
            (order_id, current_user.id)
        ).fetchone()

        if not payment:
            return jsonify({
                "error": "Payment order was not found."
            }), 404

        if payment["status"] == "success":
            return jsonify({
                "success": True,
                "message": "Payment already verified."
            })

        client = get_razorpay_client()

        client.utility.verify_payment_signature({
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature
        })

        plan = conn.execute(
            "SELECT * FROM plans WHERE id = ?",
            (payment["plan_id"],)
        ).fetchone()

        if not plan:
            return jsonify({
                "error": "The purchased plan no longer exists."
            }), 400

        existing_payment = conn.execute(
            "SELECT id FROM payments WHERE payment_id = ?",
            (payment_id,)
        ).fetchone()

        if existing_payment:
            return jsonify({
                "error": "This payment has already been used."
            }), 409

        now = datetime.now()

        end_date = now + timedelta(
            days=int(plan["duration_days"])
        )

        conn.execute(
            """
            UPDATE payments
            SET payment_id = ?,
                status = 'success',
                razorpay_signature = ?
            WHERE id = ?
            """,
            (
                payment_id,
                signature,
                payment["id"]
            )
        )

        conn.execute(
            """
            INSERT INTO subscriptions
                (user_id, plan_id, status, start_date, end_date)
            VALUES (?, ?, 'active', ?, ?)
            """,
            (
                current_user.id,
                plan["id"],
                now.strftime("%Y-%m-%d %H:%M:%S"),
                end_date.strftime("%Y-%m-%d %H:%M:%S")
            )
        )

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Payment verified and subscription activated."
        })

    except Exception:
        conn.rollback()
        app.logger.exception("Razorpay payment verification failed")

        return jsonify({
            "error": (
                "Payment verification failed. Please contact support "
                "if money was deducted."
            )
        }), 400

    finally:
        conn.close()


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = get_connection()

    try:
        total_users = conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        active_subscriptions = conn.execute(
            """
            SELECT COUNT(*)
            FROM subscriptions
            WHERE status = 'active'
            """
        ).fetchone()[0]

        total_revenue = conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0)
            FROM payments
            WHERE status = 'success'
            """
        ).fetchone()[0]

        monthly_revenue = conn.execute(
            """
            SELECT
                strftime('%Y-%m', created_at) AS month,
                SUM(amount) AS revenue
            FROM payments
            WHERE status = 'success'
            GROUP BY month
            ORDER BY month DESC
            LIMIT 6
            """
        ).fetchall()

        monthly_labels = [
            row["month"]
            for row in reversed(monthly_revenue)
        ]

        monthly_values = [
            row["revenue"]
            for row in reversed(monthly_revenue)
        ]

        recent_users = conn.execute(
            """
            SELECT id, name, email, role, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 5
            """
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        user=current_user,
        total_users=total_users,
        active_subscriptions=active_subscriptions,
        total_revenue=total_revenue,
        recent_users=recent_users,
        monthly_labels=monthly_labels,
        monthly_values=monthly_values
    )


# ==========================================
# ADMIN USER MANAGEMENT
# ==========================================

@app.route("/admin/users")
@admin_required
def admin_users():

    search = request.args.get("search", "").strip()

    conn = get_connection()

    try:
        if search:
            users = conn.execute(
                """
                SELECT id, name, email, role, created_at, last_login
                FROM users
                WHERE name LIKE ? OR email LIKE ?
                ORDER BY id DESC
                """,
                (f"%{search}%", f"%{search}%")
            ).fetchall()

        else:
            users = conn.execute(
                """
                SELECT id, name, email, role, created_at, last_login
                FROM users
                ORDER BY id DESC
                """
            ).fetchall()

    finally:
        conn.close()

    return render_template(
        "users.html",
        user=current_user,
        users=users,
        search=search
    )


# ==========================================
# ADMIN PLAN MANAGEMENT
# ==========================================

@app.route("/admin/plans")
@admin_required
def admin_plans():

    conn = get_connection()

    try:
        plans = conn.execute(
            "SELECT * FROM plans ORDER BY price ASC"
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "plans.html",
        user=current_user,
        plans=plans
    )


# ==========================================
# ADD SUBSCRIPTION PLAN
# ==========================================

@app.route("/admin/plans/add", methods=["POST"])
@admin_required
def add_plan():

    name = request.form.get("name", "").strip()
    price = request.form.get("price", "").strip()
    duration = request.form.get("duration_days", "").strip()
    description = request.form.get("description", "").strip()

    try:
        price = float(price)
        duration = int(duration)

        if not name or price < 0 or duration <= 0:
            return "Please enter valid plan details.", 400

    except ValueError:
        return "Invalid price or duration.", 400

    conn = get_connection()

    try:
        conn.execute(
            """
            INSERT INTO plans
                (name, price, duration_days, description)
            VALUES (?, ?, ?, ?)
            """,
            (name, price, duration, description)
        )

        conn.commit()

    finally:
        conn.close()

    flash("Subscription plan added successfully!")

    return redirect(url_for("admin_plans"))


# ==========================================
# EDIT SUBSCRIPTION PLAN
# ==========================================

@app.route("/admin/plans/edit/<int:plan_id>", methods=["POST"])
@admin_required
def edit_plan(plan_id):

    name = request.form.get("name", "").strip()
    price = request.form.get("price", "").strip()
    duration = request.form.get("duration_days", "").strip()
    description = request.form.get("description", "").strip()

    try:
        price = float(price)
        duration = int(duration)

        if not name or price < 0 or duration <= 0:
            return "Please enter valid plan details.", 400

    except ValueError:
        return "Invalid price or duration.", 400

    conn = get_connection()

    try:
        result = conn.execute(
            """
            UPDATE plans
            SET name = ?,
                price = ?,
                duration_days = ?,
                description = ?
            WHERE id = ?
            """,
            (name, price, duration, description, plan_id)
        )

        conn.commit()

        if result.rowcount == 0:
            flash("Plan not found.")
        else:
            flash("Subscription plan updated successfully!")

    finally:
        conn.close()

    return redirect(url_for("admin_plans"))


# ==========================================
# DELETE SUBSCRIPTION PLAN
# ==========================================

@app.route("/admin/plans/delete/<int:plan_id>", methods=["POST"])
@admin_required
def delete_plan(plan_id):

    conn = get_connection()

    try:
        existing_subscription = conn.execute(
            """
            SELECT id
            FROM subscriptions
            WHERE plan_id = ?
            LIMIT 1
            """,
            (plan_id,)
        ).fetchone()

        if existing_subscription:
            flash(
                "This plan is assigned to a subscription "
                "and cannot be deleted."
            )

        else:
            conn.execute(
                "DELETE FROM plans WHERE id = ?",
                (plan_id,)
            )

            conn.commit()
            flash("Plan deleted successfully.")

    finally:
        conn.close()

    return redirect(url_for("admin_plans"))


# ==========================================
# ADMIN SUBSCRIPTION MANAGEMENT
# ==========================================

@app.route("/admin/subscriptions")
@admin_required
def admin_subscriptions():

    conn = get_connection()

    try:
        subscriptions = conn.execute(
            """
            SELECT
                subscriptions.*,
                users.name AS user_name,
                users.email AS user_email,
                plans.name AS plan_name,
                plans.price AS plan_price
            FROM subscriptions
            LEFT JOIN users
                ON subscriptions.user_id = users.id
            LEFT JOIN plans
                ON subscriptions.plan_id = plans.id
            ORDER BY subscriptions.id DESC
            """
        ).fetchall()

        users = conn.execute(
            """
            SELECT id, name, email
            FROM users
            WHERE role != 'admin'
            ORDER BY name
            """
        ).fetchall()

        plans = conn.execute(
            "SELECT * FROM plans ORDER BY price ASC"
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "subscriptions.html",
        user=current_user,
        subscriptions=subscriptions,
        users=users,
        plans=plans
    )


# ==========================================
# ASSIGN SUBSCRIPTION
# ==========================================

@app.route("/admin/subscriptions/assign", methods=["POST"])
@admin_required
def assign_subscription():

    user_id = request.form.get("user_id", "").strip()
    plan_id = request.form.get("plan_id", "").strip()

    if not user_id or not plan_id:
        flash("Please select a user and a plan.")
        return redirect(url_for("admin_subscriptions"))

    conn = get_connection()

    try:
        user = conn.execute(
            "SELECT id FROM users WHERE id = ? AND role != 'admin'",
            (user_id,)
        ).fetchone()

        plan = conn.execute(
            "SELECT id, duration_days FROM plans WHERE id = ?",
            (plan_id,)
        ).fetchone()

        if not user or not plan:
            flash("Invalid user or plan selection.")
            return redirect(url_for("admin_subscriptions"))

        start_date = datetime.now()

        end_date = start_date + timedelta(
            days=plan["duration_days"]
        )

        conn.execute(
            """
            INSERT INTO subscriptions
                (user_id, plan_id, start_date, end_date, status)
            VALUES (?, ?, ?, ?, 'active')
            """,
            (
                user_id,
                plan_id,
                start_date.strftime("%Y-%m-%d %H:%M:%S"),
                end_date.strftime("%Y-%m-%d %H:%M:%S")
            )
        )

        conn.commit()
        flash("Subscription assigned successfully!")

    finally:
        conn.close()

    return redirect(url_for("admin_subscriptions"))


# ==========================================
# CANCEL SUBSCRIPTION
# ==========================================

@app.route(
    "/admin/subscriptions/cancel/<int:subscription_id>",
    methods=["POST"]
)
@admin_required
def cancel_subscription(subscription_id):

    conn = get_connection()

    try:
        result = conn.execute(
            """
            UPDATE subscriptions
            SET status = 'cancelled'
            WHERE id = ?
            """,
            (subscription_id,)
        )

        conn.commit()

        if result.rowcount == 0:
            flash("Subscription not found.")
        else:
            flash("Subscription cancelled successfully.")

    finally:
        conn.close()

    return redirect(url_for("admin_subscriptions"))


# ==========================================
# RENEW SUBSCRIPTION
# ==========================================

@app.route(
    "/admin/subscriptions/renew/<int:subscription_id>",
    methods=["POST"]
)
@admin_required
def renew_subscription(subscription_id):

    conn = get_connection()

    try:
        subscription = conn.execute(
            """
            SELECT
                subscriptions.*,
                plans.duration_days
            FROM subscriptions
            JOIN plans
                ON subscriptions.plan_id = plans.id
            WHERE subscriptions.id = ?
            """,
            (subscription_id,)
        ).fetchone()

        if not subscription:
            flash("Subscription not found.")
            return redirect(url_for("admin_subscriptions"))

        end_date = subscription["end_date"]

        try:
            renewal_start = datetime.strptime(
                end_date, "%Y-%m-%d %H:%M:%S"
            )

        except (ValueError, TypeError):
            renewal_start = datetime.now()

        if renewal_start < datetime.now():
            renewal_start = datetime.now()

        new_end_date = renewal_start + timedelta(
            days=subscription["duration_days"]
        )

        conn.execute(
            """
            UPDATE subscriptions
            SET start_date = ?,
                end_date = ?,
                status = 'active'
            WHERE id = ?
            """,
            (
                renewal_start.strftime("%Y-%m-%d %H:%M:%S"),
                new_end_date.strftime("%Y-%m-%d %H:%M:%S"),
                subscription_id
            )
        )

        conn.commit()
        flash("Subscription renewed successfully!")

    finally:
        conn.close()

    return redirect(url_for("admin_subscriptions"))


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash("You have been logged out.")

    return redirect(url_for("login"))


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)

