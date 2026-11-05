

from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash
)

from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from database import get_connection, create_tables


# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = "change-this-secret-key"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


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

            conn.rollback()

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

                login_user(User(user_data))

                return redirect(url_for("dashboard"))

            flash("Invalid email or password.")

        finally:

            conn.close()

    return render_template("login.html")


# ==========================================
# USER DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "admin":

        return redirect(url_for("admin_dashboard"))

    return render_template(
        "dashboard.html",
        user=current_user
    )


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

        # Update expired subscriptions before counting active ones
        conn.execute("""
            UPDATE subscriptions
            SET status = 'expired'
            WHERE status = 'active'
            AND end_date IS NOT NULL
            AND datetime(end_date) <= datetime('now')
        """)

        conn.commit()

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

    finally:

        conn.close()


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

        return render_template(
            "users.html",
            user=current_user,
            users=users,
            search=search
        )

    finally:

        conn.close()


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

        return render_template(
            "plans.html",
            user=current_user,
            plans=plans
        )

    finally:

        conn.close()


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
            INSERT INTO plans (name, price, duration_days, description)
            VALUES (?, ?, ?, ?)
            """,
            (name, price, duration, description)
        )

        conn.commit()

        flash("Subscription plan added successfully!")

    except Exception:

        conn.rollback()

        flash("Unable to add subscription plan.")

    finally:

        conn.close()

    return redirect(url_for("admin_plans"))


# ==========================================
# EDIT SUBSCRIPTION PLAN
# ==========================================

@app.route(
    "/admin/plans/edit/<int:plan_id>",
    methods=["POST"]
)
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

    except Exception:

        conn.rollback()

        flash("Unable to update subscription plan.")

    finally:

        conn.close()

    return redirect(url_for("admin_plans"))


# ==========================================
# DELETE SUBSCRIPTION PLAN
# ==========================================

@app.route(
    "/admin/plans/delete/<int:plan_id>",
    methods=["POST"]
)
@admin_required
def delete_plan(plan_id):

    conn = get_connection()

    try:

        plan = conn.execute(
            "SELECT id FROM plans WHERE id = ?",
            (plan_id,)
        ).fetchone()

        if not plan:

            flash("Plan not found.")

            return redirect(url_for("admin_plans"))

        subscription_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM subscriptions
            WHERE plan_id = ?
            """,
            (plan_id,)
        ).fetchone()[0]

        if subscription_count > 0:

            flash(
                "Cannot delete this plan because subscriptions exist."
            )

            return redirect(url_for("admin_plans"))

        conn.execute(
            "DELETE FROM plans WHERE id = ?",
            (plan_id,)
        )

        conn.commit()

        flash("Subscription plan deleted successfully!")

    except Exception:

        conn.rollback()

        flash("Unable to delete this plan.")

    finally:

        conn.close()

    return redirect(url_for("admin_plans"))


# ==========================================
# SUBSCRIPTION MANAGEMENT
# ==========================================

# VIEW ALL SUBSCRIPTIONS
@app.route("/admin/subscriptions")
@admin_required
def admin_subscriptions():

    conn = get_connection()

    try:

        # Automatically expire subscriptions whose end date has passed
        conn.execute("""
            UPDATE subscriptions
            SET status = 'expired'
            WHERE status = 'active'
            AND end_date IS NOT NULL
            AND datetime(end_date) <= datetime('now')
        """)

        conn.commit()

        subscriptions = conn.execute("""
            SELECT
                s.id,
                s.user_id,
                s.plan_id,
                s.status,
                s.start_date,
                s.end_date,
                u.name AS user_name,
                u.email AS user_email,
                p.name AS plan_name,
                p.price AS plan_price,
                p.duration_days
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            JOIN plans p ON s.plan_id = p.id
            ORDER BY s.id DESC
        """).fetchall()

        users = conn.execute("""
            SELECT id, name, email
            FROM users
            WHERE role != 'admin'
            ORDER BY name
        """).fetchall()

        plans = conn.execute("""
            SELECT id, name, price, duration_days
            FROM plans
            ORDER BY price ASC
        """).fetchall()

        return render_template(
            "subscriptions.html",
            user=current_user,
            subscriptions=subscriptions,
            users=users,
            plans=plans
        )

    finally:

        conn.close()


# ASSIGN SUBSCRIPTION
@app.route(
    "/admin/subscriptions/assign",
    methods=["POST"]
)
@admin_required
def assign_subscription():

    user_id = request.form.get("user_id", type=int)
    plan_id = request.form.get("plan_id", type=int)

    if not user_id or not plan_id:

        flash("Please select a user and a plan.")

        return redirect(url_for("admin_subscriptions"))

    conn = get_connection()

    try:

        selected_user = conn.execute("""
            SELECT id
            FROM users
            WHERE id = ? AND role != 'admin'
        """, (user_id,)).fetchone()

        selected_plan = conn.execute("""
            SELECT id, duration_days
            FROM plans
            WHERE id = ?
        """, (plan_id,)).fetchone()

        if not selected_user or not selected_plan:

            flash("Invalid user or subscription plan.")

            return redirect(url_for("admin_subscriptions"))

        active_subscription = conn.execute("""
            SELECT id
            FROM subscriptions
            WHERE user_id = ?
            AND status = 'active'
            AND (
                end_date IS NULL
                OR datetime(end_date) > datetime('now')
            )
            LIMIT 1
        """, (user_id,)).fetchone()

        if active_subscription:

            flash("This user already has an active subscription.")

            return redirect(url_for("admin_subscriptions"))

        start_date = datetime.now()

        end_date = start_date + timedelta(
            days=selected_plan["duration_days"]
        )

        conn.execute("""
            INSERT INTO subscriptions (
                user_id,
                plan_id,
                status,
                start_date,
                end_date
            )
            VALUES (?, ?, 'active', ?, ?)
        """, (
            user_id,
            plan_id,
            start_date.strftime("%Y-%m-%d %H:%M:%S"),
            end_date.strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()

        flash("Subscription assigned successfully!")

    except Exception:

        conn.rollback()

        flash("Unable to assign subscription.")

    finally:

        conn.close()

    return redirect(url_for("admin_subscriptions"))


# CANCEL SUBSCRIPTION
@app.route(
    "/admin/subscriptions/cancel/<int:subscription_id>",
    methods=["POST"]
)
@admin_required
def cancel_subscription(subscription_id):

    conn = get_connection()

    try:

        subscription = conn.execute("""
            SELECT id, status
            FROM subscriptions
            WHERE id = ?
        """, (subscription_id,)).fetchone()

        if not subscription:

            flash("Subscription not found.")

        elif subscription["status"] != "active":

            flash("Only active subscriptions can be cancelled.")

        else:

            conn.execute("""
                UPDATE subscriptions
                SET status = 'cancelled'
                WHERE id = ?
            """, (subscription_id,))

            conn.commit()

            flash("Subscription cancelled successfully!")

    except Exception:

        conn.rollback()

        flash("Unable to cancel subscription.")

    finally:

        conn.close()

    return redirect(url_for("admin_subscriptions"))


# RENEW SUBSCRIPTION
@app.route(
    "/admin/subscriptions/renew/<int:subscription_id>",
    methods=["POST"]
)
@admin_required
def renew_subscription(subscription_id):

    conn = get_connection()

    try:

        subscription = conn.execute("""
            SELECT
                s.id,
                s.user_id,
                s.status,
                s.end_date,
                p.duration_days
            FROM subscriptions s
            JOIN plans p ON s.plan_id = p.id
            WHERE s.id = ?
        """, (subscription_id,)).fetchone()

        if not subscription:

            flash("Subscription not found.")

            return redirect(url_for("admin_subscriptions"))

        if subscription["status"] not in ("expired", "cancelled"):

            flash(
                "Only expired or cancelled subscriptions can be renewed."
            )

            return redirect(url_for("admin_subscriptions"))

        another_active = conn.execute("""
            SELECT id
            FROM subscriptions
            WHERE user_id = ?
            AND id != ?
            AND status = 'active'
            AND (
                end_date IS NULL
                OR datetime(end_date) > datetime('now')
            )
            LIMIT 1
        """, (
            subscription["user_id"],
            subscription_id
        )).fetchone()

        if another_active:

            flash(
                "This user already has another active subscription."
            )

            return redirect(url_for("admin_subscriptions"))

        now = datetime.now()

        previous_end = None

        if subscription["end_date"]:

            previous_end = datetime.fromisoformat(
                subscription["end_date"]
            )

        if previous_end and previous_end > now:

            new_start = previous_end

        else:

            new_start = now

        new_end = new_start + timedelta(
            days=subscription["duration_days"]
        )

        conn.execute("""
            UPDATE subscriptions
            SET status = 'active',
                start_date = ?,
                end_date = ?
            WHERE id = ?
        """, (
            new_start.strftime("%Y-%m-%d %H:%M:%S"),
            new_end.strftime("%Y-%m-%d %H:%M:%S"),
            subscription_id
        ))

        conn.commit()

        flash("Subscription renewed successfully!")

    except Exception:

        conn.rollback()

        flash("Unable to renew subscription.")

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

    create_tables()

    app.run(debug=True)
