
import sqlite3

DB_NAME = "saas_dashboard.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    """)

    # Plans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            duration_days INTEGER NOT NULL,
            description TEXT
        )
    """)

    # Subscriptions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            start_date TEXT,
            end_date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (plan_id) REFERENCES plans(id)
        )
    """)

    # Payments table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payment_id TEXT UNIQUE,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            razorpay_order_id TEXT,
            razorpay_signature TEXT,
            plan_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (plan_id) REFERENCES plans(id)
        )
    """)

    # Backward-compatible migration for existing databases
    cursor.execute("PRAGMA table_info(payments)")
    existing_columns = {
        row["name"] for row in cursor.fetchall()
    }

    migrations = {
        "razorpay_order_id": "ALTER TABLE payments ADD COLUMN razorpay_order_id TEXT",
        "razorpay_signature": "ALTER TABLE payments ADD COLUMN razorpay_signature TEXT",
        "plan_id": "ALTER TABLE payments ADD COLUMN plan_id INTEGER"
    }

    for column, sql in migrations.items():
        if column not in existing_columns:
            cursor.execute(sql)

    # Prevent duplicate Razorpay order IDs
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_payments_razorpay_order_id
        ON payments(razorpay_order_id)
        WHERE razorpay_order_id IS NOT NULL
    """)

    conn.commit()
    conn.close()
