"""Seed a small, realistic database used by the demo, the tests, and the benchmark."""

from __future__ import annotations

import random
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL
);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def create_demo_db(path: Path | str, customers: int = 200, orders: int = 1000, products: int = 50, seed: int = 7) -> Path:
    """Create (or overwrite) a deterministic demo database. Same seed -> identical content."""
    path = Path(path)
    path.unlink(missing_ok=True)
    rng = random.Random(seed)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO customers (id, name, email, status, created_at) VALUES (?,?,?,?,?)",
        [(i, f"Customer {i}", f"user{i}@example.com", rng.choice(["active", "active", "active", "inactive"]),
          f"2025-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}") for i in range(1, customers + 1)],
    )
    conn.executemany(
        "INSERT INTO orders (id, customer_id, amount, status) VALUES (?,?,?,?)",
        [(i, rng.randint(1, customers), round(rng.uniform(5, 500), 2),
          rng.choice(["pending", "shipped", "delivered", "cancelled"])) for i in range(1, orders + 1)],
    )
    conn.executemany(
        "INSERT INTO products (id, name, price, stock) VALUES (?,?,?,?)",
        [(i, f"Product {i}", round(rng.uniform(1, 200), 2), rng.randint(0, 500)) for i in range(1, products + 1)],
    )
    conn.executemany(
        "INSERT INTO settings (key, value) VALUES (?,?)",
        [("currency", "USD"), ("tax_rate", "0.18"), ("maintenance_mode", "off"), ("api_version", "v3")],
    )
    conn.commit()
    conn.close()
    return path
