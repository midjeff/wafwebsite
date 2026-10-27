"""Persistent, atomic login failure budgets shared by all application processes."""
import hashlib
import math
import secrets
import time

from werkzeug.security import check_password_hash, generate_password_hash

from .db import connect

# A missing account performs the same password hashing work as a known account.
DUMMY_HASH = generate_password_hash(secrets.token_hex(32))


def authenticate(database, username, password, source, *, limit, window, block, now=None):
    """Atomic account lockout with a rolling failure window; source is not trusted identity."""
    db = connect(database)
    try:
        db.execute('BEGIN IMMEDIATE')
        timestamp = time.time() if now is None else now
        account = hashlib.sha256(username.encode('utf-8')).hexdigest()
        state = db.execute("SELECT blocked_until FROM login_attempts WHERE scope='account' AND key=?", (account,)).fetchone()
        if state and state['blocked_until'] > timestamp:
            # Adopt a shorter configured block without extending an existing deadline.
            deadline = min(state['blocked_until'], timestamp + block)
            if deadline != state['blocked_until']:
                db.execute("UPDATE login_attempts SET blocked_until=? WHERE scope='account' AND key=?",
                           (deadline, account))
            db.commit()
            return None, math.ceil(deadline - timestamp)
        if state and state['blocked_until'] > 0:
            db.execute('DELETE FROM login_failure_events WHERE account=?', (account,))
            db.execute("DELETE FROM login_attempts WHERE scope='account' AND key=?", (account,))
        db.execute('DELETE FROM login_failure_events WHERE occurred <= ?', (timestamp - window,))
        user = db.execute('SELECT id, password_hash FROM users WHERE username=?', (username,)).fetchone()
        valid = check_password_hash(user['password_hash'] if user else DUMMY_HASH, password)
        if valid and user is not None:
            db.execute('DELETE FROM login_failure_events WHERE account=?', (account,))
            db.execute("DELETE FROM login_attempts WHERE scope='account' AND key=?", (account,))
            db.commit()
            return user['id'], 0
        db.execute('INSERT INTO login_failure_events(account, occurred) VALUES (?, ?)', (account, timestamp))
        failures = db.execute('SELECT COUNT(*) FROM login_failure_events WHERE account=?', (account,)).fetchone()[0]
        if failures >= limit:
            db.execute("INSERT INTO login_attempts(scope,key,failures,window_start,blocked_until) VALUES ('account',?,?,?,?) ON CONFLICT(scope,key) DO UPDATE SET failures=excluded.failures,window_start=excluded.window_start,blocked_until=excluded.blocked_until", (account, failures, timestamp, timestamp + block))
        db.commit()
        # The third wrong password establishes the lock; later requests receive 429.
        return None, 0
    finally:
        db.close()
