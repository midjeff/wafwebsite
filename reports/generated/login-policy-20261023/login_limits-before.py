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
    """Return (user_id, retry_after). Both independent budgets must allow login.

    BEGIN IMMEDIATE serializes check -> password verification -> increment across
    threads AND processes. Keeping verification inside the transaction is deliberate:
    concurrent requests cannot all pass a stale pre-check. This small portal trades
    login throughput for a strict bound; unrelated readers continue under WAL.
    """
    db = connect(database)
    try:
        db.execute('BEGIN IMMEDIATE')
        timestamp = time.time() if now is None else now
        keys = [('account', hashlib.sha256(username.encode('utf-8')).hexdigest()),
                ('source', source)]
        db.execute('DELETE FROM login_attempts WHERE blocked_until <= ? AND window_start <= ?',
                   (timestamp, timestamp - window))
        states = []
        for scope, key in keys:
            row = db.execute('SELECT failures, window_start, blocked_until FROM login_attempts '
                             'WHERE scope = ? AND key = ?', (scope, key)).fetchone()
            if row is None or (0 < row['blocked_until'] <= timestamp):
                states.append((scope, key, 0, timestamp, 0))
            else:
                states.append((scope, key, row['failures'], row['window_start'], row['blocked_until']))
        retry = max(math.ceil(state[4] - timestamp) for state in states)
        if retry > 0:
            db.commit()
            return None, retry

        user = db.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        valid = check_password_hash(user['password_hash'] if user else DUMMY_HASH, password)
        if valid and user is not None:
            db.execute("DELETE FROM login_attempts WHERE scope = 'account' AND key = ?", (keys[0][1],))
            # Success must not clear the source budget: an attacker with their own
            # credentials could otherwise reset password-spraying protection.
            db.commit()
            return user['id'], 0

        for scope, key, failures, started, _ in states:
            failures += 1
            until = timestamp + block if failures >= limit else 0
            db.execute('INSERT INTO login_attempts(scope, key, failures, window_start, blocked_until) '
                       'VALUES (?, ?, ?, ?, ?) ON CONFLICT(scope, key) DO UPDATE SET '
                       'failures=excluded.failures, window_start=excluded.window_start, '
                       'blocked_until=excluded.blocked_until', (scope, key, failures, started, until))
        db.commit()
        return None, block if any(state[2] + 1 >= limit for state in states) else 0
    finally:
        db.close()  # rolls back an unfinished transaction, including on exceptions
