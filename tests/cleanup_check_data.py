"""Run inside an app container; delete only unchanged HTTP-test-owned tickets."""
import json
import os
from pathlib import Path
import sqlite3

with sqlite3.connect(Path(os.environ['DATA_DIR']) / 'portal.db', timeout=10) as db:
    ids = [row[0] for row in db.execute("""SELECT id FROM tickets t
        WHERE owner_id = 1 AND title GLOB 'HTTP_NORMAL_*' AND body = ?
        AND NOT EXISTS (SELECT 1 FROM comments c WHERE c.ticket_id = t.id AND c.body NOT LIKE 'Access check %')""",
        ('\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f \u0437\u0430\u044f\u0432\u043a\u0438',))]
    for ticket_id in ids:
        db.execute('DELETE FROM comments WHERE ticket_id = ?', (ticket_id,))
        db.execute('DELETE FROM participants WHERE ticket_id = ?', (ticket_id,))
        db.execute('DELETE FROM tickets WHERE id = ?', (ticket_id,))
print(json.dumps({'removed_test_ticket_ids': ids, 'user_edited_tickets_preserved': True}))
