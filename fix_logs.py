import sqlite3
import json
import ast

def is_valid_json(s):
    try:
        json.loads(s)
        return True
    except:
        return False

def try_fix_entry(scan_data):
    try:
        # First try literal_eval
        result = ast.literal_eval(scan_data)
        json_str = json.dumps(result)
        return json_str
    except Exception as e:
        print(f"❌ Skipping malformed log: {e}")
        return None

def fix_scan_logs_db():
    conn = sqlite3.connect("scan_logs.db")
    cursor = conn.cursor()

    cursor.execute("SELECT rowid, scan_data FROM scans")
    rows = cursor.fetchall()

    for row_id, raw_data in rows:
        raw_data = raw_data.strip()
        # Already valid JSON? Leave it
        if is_valid_json(raw_data):
            continue

        fixed = try_fix_entry(raw_data)
        if fixed:
            cursor.execute("UPDATE scans SET scan_data = ? WHERE rowid = ?", (fixed, row_id))
            print(f"✅ Fixed log at row {row_id}")
        else:
            print(f"⚠️ Deleting unrecoverable row {row_id}")
            cursor.execute("DELETE FROM scans WHERE rowid = ?", (row_id,))

    conn.commit()
    conn.close()
    print("🎉 Done cleaning scan logs.")

if __name__ == "__main__":
    fix_scan_logs_db()
