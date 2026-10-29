import sqlite3

def check_db():
    db_path = r"d:\New folder\cyber-risk-platform\crgc.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cur.fetchall()]
    print("Tables in crgc.db:")
    for t in tables:
        cur.execute(f"SELECT count(*) FROM {t};")
        cnt = cur.fetchone()[0]
        print(f"  - {t}: {cnt} rows")

    print("\nTable Schemas:")
    for t in tables:
        print(f"\n--- {t} ---")
        cur.execute(f"PRAGMA table_info({t});")
        cols = cur.fetchall()
        for col in cols:
            # cid, name, type, notnull, dflt_value, pk
            print(f"  {col[1]} ({col[2]}), notnull={col[3]}, pk={col[5]}")
        cur.execute(f"PRAGMA foreign_key_list({t});")
        fks = cur.fetchall()
        for fk in fks:
            # id, seq, table, from, to, on_update, on_delete, match
            print(f"    FK: {fk[3]} -> {fk[2]}.{fk[4]} (on_delete={fk[6]})")

if __name__ == "__main__":
    check_db()
