import sqlite3
import os

db_path = os.path.join("instance", "netsecure.db")

connection = sqlite3.connect(db_path)
cursor = connection.cursor()

cursor.execute("PRAGMA table_info(scan)")
columns = [column[1] for column in cursor.fetchall()]

if "start_time" not in columns:
    cursor.execute("ALTER TABLE scan ADD COLUMN start_time DATETIME")
    print("Added start_time column")

if "end_time" not in columns:
    cursor.execute("ALTER TABLE scan ADD COLUMN end_time DATETIME")
    print("Added end_time column")

connection.commit()
connection.close()

print("Database update completed successfully!")