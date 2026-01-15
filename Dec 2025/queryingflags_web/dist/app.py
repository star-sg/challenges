import sqlite3
import os
from flask import Flask, request, jsonify, send_from_directory
import flags

DB_NAME = 'data.db'

def init_db():
    if os.path.exists(DB_NAME):
        return

    print(f"Creating database: {DB_NAME}")
    try:
        db = sqlite3.connect(DB_NAME)
        cursor = db.cursor()

        cursor.execute("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT, content TEXT, hidden BOOLEAN)")
        cursor.execute("INSERT INTO posts (id, title, content, hidden) VALUES (?, ?, ?, ?)", (1, 'Hello World!', 'Playing around with SQL', 0))
        cursor.execute("INSERT INTO posts (id, title, content, hidden) VALUES (?, ?, ?, ?)", (2, 'Hint 1', 'You should be able to see your query below!', 0))
        cursor.execute("INSERT INTO posts (id, title, content, hidden) VALUES (?, ?, ?, ?)", (3, 'Hint 2', 'You may want to leak the whole database using <a href="https://portswigger.net/web-security/sql-injection" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:underline">sqli</a>', 0))
        cursor.execute("INSERT INTO posts (id, title, content, hidden) VALUES (?, ?, ?, ?)", (4, 'More resources', 'Try out other portswigger challenges to get better at web!', 0))
        cursor.execute("INSERT INTO posts (id, title, content, hidden) VALUES (?, ?, ?, ?)", (5, 'Docker', 'You should also try to run the dockerfile yourself and play with it', 0))
        cursor.execute("INSERT INTO posts (id, title, content, hidden) VALUES (?, ?, ?, ?)", (1337, 'Flag 1', flags.FLAG_1, 1))

        cursor.execute(f"CREATE TABLE {flags.FLAG_2} (id INTEGER PRIMARY KEY)")
        
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cursor.execute("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", (1, 'admin', flags.FLAG_3))
        cursor.execute("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", (2, 'editor', 'password123'))

        db.commit()
    except sqlite3.Error as e:
        print(f"Database init error: {e}")
    finally:
        if db:
            db.close()

init_db()

app = Flask(__name__, static_url_path='', static_folder='.')

db_uri = f'file:{DB_NAME}?mode=ro'
print(f"Connecting to database: {db_uri}")
db = sqlite3.connect(db_uri, uri=True, check_same_thread=False)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    if not data or 'query' not in data:
        return jsonify({"error": "Invalid request"}), 400

    query_input = data['query']

    try:
        cursor = db.cursor()
        
        sql_query = f"SELECT id, title, content FROM posts WHERE title LIKE '%Hello {query_input}%' AND hidden = 0 LIMIT 3"
        cursor.execute(sql_query)
        
        rows = cursor.fetchall()
        
        columns = [description[0] for description in cursor.description]
        
        return jsonify({
            "columns": columns,
            "rows": rows,
            "executed_query": sql_query
        })

    except sqlite3.Error as e:
        failed_query = 'Query not generated'
        if 'sql_query' in locals():
            failed_query = sql_query

        return jsonify({
            "error": f"ERROR: (sqlite3) {str(e)}",
            "executed_query": failed_query
        }), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
