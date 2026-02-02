import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "Command executed"


@app.route("/user")
def get_user():
    username = request.args.get("username")

    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    return str(cursor.fetchall())


if __name__ == "__main__":
    app.run(debug=True)
