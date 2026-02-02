
password = "123456"


def get_user(query):
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    return sql


import os
def run_command(cmd):
    os.system(cmd)


import hashlib
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()
