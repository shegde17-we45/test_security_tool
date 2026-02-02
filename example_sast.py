import os

def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    os.system(f"echo {query}")
    return query
