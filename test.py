from arango import ArangoClient
from cloud_agent_sdk import skill  # hypothetical import

# Define the skill for the agent
@skill(name="arango-fetch-courses")
def fetch_courses():
    # Connect to ArangoDB (read-only)
    client = ArangoClient(hosts="http://localhost:8529")
    db = client.db("aronago_db", username="root", password="password")  # skill has credentials

    # Fetch all courses
    cursor = db.aql.execute("FOR c IN courses RETURN {name: c.name, description: c.description}")
    courses = list(cursor)
    return courses
