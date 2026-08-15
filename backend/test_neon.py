from sqlalchemy import text

from app.database.postgres import engine


print("Testing Neon connection...")

try:
    with engine.connect() as connection:
        result = connection.execute(text("SELECT version();"))
        print("Connected successfully!")
        print(result.fetchone())

except Exception as e:
    print("Connection failed!")
    print(type(e).__name__)
    print(e)