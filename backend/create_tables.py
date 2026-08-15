from app.database.postgres import engine
from app.models import Base

print("Creating database tables...")

Base.metadata.create_all(bind=engine)

print("Database tables created successfully.")