from .config import psql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


PSQL_DB_URL = psql.database_url_psql
engine = create_engine(PSQL_DB_URL.replace("postgres", "postgresql"))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class PostgresDB:
    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
        