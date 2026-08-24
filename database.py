import os
from sqlalchemy import create_engine, MetaData
from dotenv import load_dotenv

load_dotenv(override=True)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_monitor.db")
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)
metadata = MetaData()

def get_db():
    with engine.connect() as connection:
        yield connection
