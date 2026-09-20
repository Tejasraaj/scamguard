from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv
import os
import datetime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class URLAnalysis(Base):
    __tablename__ = "url_analysis"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False)
    risk_score = Column(Integer)
    verdict = Column(String)
    reasons = Column(Text)  # stored as comma-separated text for simplicity
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class MessageAnalysis(Base):
    __tablename__ = "message_analysis"
    id = Column(Integer, primary_key=True, index=True)
    message = Column(Text, nullable=False)
    risk_score = Column(Integer)
    verdict = Column(String)
    reasons = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()