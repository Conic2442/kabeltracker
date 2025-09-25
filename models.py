from sqlalchemy import Column, Integer, Text
import datetime as dt, json
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

DB_URL = "sqlite:///./kabeltracker.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ...other model definitions...

class Entry(Base):
    __tablename__ = "entries"
    id = Column(Integer, primary_key=True, index=True)
    data = Column(Text, default="{}")            # JSON string with arbitrary CSV columns
    trekt = Column(Boolean, default=False)
    koblet = Column(Boolean, default=False)
    testet = Column(Boolean, default=False)
    comment = Column(Text, default="")
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def data_dict(self):
        try:
            data_str = self.data if isinstance(self.data, str) else "{}"
            return json.loads(data_str)
        except Exception:
            return {}

class User(Base):
    @staticmethod
    def hash_pw(password: str) -> str:
        import hashlib
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_pw(ph: str, password: str) -> bool:
        return ph == User.hash_pw(password)

    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

class EntryLog(Base):
    __tablename__ = "entry_logs"
    id = Column(Integer, primary_key=True)
    entry_id = Column(Integer, ForeignKey("entries.id"))
    timestamp = Column(DateTime, default=dt.datetime.utcnow)
    trekt = Column(Boolean)
    koblet = Column(Boolean)
    testet = Column(Boolean)
    comment = Column(Text)

import datetime as dt, json
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

DB_URL = "sqlite:///./kabeltracker.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Entry(Base):
    __tablename__ = "entries"
    id = Column(Integer, primary_key=True, index=True)
    data = Column(Text, default="{}")            # JSON string with arbitrary CSV columns
    trekt = Column(Boolean, default=False)
    koblet = Column(Boolean, default=False)
    testet = Column(Boolean, default=False)
    comment = Column(Text, default="")  # <-- Add this line
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def data_dict(self):
        try:
            data_str = self.data if isinstance(self.data, str) else "{}"
            return json.loads(data_str)
        except Exception:
            return {}

class User(Base):
    @staticmethod
    def hash_pw(password: str) -> str:
        import hashlib
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_pw(ph: str, password: str) -> bool:
        return ph == User.hash_pw(password)

    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

class EntryLog(Base):
    __tablename__ = "entry_logs"
    id = Column(Integer, primary_key=True)
    entry_id = Column(Integer, ForeignKey("entries.id"))
    timestamp = Column(DateTime, default=dt.datetime.utcnow)
    trekt = Column(Boolean)
    koblet = Column(Boolean)
    testet = Column(Boolean)
    comment = Column(Text)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_counts(sess) -> dict:
    total = sess.query(Entry).count()
    trekt = sess.query(Entry).filter(Entry.trekt == True).count()
    koblet = sess.query(Entry).filter(Entry.koblet == True).count()
    testet = sess.query(Entry).filter(Entry.testet == True).count()
    return {"total": total, "trekt": trekt, "koblet": koblet, "testet": testet}
