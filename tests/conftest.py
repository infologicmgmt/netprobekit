"""
Filename: tests/conftest.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: Common fixtures for pytest
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from netprobe.server import app
from netprobe.database import Base, get_db
from netprobe.db_models import ApiKey, Organization
import hashlib

@pytest.fixture(scope="session")
def engine():
    return create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

@pytest.fixture(scope="function")
def tables(engine):
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False)

@pytest.fixture(scope="function")
def db_session(engine, tables):
    """
    Returns an sqlalchemy session, and after the test tears down everything properly.
    """
    connection = engine.connect()
    TestingSessionLocal.configure(bind=connection)
    # begin the nested transaction
    transaction = connection.begin()
    # use the connection with the already started transaction
    session = TestingSessionLocal()

    yield session

    session.close()
    # roll back the broader transaction
    transaction.rollback()
    # put back the connection to the connection pool
    connection.close()


@pytest.fixture
def client(db_session, monkeypatch, tables):
    """
    Pytest fixture to provide a TestClient with a valid API key.
    """
    def override_get_db():
        yield db_session

    monkeypatch.setattr(app, "dependency_overrides", {get_db: override_get_db})

    org = Organization(name="Test Org")
    db_session.add(org)
    db_session.commit()

    api_key = "test-key"
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    api_key_obj = ApiKey(api_key_hash=api_key_hash, org_id=org.id)
    db_session.add(api_key_obj)
    db_session.commit()

    client = TestClient(app)
    client.headers["X-API-Key"] = api_key
    yield client

    app.dependency_overrides.clear()
