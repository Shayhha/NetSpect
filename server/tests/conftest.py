import sys, os, random, pytest
from typing import Generator
from fastapi.testclient import TestClient
# ensures that conftest.py file will run from main folder in the terminal
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'src'))
from src.app.main import app


# function for creating the test client for API tests
@pytest.fixture(scope='session')
def NetSpectClient() -> Generator[TestClient, None]:
    # create the TestClient for testing API endpoints
    with TestClient(app) as netspectClient:

        # wait until the tests finish
        yield netspectClient


# function for creating test user for all tests
@pytest.fixture(scope='session')
def TestUser() -> Generator[dict, None]:
    # create random test user credentials for testing
    testUser = {
        'email': f'testuser.{random.randint(1, 999999)}@netspect.com',
        'username': f'TestUser{random.randint(1, 999999)}',
        'password': f'TestPass{random.randint(1, 999999)}',
        'sessionId': '',
        'authHeader': ''
    }

    # wait until the tests finish
    yield testUser