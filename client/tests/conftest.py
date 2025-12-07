import sys, os, random, pytest
from typing import Generator
from PySide6.QtWidgets import QApplication
# ensures that conftest.py file will run from main folder in the terminal
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'src', 'main'))
from src.main.NetSpect import NetSpect


# function for main Qt application
@pytest.fixture(scope='session')
def app() -> QApplication:
    return QApplication(sys.argv)


# function for creating test user for all tests
@pytest.fixture(scope='session')
def TestUser() -> Generator[dict, None]:
    # create random test user credentials for testing
    testUser = {
        'email': f'testuser.{random.randint(1, 999999)}@netspect.com',
        'username': f'TestUser{random.randint(1, 999999)}',
        'password': f'TestPass{random.randint(1, 999999)}'
    }

    # wait until the tests finish
    yield testUser


# function for creating the NetSpect GUI object for tests
@pytest.fixture(scope='function')
def NetSpectWindow(app: QApplication, qtbot) -> Generator[NetSpect, None]:
    try:
        # create the NetSpect window for testing GUI with SQL database thread
        netspect = NetSpect()
        qtbot.addWidget(netspect)
        netspect.ToggleMessageBox(True) #disable message box visability
        netspect.show()

        # wait for the SQL manager to initialize
        qtbot.waitUntil(lambda: hasattr(netspect, 'sqlManager') and netspect.sqlManager != None, timeout=5000)

        # wait until the test finishes
        yield netspect

    # check if we reached timeout, if so show print error message
    except TimeoutError:
        assert False, 'SQL manager did not start within timeout.'
    # finally we close the application
    finally:
        # close application when test finishes
        netspect.close()