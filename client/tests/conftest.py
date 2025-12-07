import sys, os, pytest
from PySide6.QtWidgets import QApplication
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src', 'main'))) #ensures that conftest.py file will run from main folder in the terminal
from src.main.NetSpect import NetSpect


# function for main Qt application
@pytest.fixture(scope='session')
def app():
    return QApplication(sys.argv)


# function for creating the NetSpect GUI object for tests
@pytest.fixture(scope='function')
def NetSpectWindow(app, qtbot):
    try:
        # create the NetSpect window for testing GUI with SQL database thread
        netspect = NetSpect()
        qtbot.addWidget(netspect)
        netspect.ToggleMessageBox(True) #disable message box visability
        netspect.show()

        # wait for the SQL database thread to initialize
        qtbot.waitUntil(lambda: hasattr(netspect, 'sqlThread') and netspect.sqlThread.isRunning(), timeout=5000)

        # wait until the test finishes
        yield netspect

    # check if we reached timeout, if so show print error message
    except TimeoutError:
        assert False, 'SQL thread did not start within timeout.'
    # finally we close the application
    finally:
        # close application when test finishes
        netspect.close()