import sys, os, time, random, pytest
# ensures that UnitTest.py file will run from main folder in the terminal
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'src'))
from src.app.utility.utility import UUID, Utility
os.chdir(os.path.dirname(__file__))


#-----------------------------------------------------UTILITY--FUNCTIONS--------------------------------------------------------#
# test utility functions
class TestUtilityFunctions():

    # test step function for ToSHA256 function
    @pytest.mark.parametrize('message', [('Test message', 'c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b1'), ('Unit test message', 'd7339ac2986b8c29733af74a6ddb9bc7f0b6cebe2c73be4c50c3779b14107bad'), ('Message testing', 'c61a658992579824833b927d78989cfca1a164ea9abed0fc1a8cf493f379352b')])
    def testToSHA256(self, message: str) -> None:
        # get the hashed message with function
        hashedMessage = Utility.ToSHA256(message[0])

        # assert function was successful and returned correct hash
        assert hashedMessage != None, f'SHA256 function returned None for message "{message[0]}".'
        assert hashedMessage == message[1], f'Expected hash was "{message[1]}", got "{hashedMessage}".'


    # test step function for GetUUID function
    @pytest.mark.parametrize('message', ['550e8400-e29b-41d4-a716-446655440000', '12345678-1234-5678-1234-567812345678', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'])
    def testGetUUID(self, message: str) -> None:
        # get the uuid string with function
        uuidStr = Utility.GetUUID(message)

        # assert function was successful and returned correct uuid string
        assert uuidStr != None, f'UUID function returned None for message "{message}".'
        assert isinstance(uuidStr, UUID), f'Expected UUID object for "{message}", got "{uuidStr}".'
        assert str(uuidStr) == message, f'Expected UUID string "{message}", got "{str(uuidStr)}".'


    # test step function for GetPassword function
    @pytest.mark.parametrize('length', [8, 16, 32])
    def testGetPassword(self, length: int) -> None:
        # get the password with function
        password = Utility.GetPassword(length)

        # assert function was successful and returned correct password with expected length, with at least one uppercase and one digit
        assert password != None, 'Password function returned None.'
        assert len(password) == length, f'Password length mismatch: expected {length}, got {len(password)}.'
        assert any(c.isupper() for c in password), f'Password "{password}" must contain at least one uppercase letter.'
        assert any(c.isdigit() for c in password), f'Password "{password}" must contain at least one digit.'


    # test step function for GetResetCode function
    @pytest.mark.parametrize('length', [8, 16, 32])
    def testGetResetCode(self, length: int) -> None:
        # get reset password code with function
        resetCode = Utility.GetResetCode(length)

        # assert function was successful and returned reset code in desired length
        assert resetCode != None, 'Reset code function returned None.'
        assert len(resetCode) == length, f'Reset code length mismatch: expected {length}, got {len(resetCode)}.'

#---------------------------------------------------UTILITY--FUNCTIONS-END------------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#
# main function for running the tests
if __name__ == '__main__':
    pytest.main(['-v', __file__])

#----------------------------------------------------------MAIN-END-------------------------------------------------------------#