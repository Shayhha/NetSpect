import sys, os, time, random, pytest
# ensures that ServerTest.py file will run from main folder in the terminal
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'src'))
from src.app.utility.serverEnums import Endpoints
os.chdir(os.path.dirname(__file__))


#--------------------------------------------------------AUTH-ENDPOINTS---------------------------------------------------------#
# test auth endpoints
class TestAuthEndpoints():

    # test step function for positive register attempt
    def testRegisterPositive(self, NetSpectClient, TestUser: dict) -> None:
        request = {'email': TestUser['email'], 'username': TestUser.get('username'), 'password': TestUser.get('password')}
        result = NetSpectClient.post(Endpoints.API.Auth.Register, json=request)
        # assert successful registration with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'User registration failed.'


    # test step function for negative register attempts
    @pytest.mark.parametrize('credentials', [('TestEmail', 'TestUser[]', ''), ('', 'TestUser//', 'TestPass'), ('testuser.1@netspect.com', '', 'TestPass123')])
    def testRegisterNegative(self, NetSpectClient, TestUser: dict, credentials) -> None:
        request = {'email': credentials[0], 'username': credentials[1], 'password': credentials[2]}
        result = NetSpectClient.post(Endpoints.API.Auth.Register, json=request)
        # assert failed registration with status code 422 and state false
        assert result.status_code == 422 and result.json().get('state') == False, 'Was able to register an invalid account.'


    # test step function for positive login attempt
    def testLoginPositive(self, NetSpectClient, TestUser: dict) -> None:
        request = {'username': TestUser.get('username'), 'password': TestUser.get('password')}
        result = NetSpectClient.post(Endpoints.API.Auth.Login, json=request)
        # assert successful login with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed logging into user\'s account.'

        # set session id in test user for later tests
        sessionId = result.json().get('result', {}).get('sessionId')
        # check if we received session id and set it in TestUser dict
        if sessionId:
            TestUser['sessionId'] = sessionId
            TestUser['authHeader'] = {'Authorization': f'Session {sessionId}'}
        # assert sessionId is initialized
        assert TestUser.get('sessionId'), 'Failed to retrieve sessionId after login.'


    # test step function for negative login attempt
    def testLoginNegative(self, NetSpectClient, TestUser: dict) -> None:
        request = {'username': TestUser.get('username'), 'password': f'{TestUser.get('password')}Test'}
        result = NetSpectClient.post(Endpoints.API.Auth.Login, json=request)
        # assert failed login with status code 200 and state false
        assert result.status_code == 200 and result.json().get('state') == False, 'Was able to log into account with invalid credentials.'

#------------------------------------------------------AUTH-ENDPOINTS-END-------------------------------------------------------#

#-------------------------------------------------------USERS-ENDPOINTS---------------------------------------------------------#
# test users endpoints
class TestUsersEndpoints():

    # test step function for testing change email positive scenarios
    @pytest.mark.parametrize('newEmail', [f'newemail{random.randint(1, 10)}@netspect.com', f'username{random.randint(1, 10)}@something.com', f'email{random.randint(1, 10)}@test.co.il'])
    def testChangeEmailPositive(self, NetSpectClient, TestUser: dict, newEmail) -> None:
        request = {'newEmail': newEmail}
        result = NetSpectClient.put(Endpoints.API.Users.ChangeEmail, headers=TestUser.get('authHeader'), json=request)
        # assert email changed successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed changing user\'s email.'


    # test step function for testing change email negative scenarios
    @pytest.mark.parametrize('newEmail', [f'new.user{random.randint(1, 10)}@', f'username{random.randint(1, 10)}@something', f'email{random.randint(1, 10)}test.co.il'])
    def testChangeEmailNegative(self, NetSpectClient, TestUser: dict, newEmail) -> None:
        request = {'newEmail': newEmail}
        result = NetSpectClient.put(Endpoints.API.Users.ChangeEmail, headers=TestUser.get('authHeader'), json=request)
        # assert email change failed with status code 422 and state false
        assert result.status_code == 422 and result.json().get('state') == False, 'Was able to change email to an invalid email.'


    # test step function for testing change username positive scenarios
    @pytest.mark.parametrize('newUsername', [f'TestName{random.randint(1, 10)}', f'testName{random.randint(1, 10)}', f'Testname123{random.randint(1, 10)}'])
    def testChangeUsernamePositive(self, NetSpectClient, TestUser: dict, newUsername) -> None:
        request = {'newUsername': newUsername}
        result = NetSpectClient.put(Endpoints.API.Users.ChangeUsername, headers=TestUser.get('authHeader'), json=request)
        # assert username changed successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed changing user\'s username.'


    # test step function for testing change username negative scenarios
    @pytest.mark.parametrize('newUsername', [f'A{random.randint(1, 5)}', f'{random.randint(1, 5)}Me', f'{random.randint(1, 100)}'])
    def testChangeUsernameNegative(self, NetSpectClient, TestUser: dict, newUsername) -> None:
        request = {'newUsername': newUsername}
        result = NetSpectClient.put(Endpoints.API.Users.ChangeUsername, headers=TestUser.get('authHeader'), json=request)
        # assert username change failed with status code 422 and state false
        assert result.status_code == 422 and result.json().get('state') == False, 'Was able to change username to an invalid username.'


    # test step function for testing change password positive scenarios
    @pytest.mark.parametrize('newPassword', ['User1234', '1234Abcd', '12!@#aB'])
    def testChangePasswordPositive(self, NetSpectClient, TestUser: dict, newPassword) -> None:
        request = {'oldPassword': TestUser.get('password'), 'newPassword': newPassword}
        result = NetSpectClient.put(Endpoints.API.Users.ChangePassword, headers=TestUser.get('authHeader'), json=request)
        # assert password changed successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed changing user\'s password.'

        # change password back to default password
        request.update({'oldPassword': newPassword, 'newPassword': TestUser.get('password')})
        result = NetSpectClient.put(Endpoints.API.Users.ChangePassword, headers=TestUser.get('authHeader'), json=request)
        # assert password changed successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed changing user\'s password back to default password.'


    # test step function for testing change password negative scenarios
    @pytest.mark.parametrize('newPassword', ['User1', '', 'U2'])
    def testChangePasswordNegative(self, NetSpectClient, TestUser: dict, newPassword) -> None:
        request = {'oldPassword': TestUser.get('password'), 'newPassword': newPassword}
        result = NetSpectClient.put(Endpoints.API.Users.ChangePassword, headers=TestUser.get('authHeader'), json=request)
        # assert password change failed with status code 422 and state false
        assert result.status_code == 422 and result.json().get('state') == False, 'Was able to change password to an invalid password.'

#-----------------------------------------------------USERS-ENDPOINTS-END-------------------------------------------------------#

#-----------------------------------------------------BLACKLIST-ENDPOINTS-------------------------------------------------------#
# test blacklist endpoints
class TestBlacklistEndpoints():

    # test step function for testing add blacklist MAC positive scenarios
    @pytest.mark.parametrize('macAddress', ['3a:5f:8c:2b:1e:d4', '9b:0d:7f:ae:c3:11', 'f2:4e:6a:b9:0c:88'])
    def testAddBlacklistMACPositive(self, NetSpectClient, TestUser: dict, macAddress) -> None:
        request = {'macAddress': macAddress}
        result = NetSpectClient.post(Endpoints.API.Blacklist.AddBlacklistMac, headers=TestUser.get('authHeader'), json=request)
        # assert added blacklist MAC address successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed adding MAC address to blacklist.'


    # test step function for testing add blacklist MAC negative scenarios
    @pytest.mark.parametrize('macAddress', ['3a:5f:8c:2b:1e:', '9b:0d:7f', 'f2:4e:6a:b9:0c:000'])
    def testAddBlacklistMACNegative(self, NetSpectClient, TestUser: dict, macAddress) -> None:
        request = {'macAddress': macAddress}
        result = NetSpectClient.post(Endpoints.API.Blacklist.AddBlacklistMac, headers=TestUser.get('authHeader'), json=request)
        # assert add blacklist MAC failed with status code 422 and state false
        assert result.status_code == 422 and result.json().get('state') == False, 'Was able to add invalid MAC address to blacklist.'


    # test step function for testing delete blacklist MAC positive scenarios
    @pytest.mark.parametrize('macAddress', ['3a:5f:8c:2b:1e:d4', '9b:0d:7f:ae:c3:11', 'f2:4e:6a:b9:0c:88'])
    def testDeleteBlacklistMACPositive(self, NetSpectClient, TestUser: dict, macAddress) -> None:
        request = {'macAddress': macAddress}
        result = NetSpectClient.post(Endpoints.API.Blacklist.DeleteBlacklistMac, headers=TestUser.get('authHeader'), json=request)
        # assert deleted blacklist MAC address successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed deleting MAC address from blacklist.'


    # test step function for testing delete blacklist MAC negative scenarios
    @pytest.mark.parametrize('macAddress', ['3a:5f:8c:2b:1e:', '9b:0d:7f', 'f2:4e:6a:b9:0c:000'])
    def testDeleteBlacklistMACNegative(self, NetSpectClient, TestUser: dict, macAddress) -> None:
        request = {'macAddress': macAddress}
        result = NetSpectClient.post(Endpoints.API.Blacklist.DeleteBlacklistMac, headers=TestUser.get('authHeader'), json=request)
        # assert delete blacklist MAC failed with status code 422 and state false
        assert result.status_code == 422 and result.json().get('state') == False, 'Was able to delete invalid MAC address from blacklist.'

#---------------------------------------------------BLACKLIST-ENDPOINTS-END-----------------------------------------------------#

#------------------------------------------------------ALERTS-ENDPOINTS---------------------------------------------------------#
# test alerts endpoints
class TestAlertsEndpoints():

    # test step function for testing add alert
    @pytest.mark.parametrize('alert', [
        {'interface': 'Ethernet', 'attackType': 'ARP Spoofing', 'sourceIp': '192.168.0.1', 'sourceMac': 'aa:bb:cc:dd:ee:ff', 'destinationIp': '192.168.0.2',
        'destinationMac': 'ff:ee:dd:cc:bb:aa', 'protocol': 'ARP', 'osType': 'Windows', 'timestamp': '12:00:00 16/10/25'},
        {'interface': 'eth1', 'attackType': 'Port Scan', 'sourceIp': '10.0.0.1', 'sourceMac': '11:22:33:44:55:66', 'destinationIp': '10.0.0.2',
        'destinationMac': '66:55:44:33:22:11', 'protocol': 'TCP', 'osType': 'Linux', 'timestamp': '13:30:45 16/10/25'},
        {'interface': 'en0', 'attackType': 'DNS Tunneling', 'sourceIp': '172.16.5.10', 'sourceMac': 'de:ad:be:ef:00:01', 'destinationIp': '8.8.8.8',
            'destinationMac': '00:aa:bb:cc:dd:ee', 'protocol': 'DNS', 'osType': 'MACOS', 'timestamp': '14:15:30 16/10/25'}
    ])
    def testAddAlert(self, NetSpectClient, TestUser: dict, alert) -> None:
        result = NetSpectClient.post(Endpoints.API.Alerts.AddAlert, headers=TestUser.get('authHeader'), json=alert)
        # assert added alert successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed adding alert for user.'


    # test step function for testing delete alerts
    def testDeleteAlerts(self, NetSpectClient, TestUser: dict) -> None:
        result = NetSpectClient.delete(Endpoints.API.Alerts.DeleteAlerts, headers=TestUser.get('authHeader'))
        # assert deleted alerts successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed deleting alerts for user.'

#----------------------------------------------------ALERTS-ENDPOINTS-END-------------------------------------------------------#

#------------------------------------------------------USERS-ENDPOINTS----------------------------------------------------------#
# test users endpoint for deleting account
class TestUsersEndpointDeleteAccount():

    # test step function for testing delete account
    def testDeleteAccount(self, NetSpectClient, TestUser: dict) -> None:
        result = NetSpectClient.delete(Endpoints.API.Users.HardDeleteAccount, headers=TestUser.get('authHeader'))
        # assert password changed successfully with status code 200 and state true
        assert result.status_code == 200 and result.json().get('state') == True, 'Failed deleting user\'s account.'

#----------------------------------------------------USERS-ENDPOINTS-END--------------------------------------------------------#

#------------------------------------------------------------MAIN---------------------------------------------------------------#
# main function for running the tests
if __name__ == '__main__':
    pytest.main(['-v', __file__])

#----------------------------------------------------------MAIN-END-------------------------------------------------------------#