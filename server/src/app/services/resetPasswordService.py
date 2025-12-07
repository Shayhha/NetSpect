import asyncio, requests, base64
from email.message import EmailMessage
from smtplib import SMTP
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from app.database.database import asyncpg
from app.utility.utility import Utility
from app.services import usersService
from app.config.config import emailConfig


# function for adding resetcode for given email for user in resetcodes table
async def AddResetCode(connection: asyncpg.Connection, email: str, resetCode: str) -> dict:
    resultDict = {'state': True, 'message': '', 'error': False} #represents result dict
    try:
        resetCodeHash = Utility.ToSHA256(resetCode) #get SHA-256 hash for reset code
        oldResetCodeResult = await CheckResetCode(connection, email) #check if email had an old reset code already

        # if there's an old resetcode for email we delete it from resetcodes table
        if oldResetCodeResult.get('state') and oldResetCodeResult.get('result').get('resetCode'):
            deleteResetCodeResult = await DeleteResetCode(connection, email, oldResetCodeResult.get('result').get('resetCode'))
            resultDict.update(deleteResetCodeResult) #update resultDict based on delete reset code result

        # check if old reset code deletion was successful, if so add new reset code to resetcodes table
        if resultDict.get('state') and not resultDict.get('error'):
            # insert new reset code for user into resetcodes table
            query = '''
                INSERT INTO resetcodes (email, resetcode) 
                VALUES ($1, $2)
                '''
            queryResult = await connection.execute(query, email, resetCodeHash)
            rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

            # we check if operation was successful and rows affected
            if rowsAffected > 0:
                resultDict.update({'message': 'Added reset code successfully.'})
            else:
                resultDict.update({'message': 'Failed adding reset code.', 'state': False})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error adding reset code: {e}.', 'state': False, 'error': True})
    finally:
        return resultDict


# function for checking if given email or reset code present for user in resetcodes table
async def CheckResetCode(connection: asyncpg.Connection, email: str, resetCode: str=None) -> dict:
    resultDict = {'state': False, 'message': '', 'result': {'email': '', 'resetCode': ''}, 'error': False} #represents result dict
    try:
        # check if email has a reset code for user in resetcodes table
        query = '''
            SELECT email, resetcode 
            FROM resetcodes 
            WHERE email = $1
            '''
        queryResult = None #represents query result

        # check if resetCode given, if so we add it
        if resetCode != None:
            query += ' AND resetcode = $2'
            queryResult = await connection.fetchrow(query, email, resetCode)
        else:
            queryResult = await connection.fetchrow(query, email)

        # if we received result we return email and resetCode as result
        if queryResult:
            # update result dict with result email and resetCode for user
            resultDict.update({'message': 'Reset code found successfully.', 'result': {'email': queryResult['email'], 'resetCode': queryResult['resetcode']}, 'state': True})
        else:
            resultDict.update({'message': 'Reset code not found or is invalid.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error checking reset code: {e}.', 'error': True})
    finally:
        return resultDict


# function for deleting reset code for user in resetcodes table
async def DeleteResetCode(connection: asyncpg.Connection, email: str, resetCode: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        # delete reset code for user from resetcodes table
        query = '''
            DELETE FROM resetcodes 
            WHERE email = $1 AND resetcode = $2
            '''
        queryResult = await connection.execute(query, email, resetCode)
        rowsAffected = int(queryResult.split()[-1]) #get how many rows affected

        # we check if operation was successful and rows affected
        if rowsAffected > 0:
            resultDict.update({'message': 'Reset code deleted successfully.', 'state': True})
        else:
            resultDict.update({'message': 'No matching reset code found.', 'state': True})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error deleting reset code: {e}.', 'error': True})
    finally:
        return resultDict


# function for verifying reset code for a user in resetcodes table
async def VerifyResetCode(connection: asyncpg.Connection, email: str, resetCode: str, resetCodeTimeout: int=5) -> dict:
    resultDict = {'state': True, 'message': '', 'result': {'expired': False, 'newPassword': ''}, 'error': False} #represents result dict
    try:
        resetCodeHash = Utility.ToSHA256(resetCode) #get SHA-256 hash for reset code
        resetCodeExists = await CheckResetCode(connection, email, resetCodeHash) #check if reset code exists and assosiated with email address

        # check if reset code exists and assosiated with an email address in database, if so verify timestamp and reset password for user
        if resetCodeExists.get('state') and resetCodeExists.get('result').get('email'):
            # check if reset code valid and not expired for user in resetcodes table
            query = '''
                SELECT email, resetcode 
                FROM resetcodes 
                WHERE email = $1 AND resetcode = $2 
                AND timestamp >= (now() at time zone 'utc') - make_interval(mins => $3)
                '''
            resetCodeValidResult = await connection.fetchrow(query, email, resetCodeHash, resetCodeTimeout)

            # check if rest code is valid, if so we create new password for user and update it in users table
            if resetCodeValidResult:
                newPassword = Utility.GetPassword(8) #create new secure password for user
                resetPasswordResult = await usersService.ResetPassword(connection, email, newPassword) #reset user password by email address with new password
                resultDict.update(resetPasswordResult) #update resultDict based on reset password result

                # check if reset password was successful, if so return new password for user
                if resultDict.get('state') and not resultDict.get('error'):
                    # update result dict with message and return new password for user
                    resultDict.update({'message': 'Verified reset code successfully. Use new password to log in and change it if necessary.', 'result': {'expired': False, 'newPassword': newPassword}})

            else:
                # update result dict with message and return expired result for user's given reset code
                resultDict.update({'message': f'The reset code has expired, it was valid for {resetCodeTimeout} minutes. Try resetting password again.', 'result': {'expired': True, 'newPassword': ''}, 'state': False})

            await DeleteResetCode(connection, email, resetCodeHash) #delete old reset code for user
        else:
            resultDict.update({'message': 'Your given reset code is incorrect, try again.', 'state': False})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error verifying reset code: {e}.', 'state': False, 'error': True})
    finally:
        return resultDict


# function for sending reset code to user's email for a user in users table
async def SendResetCode(connection: asyncpg.Connection, email: str) -> dict:
    resultDict = {'state': False, 'message': '', 'error': False} #represents result dict
    try:
        emailExists = await usersService.CheckEmail(connection, email, 0) #check if email exists in database and not associated with deleted user

        # check that email exists in database before sending rest code
        if emailExists != None:
            resetCode = Utility.GetResetCode(16) #create reset code for user
            addResetCodeResult = await AddResetCode(connection, email, resetCode) #add reset code for user in resetcodes table

            # check that add reset code was successful, if so send reset code to user's email
            if addResetCodeResult.get('state'):
                isEmailSent = await SendEmail(email, resetCode) #try to send reset code to user's email

                # check if email was sent successfully
                if isEmailSent:
                    resultDict.update({'message': 'Sent reset code to user\'s email successfully.', 'state': True})
                else:
                    resultDict.update({'message': 'Failed sending reset code to user\'s email.', 'error': True})
            else:
                resultDict.update({'message': 'Failed to create reset code, try again later.', 'error': True})
        else:
            resultDict.update({'message': 'Email is not associated with any account, please try another one.'})

    # if exception occured we return error message
    except Exception as e:
        resultDict.update({'message': f'Error sending reset code: {e}.', 'error': True})
    finally:
        return resultDict


# function for sending email with reset code to user's registered email
async def SendEmail(userEmail: str, resetCode: str, resetCodeTimeout: int=5) -> bool:
    try:
        # check if email is given, else return false
        if not emailConfig.email:
            return False

        # create email message with our desired format with given reset code
        message = EmailMessage()
        message.set_content(f'''
            <html>
                <body>
                    <p>Hello,</p>
                    <p>You requested a password reset for your NetSpect account.</p>
                    <p>Your reset code is: <strong>{resetCode}</strong></p>
                    <p>This code is valid for {resetCodeTimeout} minutes.</p>
                    <p>If you did not request this reset, please ignore this email.</p>
                    <p>Best Regards,<br>NetSpect Team</p>
                </body>
            </html>
            ''', subtype='html')
        message['Subject'] = 'NetSpect Password Reset Request'
        message['From'] = emailConfig.email
        message['To'] = userEmail

        # check if client id, secret and token are given, if so send email with HTTPS via Gmail API
        if emailConfig.clientId and emailConfig.clientSecret and emailConfig.clientToken:
            return await asyncio.to_thread(SendEmailHTTPS, message) #send reset code email with HTTPS

        # else check if host and password are given, is so send email with SMTPS
        elif emailConfig.host and emailConfig.password:
            return await asyncio.to_thread(SendEmailSMTPS, message) #send reset code email with SMTPS

        # else no email information given for both email methods, we return false
        else:
            return False #return false if no email information given

    # if exception occured we return false
    except Exception as e:
        return False


# function for sending email with SMTPS to user's registered email
def SendEmailSMTPS(message: EmailMessage) -> bool:
    try:
        # send reset code with SMTPS with email host and password with TLS
        with SMTP(emailConfig.host, 587) as server:
            server.ehlo()
            server.starttls()
            server.login(emailConfig.email, emailConfig.password)
            server.send_message(message)
        # return true if we sent email successfully
        return True

    # if exception occured we return false
    except Exception as e:
        return False


# function for sending email with HTTPS via Gmail API to user's registered email
def SendEmailHTTPS(message: EmailMessage) -> bool:
    try:
        # create credentials with client information for sending email with Gmail API
        credentials = Credentials(
            token=None,
            refresh_token=emailConfig.clientToken,
            token_uri=emailConfig.tokenUrl,
            client_id=emailConfig.clientId,
            client_secret=emailConfig.clientSecret,
            scopes=[emailConfig.scopeUrl]
        )
        credentials.refresh(Request()) #get new access token with our client token

        # encode our email message for sending email with Gmail API
        encodedMessage = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')

        # send reset code via HTTPS post request with client information and access token
        response = requests.post(
            emailConfig.sendUrl,
            headers={'Authorization': f'Bearer {credentials.token}', 'Content-Type': 'application/json'},
            json={'raw': encodedMessage}
        )
        # return true if we sent email successfully
        return True if response.status_code >= 200 and response.status_code < 300 else False

    # if exception occured we return false
    except Exception as e:
        return False