from abc import ABC
from uuid import UUID
from hashlib import sha256
from secrets import choice, token_hex
from string import digits, ascii_letters, ascii_uppercase


# static class for getting sha-256 hashes, creating secure passwords and creating reset codes
class Utility(ABC):

   # function for hashing given password with sha-256, retuns hex representation
    @staticmethod
    def ToSHA256(message: str) -> str | None:
        try:
            sha256Obj = sha256() #create a sha-256 object
            sha256Obj.update(message.encode()) #update message with its sha-256 hash
            return sha256Obj.hexdigest() #return hash as hexadecimal
        except Exception:
            return None #return none if exception occured
    

    # function for getting UUID object from given message string
    @staticmethod
    def GetUUID(message: str) -> UUID | None:
        try:
            uuidStr = UUID(message) #create uuid object from given string
            return uuidStr #return uuid object if successful
        except Exception:
            return None #return none if exception occured


    # method for generating a password for user in specified length
    @staticmethod
    def GetPassword(length: int=8) -> str | None:
        try:
            # create a password in specified length with at least one uppercase and one digit
            password = [choice(ascii_letters + digits) for _ in range(length)]
            password[choice(range(length))] = choice(ascii_uppercase) #set uppercase letter in random position
            password[choice(range(length))] = choice(digits) #set digit in random position
            return ''.join(password) #return generated password
        except Exception:
            return None #return none if exception occured


    # method for generating a reset code in specified length
    @staticmethod
    def GetResetCode(length: int=8) -> str | None:
        try:
            resetCode = token_hex(length // 2) #generate a reset code in specified length
            return resetCode #return generated reset code
        except Exception:
            return None #return none if exception occured