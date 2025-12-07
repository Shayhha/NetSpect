import sys, os
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.config.config import BaseModel, serverConfig

#--------------------------------------RATE-LIMIT-CONFIGURATION-SCHEMA---------------------------------------#
# represents app rate limit configuration
class RateLimitConfig(BaseModel):
    api: str = '100/minute' #represents api endpoints rate limit
    auth: str = '10/minute' #represents auth endpoints rate limit
    resetPassword: str = '5/hour' #represents reset password endpoints rate limit

    # class method that creates an instance for our RateLimitConfig class
    @classmethod
    def GetInstance(cls) -> 'RateLimitConfig':
        # return cls instance with our rate limit configuration
        return cls(
            api='100/minute' if serverConfig.mode == 'production' else '1000/minute',
            auth='10/minute' if serverConfig.mode == 'production' else '100/minute',
            resetPassword='5/hour' if serverConfig.mode == 'production' else '10/hour'
        )

#------------------------------------RATE-LIMIT-CONFIGURATION-SCHEMA-END-------------------------------------#

#------------------------------------RATE-LIMIT-CONFIGURATION-INSTANCES--------------------------------------#
try:
    # create our rate limit configuration instance for later use in server
    rateLimitConfig = RateLimitConfig.GetInstance()

    # create limiter instance for app server rate limit with our rate limit configuration and with storage url if given
    limiter = Limiter(key_func=get_remote_address, default_limits=[rateLimitConfig.api], storage_uri=serverConfig.storageUrl,
                       in_memory_fallback=[rateLimitConfig.api], in_memory_fallback_enabled=True, key_prefix=f'{serverConfig.name}:')

# if exception occured we log validation error and exit
except Exception as e:
    print(f'Error initializing rate limit configuration: {e}.')
    raise sys.exit(1)

#-----------------------------------RATE-LIMIT-CONFIGURATION-INSTANCES-END-----------------------------------#