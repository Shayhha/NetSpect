import sys, os
from dotenv import load_dotenv
from pathlib import Path
from app.schemas.baseSchema import BaseModel, RequiredStr, UrlStr, EmailStr, PositiveInt

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located

load_dotenv(dotenv_path=currentDir.parent / 'config' / '.env') #load environment variables from .env if exists

#----------------------------------------SERVER-CONFIGURATION-SCHEMA-----------------------------------------#
# represents server configuration
class ServerConfig(BaseModel):
    name: str = 'NetSpectServer' #represents server name
    mode: str = 'production' #represents server mode, production or development
    app: str = 'app.main:app' #represents server app for running with uvicorn
    host: str = '0.0.0.0' #represents server host, default is 0.0.0.0
    port: PositiveInt = 8000 #represnets server port, defualt 8000
    workers: PositiveInt = 0 #represnets number of server workers, defualt 0
    proxyHeaders: bool = False #represents server proxy headers state
    forwardedIps: str | None = None #represents server forwarded ips state
    reload: bool = False #represents server reload state
    storageUrl: UrlStr | None = None #represents server storage url like redis, default is in memory
    title: str = 'NetSpect RESTful API Server' #represents server title
    version: str = '1.0.0' #represents server version
    contact: dict = {'name': 'NetSpect GitHub', 'url': 'https://github.com/Shayhha/NetSpect'} #represents server contact info
    licenseInfo: dict = {'name': 'GPLv3 License', 'url': 'https://www.gnu.org/licenses/gpl-3.0'} #represents server license info
    docsIcon: str = 'NetSpectIconTransparent.ico' #represents server docs icon
    docsTitle: str = 'NetSpect API Docs' #represents server docs title
    redocTitle: str = 'NetSpect API ReDoc' #represents server redoc title
    openApiUrl: str | None = None #represents server openapi url
    docsUrl: str | None = None #represents server docs url
    redocUrl: str | None = None #represents server redoc url
    description: str = ( #represents server description
        '<div align="center"><br>'
        f'<img src="/static/{docsIcon}" alt="Logo" width="100">'
        '<h2><b>NetSpect IDS RESTful API Server</b></h2>'
        'This RESTful API server provides endpoints for NetSpect IDS, including authentication, user and session management, reset password, blacklist management and alert handling.<br><br>'
        'All API endpoints interact with the database to securely maintain application state and enable real-time functionality for NetSpect IDS.<br><br><br>'
        '</div>'
    )

    # class method that creates an instance for our ServerConfig class
    @classmethod
    def GetInstance(cls) -> 'ServerConfig':
        # get server mode from env file
        serverMode = os.getenv('SERVER_MODE', 'production')
        # return cls instance with our server configuration
        return cls(
            mode=serverMode,
            host=os.getenv('SERVER_HOST', '0.0.0.0'),
            port=os.getenv('PORT', os.getenv('SERVER_PORT', '8000')),
            workers=os.getenv('SERVER_WORKERS', '0'),
            proxyHeaders=True if serverMode == 'production' else False,
            forwardedIps='*' if serverMode == 'production' else None,
            reload=False if serverMode == 'production' else True,
            storageUrl=os.getenv('SERVER_STORAGE_URL') or None
        )

#--------------------------------------SERVER-CONFIGURATION-SCHEMA-END---------------------------------------#

#---------------------------------------DATABASE-CONFIGURATION-SCHEMA----------------------------------------#
# represents database configuration
class DatabaseConfig(BaseModel):
    host: RequiredStr | None = None #represents database host name
    database: RequiredStr | None = None #represents database name
    port: PositiveInt = 5432 #represents database port, default 5432
    user: RequiredStr | None = None #represents database user
    password: RequiredStr | None = None #represents database password
    poolMinSize: PositiveInt = 0 #represents minimum amount of connections in pool, 0 by default
    poolMaxSize: PositiveInt = 20 #represents maximum concurrent connections, 20 connections by default
    connectionTimeout: float = 10.0 #represents connection timeout, 10 seconds by default
    commandTimeout: float = 30.0 #represents command timeout, 30 seconds by default

    # class method that creates an instance for our DatabaseConfig class
    @classmethod
    def GetInstance(cls) -> 'DatabaseConfig':
        # return cls instance with our database configuration
        return cls(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_DATABASE'),
            port=os.getenv('DB_PORT', '5432'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            poolMinSize=os.getenv('DB_POOL_MIN', '0'),
            poolMaxSize=os.getenv('DB_POOL_MAX', '20')
        )

#-------------------------------------DATABASE-CONFIGURATION-SCHEMA-END--------------------------------------#

#----------------------------------------EMAIL-CONFIGURATION-SCHEMA------------------------------------------#
# represents email configuration
class EmailConfig(BaseModel):
    email: EmailStr | None = None #represents email for reset password
    host: RequiredStr | None = 'smtp.gmail.com' #represents email host for reset password
    password: RequiredStr | None = None #represents email password for reset password
    clientId: RequiredStr | None = None #represents email client id for reset password
    clientSecret: RequiredStr | None = None #represents email client secret for reset password
    clientToken: RequiredStr | None = None #represents email client token for reset password
    scopeUrl: UrlStr | None = 'https://www.googleapis.com/auth/gmail.send' #represents email scope url for reset password
    authUrl: UrlStr | None = 'https://accounts.google.com/o/oauth2/auth' #represents email auth url for reset password
    tokenUrl: UrlStr | None = 'https://oauth2.googleapis.com/token' #represents email token url for reset password
    sendUrl: UrlStr | None = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send' #represents send scope url for reset password

    # class method that creates an instance for our EmailConfig class
    @classmethod
    def GetInstance(cls) -> 'EmailConfig':
        # return cls instance with our email configuration
        return cls(
            email=os.getenv('MAIL_EMAIL') or None,
            host=os.getenv('MAIL_HOST', 'smtp.gmail.com') or None,
            password=os.getenv('MAIL_PASSWORD') or None,
            clientId=os.getenv('MAIL_CLIENT_ID') or None,
            clientSecret=os.getenv('MAIL_CLIENT_SECRET') or None,
            clientToken=os.getenv('MAIL_CLIENT_TOKEN') or None,
            scopeUrl=os.getenv('MAIL_SCOPE_URL', 'https://www.googleapis.com/auth/gmail.send') or None,
            authUrl=os.getenv('MAIL_AUTH_URL', 'https://accounts.google.com/o/oauth2/auth') or None,
            tokenUrl=os.getenv('MAIL_TOKEN_URL', 'https://oauth2.googleapis.com/token') or None,
            sendUrl=os.getenv('MAIL_SEND_URL', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send') or None
        )

#---------------------------------------EMAIL-CONFIGURATION-SCHEMA-END---------------------------------------#

#-----------------------------------------APP-CONFIGURATION-INSTANCES----------------------------------------#
try:
    # create our configuration instances for later use in server
    serverConfig = ServerConfig.GetInstance()
    databaseConfig = DatabaseConfig.GetInstance()
    emailConfig = EmailConfig.GetInstance()

# if exception occured we log validation error and exit
except Exception as e:
    print(f'Error initializing server configuration: {e}.')
    raise sys.exit(1)

#---------------------------------------APP-CONFIGURATION-INSTANCES-END--------------------------------------#