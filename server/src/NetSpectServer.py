import sys, os, uvicorn
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) #ensures that NetSpectServer.py file will run from main folder in the terminal
from app.config.config import serverConfig

#------------------------------------------------------------MAIN---------------------------------------------------------------#
# main function for running NetSpect FastAPI server
if __name__ == '__main__':
    try:
        # start NetSpect FastAPI server with uvicorn using our server configuration settings
        uvicorn.run(app=serverConfig.app, host=serverConfig.host, port=serverConfig.port, workers=serverConfig.workers, proxy_headers=serverConfig.proxyHeaders, forwarded_allow_ips=serverConfig.forwardedIps, reload=serverConfig.reload)

    # if exception occured we log error message and exit
    except Exception as e:
        print(f'Error starting server: {e}.')
        raise sys.exit(1)

#-----------------------------------------------------------MAIN-END------------------------------------------------------------#