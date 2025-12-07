from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from app.core.serverLifespan import NetSpectServerLifespan
from app.core.exceptionHandlers import RequestValidationErrorHandler, HTTPExceptionHandler, RateLimitExceededHandler
from app.core.serverDocs import SetupDocs
from app.routers import statusRouter, authRouter, usersRouter, sessionsRouter, resetPasswordRouter, blacklistRouter, alertsRouter
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import limiter
from app.config.config import serverConfig

# create NetSpect server app with server configuration and lifespan
app = FastAPI(title=serverConfig.title, description=serverConfig.description, version=serverConfig.version, contact=serverConfig.contact,
               license_info=serverConfig.licenseInfo, openapi_url=serverConfig.openApiUrl, docs_url=serverConfig.docsUrl, redoc_url=serverConfig.redocUrl, lifespan=NetSpectServerLifespan)

# setup our custom OpenAPI documentation
SetupDocs(app, serverConfig.docsTitle, serverConfig.redocTitle, serverConfig.docsIcon)

# attach limiter to app state
app.state.limiter = limiter

# add slowapi middleware to server app
app.add_middleware(SlowAPIMiddleware)

# check if server is in production mode, if so enable HTTPS redirect middleware
if serverConfig.mode == 'production':
    # add HTTPS redirect middleware to server app
    app.add_middleware(HTTPSRedirectMiddleware)

# add exception handlers to server app
app.add_exception_handler(RequestValidationError, RequestValidationErrorHandler)
app.add_exception_handler(HTTPException, HTTPExceptionHandler)
app.add_exception_handler(RateLimitExceeded, RateLimitExceededHandler)

# include routers for server app with our api endpoints
app.include_router(statusRouter.router)
app.include_router(authRouter.router, prefix=Endpoints.API.Base)
app.include_router(usersRouter.router, prefix=Endpoints.API.Base)
app.include_router(sessionsRouter.router, prefix=Endpoints.API.Base)
app.include_router(resetPasswordRouter.router, prefix=Endpoints.API.Base)
app.include_router(blacklistRouter.router, prefix=Endpoints.API.Base)
app.include_router(alertsRouter.router, prefix=Endpoints.API.Base)