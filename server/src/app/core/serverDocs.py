from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.staticfiles import StaticFiles
from app.utility.serverEnums import Endpoints
from app.dependancies.rateLimit import rateLimitConfig, limiter
from pathlib import Path

currentDir = Path(__file__).resolve().parent #represents the path to the current working direcotry where this file is located


# function for setting our custom title and icon for OpenAPI docs
def SetupDocs(app: FastAPI, docsTitle: str, redocTitle: str, icon: str) -> None:
    # mount static folder for accessing our icons in static path
    app.mount(Endpoints.Static, StaticFiles(directory=currentDir.parent / 'static'), name='static')

    # get OpenAPI schema with our custom rate limiting
    @app.get(Endpoints.OpenApi, include_in_schema=False, description='**Get OpenAPI schema for users.**')
    @limiter.limit(rateLimitConfig.api)
    async def GetOpenApi(request: Request) -> JSONResponse:
        # return our custom OpenAPI schema
        return JSONResponse(content=app.openapi(), status_code=status.HTTP_200_OK)

    # get Swagger UI html with our custom title and icon
    @app.get(Endpoints.Docs, include_in_schema=False, description='**Get Swagger UI API for users.**')
    @limiter.limit(rateLimitConfig.api)
    async def GetSwaggerUIHtml(request: Request) -> get_swagger_ui_html:
        # return our custom Swagger UI html
        return get_swagger_ui_html(openapi_url=Endpoints.OpenApi, title=docsTitle, swagger_favicon_url=f'{Endpoints.Static}/{icon}')

    # get ReDoc UI html with our custom title and icon
    @app.get(Endpoints.Redoc, include_in_schema=False, description='**Get ReDoc UI API for users.**')
    @limiter.limit(rateLimitConfig.api)
    async def GetReDocHtml(request: Request) -> get_redoc_html:
        # return our custom ReDoc UI html
        return get_redoc_html(openapi_url=Endpoints.OpenApi, title=redocTitle, redoc_favicon_url=f'{Endpoints.Static}/{icon}')