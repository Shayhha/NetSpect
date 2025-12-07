from fastapi import FastAPI
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from app.database.database import Database
from app.config.config import serverConfig


# lifespan function for initializing database connection pool on startup and closing it on shutdown
@asynccontextmanager
async def NetSpectServerLifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # start NetSpect server with our configuration and initialize database connecion pool
    try:
        print('🟡 Starting NetSpect server...')
        await Database.InitConnectionPool()
        print('🟢 Initialzied database connection pool successfully.')
        print(f'🟢 NetSpect server running on {serverConfig.host}:{serverConfig.port}')
    except Exception as e:
        raise RuntimeError(f'🔴 Error starting NetSpect server: {e}.')

    # yield server for performing various server oeprations with database
    yield

    # stop NetSpect server when exiting and close database connection pool
    try:
        print('🟡 Shutting down NetSpect server...')
        await Database.CloseConnectionPool()
        print('🟢 Closed database connection pool successfully.')
        print('🔴 NetSpect server stopped.')
    except Exception as e:
        raise RuntimeError(f'🔴 Error shutting down NetSpect server: {e}.')