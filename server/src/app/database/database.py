import asyncpg
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from app.config.config import databaseConfig


# class for managing database connection pool, connections and transactions
class Database():
    connectionPool: asyncpg.pool.Pool = None #represents database connection pool


    # method for initializing database connection pool with our database configuration
    @staticmethod
    async def InitConnectionPool() -> None:
        # check if database connection pool is not initialzied
        if not Database.connectionPool:
            # initialize connection pool with database configuration
            Database.connectionPool = await asyncpg.create_pool(
                host=databaseConfig.host,
                database=databaseConfig.database,
                port=databaseConfig.port,
                user=databaseConfig.user,
                password=databaseConfig.password,
                min_size=databaseConfig.poolMinSize,
                max_size=databaseConfig.poolMaxSize,
                timeout=databaseConfig.connectionTimeout,
                command_timeout=databaseConfig.commandTimeout
            )


    # method for checking database connection pool state
    @staticmethod
    async def CheckConnectionPool() -> bool:
        # return database connection pool state
        return Database.connectionPool != None


    # method for acquering database connection from connecion pool for executing queries
    @staticmethod
    @asynccontextmanager
    async def GetConnection() -> AsyncGenerator[asyncpg.Connection, None]:
        # check if database connection pool is not initialzied
        if not Database.connectionPool:
            await Database.InitConnectionPool() #intialize connection pool
        # acquire connection from connection pool and yield connection
        async with Database.connectionPool.acquire() as connection:
            yield connection


    # method for acquering database connection and starting a transaction for executing queries atomicly
    @staticmethod
    @asynccontextmanager
    async def GetTransaction() -> AsyncGenerator[asyncpg.Connection, None]:
        # acquire connection from connection pool and yield connection
        async with Database.GetConnection() as connection:
            # start transaction and yield transaction
            async with connection.transaction():
                yield connection
    

    # method for closing database connection pool
    @staticmethod
    async def CloseConnectionPool() -> None:
        # check if database connection pool is initialzied
        if Database.connectionPool:
            # close the database connection pool
            await Database.connectionPool.close()
            # set connectionPool back to none
            Database.connectionPool = None