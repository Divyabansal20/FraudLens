from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from loguru import logger
from sqlalchemy.exc import IntegrityError


def register_exception_handlers(app: FastAPI):

    @app.exception_handler(IntegrityError)
    async def integrity_exception_handler(
        request: Request,
        exc: IntegrityError,
    ):
        logger.error(str(exc))

        return JSONResponse(
            status_code=400,
            content={
                "message": "Database integrity error.",
                "detail": "The requested operation violates database constraints.",
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,
        exc: Exception,
    ):
        logger.exception(exc)

        return JSONResponse(
            status_code=500,
            content={
                "message": "Internal Server Error"
            },
        )