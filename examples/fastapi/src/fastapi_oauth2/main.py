from fastapi import FastAPI
from fastapi_oauth2.config import settings
from fastapi_oauth2.db import gino
from fastapi_oauth2.router import router

app = FastAPI(title=settings.PROJECT_NAME)
app.include_router(router, prefix="/oauth2/v2")
gino.init_app(app)
