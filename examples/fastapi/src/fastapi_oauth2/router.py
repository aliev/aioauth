from async_oauth2_provider.integrations.fastapi.utils import (
    to_fastapi_response,
    to_oauth2_request,
)
from fastapi import APIRouter, Request
from fastapi_oauth2.oauth2 import endpoint

router = APIRouter()


@router.get("/authorize")
@router.post("/authorize")
async def authorize(request: Request):
    oauth2_request = await to_oauth2_request(request)
    oauth2_response = await endpoint.create_authorization_response(oauth2_request)

    return await to_fastapi_response(oauth2_response)


@router.post("/token")
async def token(request: Request):
    oauth2_request = await to_oauth2_request(request)
    oauth2_response = await endpoint.create_token_response(oauth2_request)

    return await to_fastapi_response(oauth2_response)
