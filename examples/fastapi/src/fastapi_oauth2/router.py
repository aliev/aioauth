from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/authorize")
def get_router(request: Request):
    ...
