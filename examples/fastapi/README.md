Run and install

```
pip install -e .
alembic upgrade head
uvicorn fastapi_oauth2.main:app
```
