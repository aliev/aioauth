First you have to create two databases:

For tests runner and for server itself

```
createdb ownauth;
createdb ownauth_test;
```

In this current directory you have to create .env file:

```
# PostgreSQL specific settings
POSTGRES_SERVER="localhost"
POSTGRES_USER=ownauth
POSTGRES_PASSWORD=
POSTGRES_DB=ownauth
SERVER_NAME=Ownauth
SERVER_HOST=http://127.0.0.1
# This option will disable SSL connection check
OAUTH2_INSECURE_TRANSPORT=True
```

Run and install

```
# Install requirements
pip install -e .
# Apply all migrations
alembic upgrade head
# Run tests
pytest
# Run Server
uvicorn fastapi_oauth2.main:app
```
