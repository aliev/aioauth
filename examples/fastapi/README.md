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
uvicorn fastapi_oauth2.main:app --reload
```

Try

```
http://127.0.0.1:8000/oauth/v2/authorize?client_id=67IGqEoQ8ddoh5s0wuJll51G&redirect_uri=https://ownauth.com/callback&response_type=token&state=123&scope=wead%20write
```
