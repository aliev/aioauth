"""Create data.

Revision ID: b14aa9fada68
Revises: c213ee84fc60
Create Date: 2020-09-19 10:38:33.484843

"""
import json
import time

import sqlalchemy as sa
from alembic import op
from async_oauth2_provider.types import GrantType, ResponseType
from fastapi_oauth2.tables import ClientTable

# revision identifiers, used by Alembic.
revision = "b14aa9fada68"
down_revision = "c213ee84fc60"
branch_labels = None
depends_on = None
client_table = ClientTable.__table__
client_id = "67IGqEoQ8ddoh5s0wuJll51G"
client_secret = "h4s5RJ4OMu92jk0e5scodq5nNPhblW"


def upgrade():
    op.execute(
        sa.insert(client_table).values(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=int(time.time()),
            client_secret_expires_at=int(time.time()),
            client_metadata=json.dumps(
                {
                    "grant_types": [
                        GrantType.TYPE_AUTHORIZATION_CODE.value,
                        GrantType.TYPE_PASSWORD.value,
                        GrantType.TYPE_CLIENT_CREDENTIALS.value,
                        GrantType.TYPE_REFRESH_TOKEN.value,
                    ],
                    "response_types": [
                        ResponseType.TYPE_TOKEN.value,
                        ResponseType.TYPE_CODE.value,
                    ],
                    "redirect_uris": ["https://ownauth.com/callback"],
                    "scope": "read write",
                }
            ),
        )
    )


def downgrade():
    op.execute(sa.delete(client_table).where(client_table.c.client_id == client_id))
