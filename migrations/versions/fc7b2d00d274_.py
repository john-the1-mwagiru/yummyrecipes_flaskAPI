"""empty message

Revision ID: fc7b2d00d274
Revises: 
Create Date: 2023-09-11 08:52:07.560384

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "fc7b2d00d274"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_index("ix_users_email")

    op.drop_table("users")
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "users",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column("email", sa.VARCHAR(length=32), autoincrement=False, nullable=True),
        sa.Column("name", sa.VARCHAR(length=32), autoincrement=False, nullable=True),
        sa.Column(
            "password_hash", sa.VARCHAR(length=128), autoincrement=False, nullable=True
        ),
        sa.PrimaryKeyConstraint("id", name="users_pkey"),
    )
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.create_index("ix_users_email", ["email"], unique=False)

    # ### end Alembic commands ###
