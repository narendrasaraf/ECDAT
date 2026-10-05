"""Initial project/access/evidence/job/audit schema."""
from alembic import op
from ecdat.store import Base
revision='0001'
down_revision=None
branch_labels=None
depends_on=None
def upgrade():
    Base.metadata.create_all(op.get_bind())
def downgrade():
    raise RuntimeError('Destructive downgrade is not supported; restore a reviewed database backup')
