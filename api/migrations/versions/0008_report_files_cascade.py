"""report_files se borra con su scan o su grupo (F9)

report_files apunta a un scan o a un grupo según subject_type, así que no puede llevar una
clave foránea normal. La cascada se hace con triggers: vale para cualquier DELETE, venga de
la api, de la purga por retención o de psql.

Revision ID: 0008
Revises: 0007
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Huérfanos que hayan quedado de antes.
    op.execute(
        "DELETE FROM report_files f WHERE (f.subject_type = 'scan' AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = f.subject_id)) "
        "OR (f.subject_type = 'group' AND NOT EXISTS (SELECT 1 FROM test_groups g WHERE g.id = f.subject_id))"
    )
    op.execute(
        """
        CREATE FUNCTION report_files_cascade() RETURNS trigger AS $$
        BEGIN
            DELETE FROM report_files WHERE subject_type = TG_ARGV[0] AND subject_id = OLD.id;
            RETURN OLD;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute("CREATE TRIGGER jobs_report_files_cascade AFTER DELETE ON jobs FOR EACH ROW EXECUTE FUNCTION report_files_cascade('scan')")
    op.execute("CREATE TRIGGER test_groups_report_files_cascade AFTER DELETE ON test_groups FOR EACH ROW EXECUTE FUNCTION report_files_cascade('group')")
    op.create_index("ix_report_files_subject", "report_files", ["subject_type", "subject_id"])
    # Purga por retención (F9): busca scans terminados por fecha.
    op.create_index("ix_jobs_created_at", "jobs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_jobs_created_at", table_name="jobs")
    op.drop_index("ix_report_files_subject", table_name="report_files")
    op.execute("DROP TRIGGER test_groups_report_files_cascade ON test_groups")
    op.execute("DROP TRIGGER jobs_report_files_cascade ON jobs")
    op.execute("DROP FUNCTION report_files_cascade()")
