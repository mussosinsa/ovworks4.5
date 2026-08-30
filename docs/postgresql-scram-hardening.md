# PostgreSQL SCRAM hardening during engine-setup

PostgreSQL has no `root` database account. For automatic local provisioning,
`engine-setup` asks for the password of the PostgreSQL superuser role named
`postgres`; it never changes the Linux `root` password.

The prompt is hidden, asks for confirmation, and requires at least 14
characters. In unattended setup the secret answer key is:

```text
OVESETUP_PROVISIONING/postgresSuperuserPassword
```

Treat answer files containing this key as secrets and remove them after the
approved installation workflow. Prefer interactive entry.

For newly provisioned local PostgreSQL, setup performs all of the following:

* persists `password_encryption = 'scram-sha-256'` in `postgresql.conf`;
* sets the same value in the SQL session before creating the Engine login and
  before changing the `postgres` role password;
* replaces setup-managed `md5` host entries with `scram-sha-256`; and
* keeps local operating-system administration through the existing peer/ident
  path, so routine scripts do not need the superuser password.

The `postgres` password is deliberately applied during the closeup stage, after
the Engine, DWH, and AAA database schemas and configuration have completed.
Until then setup performs local administration as the operating-system
`postgres` user over peer authentication, without a PostgreSQL superuser
password. This prevents changing the superuser credentials from disrupting
later setup tools such as `ovirt-aaa-jdbc-tool`.

The packaged `org.postgresql` JBoss module also contains the ONGRES
`com.ongres.scram:client` and `com.ongres.scram:common` runtime libraries
required by PostgreSQL JDBC 42.2.x. Omitting these libraries causes SCRAM
connections from Engine and
`ovirt-aaa-jdbc-tool` to fail with a `NoClassDefFoundError` for
`com.ongres.scram` classes. The Engine RPM requires the `ongres-scram` system
package and links its `client.jar` and `common.jar` directly into the
`org.postgresql` module; declaring Maven dependencies alone is not sufficient
for the installed RPM module.

The password is passed as a database driver parameter. It is not interpolated
into SQL, logged, included in summaries, or stored by the provisioning code.

After setup, verify without printing password hashes:

```console
sudo -u postgres psql -X -d postgres -tAc "show password_encryption"
sudo -u postgres psql -X -d postgres -tAc \
  "select rolpassword like 'SCRAM-SHA-256$%' from pg_authid where rolname='postgres'"
grep -E '^[[:space:]]*password_encryption[[:space:]]*=' \
  /var/lib/pgsql/data/postgresql.conf
grep -E '^[[:space:]]*host' /var/lib/pgsql/data/pg_hba.conf
```

Expected results include `scram-sha-256`, `t`, and setup-managed host rules
ending in `scram-sha-256`. Paths can differ for a non-default PostgreSQL data
directory.

This behavior applies only when setup automatically provisions a local new
database. For a remote or manually managed PostgreSQL server, the DBA must set
SCRAM policy and the superuser password outside `engine-setup` before connection
validation.
