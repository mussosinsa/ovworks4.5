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
* converts the Engine login verifier and its loopback host rules to SCRAM in
  the closeup stage;
* sets SCRAM in the SQL session before changing the `postgres` role password;
* keeps local operating-system administration through the existing peer/ident
  path, so routine scripts do not need the superuser password.

The `postgres` password is deliberately applied during the closeup stage, after
the Engine, DWH, and AAA database schemas and configuration have completed.
Until then setup performs local administration as the operating-system
`postgres` user over peer authentication, without a PostgreSQL superuser
password. This prevents changing the superuser credentials from disrupting
later setup tools such as `ovirt-aaa-jdbc-tool`.

During schema and miscellaneous configuration, setup temporarily uses an MD5
verifier and MD5 loopback rules for the Engine database login. This is required
because `ovirt-aaa-jdbc-tool` can run before the final PostgreSQL JBoss module
with its ONGRES SCRAM runtime is installed. Enabling SCRAM earlier makes that
tool fail with `NoClassDefFoundError` for an ONGRES `StringPreparation` class.

During closeup, after all Java setup tools have finished, setup rewrites the
Engine verifier and installs only the following final rules for a locally
provisioned database:

```text
host    ovirt_engine    engine    127.0.0.1/32    scram-sha-256
host    ovirt_engine    engine    ::1/128         scram-sha-256
```

The database and role names follow the names selected during setup. Setup then
restarts PostgreSQL before completing installation. Thus MD5 is limited to the
local setup transaction and is not left in the completed configuration.

The packaged `org.postgresql` JBoss module contains the ONGRES
`com.ongres.scram:client`, `com.ongres.scram:common`, and
`com.ongres.stringprep:saslprep` and `com.ongres.stringprep:stringprep` runtime
libraries required by PostgreSQL JDBC 42.2.x. Omitting any of these libraries
causes SCRAM connections from Engine and `ovirt-aaa-jdbc-tool` to fail with a
`NoClassDefFoundError`, including for `com.ongres.saslprep.SaslPrep` or
`com.ongres.stringprep.StringPrep`. These four Maven artifacts are bundled
directly in the Engine PostgreSQL module. They must not be replaced during RPM assembly by
absolute links to distribution-specific JAR paths: a missing or renamed system
JAR leaves a dangling module resource and makes Engine deployment fail only
after SCRAM is enabled.

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
