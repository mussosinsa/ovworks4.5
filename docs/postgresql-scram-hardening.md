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
* finally makes every local login need a password: `su - postgres` followed by
  `psql` asks for the `postgres` role's password from then on. Unattended
  checks log in as the read-only `ovworks_ops` role instead, reachable by peer
  authentication from `root` and `ovirt` only. See
  [db-local-authentication.md](db-local-authentication.md).

Setup itself still works as the operating-system `postgres` user over the
socket when it provisions, installs extensions, grants access or upgrades
PostgreSQL. It relaxes the local rules for the duration of that work and puts
them back afterwards.

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

## Components outside the JBoss module path

Bundling the runtime in the `org.postgresql` module covers everything that runs
under JBoss modules. That is not everything that opens a PostgreSQL connection,
and treating it as such is how the Data Warehouse was broken by this hardening
once already.

| Component | Reaches the SCRAM runtime by |
| --- | --- |
| Engine deployments | the `org.postgresql` JBoss module |
| `ovirt-aaa-jdbc-tool` | the same module |
| `ovirt-engine-notifier` | a separate JVM, started with `ENGINE_JAVA_MODULEPATH`, so the module still applies |
| **Data Warehouse ETL (`ovirt-engine-dwhd`)** | **nothing, until setup places the libraries beside its own JARs** |

`ovirt-engine-dwhd` starts a plain JVM whose classpath is
`<PKG_JAVA_LIB>/*` plus whatever `dwh-classpath.sh` resolves. That resolves the
PostgreSQL JDBC driver and not the libraries the driver calls, so the failure
happens *after* the driver has loaded:

```text
java.lang.NoClassDefFoundError: com/ongres/scram/common/stringprep/StringPreparation
    at org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(...)
Caused by: java.lang.ClassNotFoundException:
    com.ongres.scram.common.stringprep.StringPreparation
```

The ETL exits 1, systemd restarts it forever, and nothing else changes: the
engine still reaches the Data Warehouse database (it has the libraries), so the
dashboard's `dwhAvailable` check passes and the dashboard renders. It renders
every utilization figure as zero, because no sample is ever collected. Nothing
in the event list says the database refused anything.

So setup places the four libraries where the ETL loads its own, as links into
the engine's module directory - see
`packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/dwh_scram_runtime.py`:

* only when `historyETL.jar` is present, so a host without the Data Warehouse
  is left alone;
* into every directory that carries it, because which one is `PKG_JAVA_LIB`
  depends on the `ovirt-engine-dwh` build;
* named `ongres-*.jar`, so what put them there is legible and
  `engine-cleanup` can take them back before the engine's own tree goes;
* as links rather than copies, so an engine update carries a corrected library
  across;
* refusing to continue when it cannot, because the alternative is a Data
  Warehouse that cannot log in and says so nowhere an administrator looks.

`ov-works-security_audit.sh` checks the same thing on a running host
(`check_dwh_scram_runtime`), for the case where the Data Warehouse was
installed after `engine-setup` last ran. It reports the libraries as missing
only once the database actually uses `scram-sha-256`, and reports
`ovirt-engine-dwhd` separately when it is not running.

To verify by hand:

```console
head -1 /usr/share/ovirt-engine-dwh/lib/historyETL.jar >/dev/null && \
  ls -l /usr/share/ovirt-engine-dwh/lib/ | grep ongres
systemctl is-active ovirt-engine-dwhd
sudo -u postgres psql -d ovirt_engine_history -tAc \
  "select count(*) from v4_5_statistics_hosts_resources_usage_samples
    where history_datetime >= current_timestamp - interval '10 minute'"
```

A running service with a non-zero sample count is the whole of it; a dashboard
reading zero with the service in `activating (auto-restart)` is this failure.

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
