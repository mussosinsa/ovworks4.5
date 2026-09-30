import unittest
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).parents[3]
ROOT_POM = ROOT / 'pom.xml'
MODULE_XML = (
    ROOT
    / 'backend/manager/dependencies/common/src/main/modules'
    / 'org/postgresql/main/module.xml'
)
COMMON_POM = ROOT / 'backend/manager/dependencies/common/pom.xml'
ENGINE_SPEC = ROOT / 'ovirt-engine.spec.in'
ENGINE_CONSTANTS = (
    ROOT / 'packaging/setup/ovirt_engine_setup/engine/constants.py'
)
DWH_RUNTIME_PLUGIN = (
    ROOT
    / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine'
    / 'system/dwh_scram_runtime.py'
)
SYSTEM_PLUGINS_INIT = (
    ROOT
    / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine'
    / 'system/__init__.py'
)
REMOVE_PLUGIN = (
    ROOT
    / 'packaging/setup/plugins/ovirt-engine-remove/ovirt-engine'
    / 'config/misc.py'
)
NOTIFIER_LAUNCHER = (
    ROOT
    / 'packaging/services/ovirt-engine-notifier/ovirt-engine-notifier.py.in'
)
AUDIT_SCRIPT = ROOT / 'ov-works-security_audit.sh'
SCRAM_DOC = ROOT / 'docs/postgresql-scram-hardening.md'

# The libraries the PostgreSQL JDBC driver loads to answer a SCRAM challenge.
# They are needed after the driver itself has loaded, so having the driver on a
# classpath says nothing about whether authentication will work.
SCRAM_RUNTIME_JARS = ('client.jar', 'common.jar', 'saslprep.jar', 'stringprep.jar')


class PostgresqlJdbcScramModuleTest(unittest.TestCase):
    def test_dependency_management_uses_published_scram_coordinates(self):
        tree = ElementTree.parse(ROOT_POM)
        namespace = {'p': 'http://maven.apache.org/POM/4.0.0'}
        dependencies = {
            (
                dependency.findtext('p:groupId', namespaces=namespace),
                dependency.findtext('p:artifactId', namespaces=namespace),
            )
            for dependency in tree.findall(
                './p:dependencyManagement/p:dependencies/p:dependency',
                namespace,
            )
        }
        self.assertTrue(
            {
                ('com.ongres.scram', 'client'),
                ('com.ongres.scram', 'common'),
                ('com.ongres.stringprep', 'saslprep'),
                ('com.ongres.stringprep', 'stringprep'),
            }
            <= dependencies
        )
        self.assertTrue(
            {
                ('com.ongres.scram', 'scram-client'),
                ('com.ongres.scram', 'scram-common'),
            }.isdisjoint(dependencies)
        )

    def test_postgresql_module_contains_scram_runtime_jars(self):
        tree = ElementTree.parse(MODULE_XML)
        namespace = {'m': 'urn:jboss:module:1.1'}
        resources = {
            element.attrib['path']
            for element in tree.findall('.//m:resource-root', namespace)
        }
        self.assertTrue(
            {
                'postgresql.jar',
                'client.jar',
                'common.jar',
                'saslprep.jar',
                'stringprep.jar',
            }
            <= resources
        )

    def test_build_maps_both_scram_artifacts_into_postgresql_module(self):
        tree = ElementTree.parse(COMMON_POM)
        namespace = {'p': 'http://maven.apache.org/POM/4.0.0'}
        mappings = {
            (
                module.findtext('p:groupId', namespaces=namespace),
                module.findtext('p:artifactId', namespaces=namespace),
                module.findtext('p:moduleName', namespaces=namespace),
            )
            for module in tree.findall('.//p:modules/p:module', namespace)
        }
        self.assertIn(
            ('com.ongres.scram', 'client', 'org.postgresql'),
            mappings,
        )
        self.assertIn(
            ('com.ongres.scram', 'common', 'org.postgresql'),
            mappings,
        )
        self.assertIn(
            ('com.ongres.stringprep', 'saslprep', 'org.postgresql'),
            mappings,
        )
        self.assertIn(
            ('com.ongres.stringprep', 'stringprep', 'org.postgresql'),
            mappings,
        )

    def test_rpm_does_not_replace_bundled_scram_jars_with_symlinks(self):
        spec = ENGINE_SPEC.read_text(encoding='utf-8')

        self.assertNotIn('Requires:\tongres-scram', spec)
        self.assertNotIn(
            'common/org/postgresql/main/client.jar '
            'ongres-scram/client.jar',
            spec,
        )
        self.assertNotIn(
            'common/org/postgresql/main/common.jar '
            'ongres-scram/common.jar',
            spec,
        )
        self.assertIn('%{engine_jboss_modules}/', spec)


class ScramRuntimeReachesEveryPostgresClientTest(unittest.TestCase):
    """Every component that opens a PostgreSQL connection must reach the SCRAM runtime.

    Bundling the ONGRES libraries in the org.postgresql JBoss module covers
    everything that runs under JBoss modules, and that was taken for the whole
    answer once. It is not: ovirt-engine-dwhd is a plain JVM with a classpath of
    its own, so turning the database over to scram-sha-256 stopped its ETL from
    logging in - silently, because the driver fails inside itself, the service
    restarts forever and the dashboard simply reads zero.

    These tests are the standing list. A new component that talks to PostgreSQL
    is added here with the way it reaches the runtime, and one that reaches it
    no way at all fails this file rather than a dashboard months later.
    """

    def setUp(self):
        self.module_xml = MODULE_XML.read_text(encoding='utf-8')
        self.constants = ENGINE_CONSTANTS.read_text(encoding='utf-8')
        self.plugin = DWH_RUNTIME_PLUGIN.read_text(encoding='utf-8')
        self.plugins_init = SYSTEM_PLUGINS_INIT.read_text(encoding='utf-8')
        self.remove_plugin = REMOVE_PLUGIN.read_text(encoding='utf-8')
        self.notifier = NOTIFIER_LAUNCHER.read_text(encoding='utf-8')
        self.audit = AUDIT_SCRIPT.read_text(encoding='utf-8')

    def test_components_under_jboss_modules_reach_the_bundled_runtime(self):
        # The engine's own deployments and ovirt-aaa-jdbc-tool load the module
        # directly; the notifier is a separate JVM but is started with the
        # engine's module path, which is what covers it.
        for jar in SCRAM_RUNTIME_JARS:
            self.assertIn(
                '<resource-root path="{jar}"/>'.format(jar=jar),
                self.module_xml,
            )
        self.assertIn("'JAVA_MODULEPATH': '%s:%s' % (", self.notifier)
        self.assertIn("self._config.get('ENGINE_JAVA_MODULEPATH')", self.notifier)

    def test_the_data_warehouse_etl_is_given_the_runtime_explicitly(self):
        # It runs outside JBoss modules, so nothing above reaches it. Its
        # launcher puts "<PKG_JAVA_LIB>/*" on the classpath, which is why
        # placing the JARs in that directory is enough.
        self.assertIn('DWH_JAVA_LIB_DIRS = (', self.constants)
        self.assertIn("'ovirt-engine-dwh', 'lib'", self.constants)
        self.assertIn("'java', 'ovirt-engine-dwh'", self.constants)
        self.assertIn("DWH_ETL_JAR = 'historyETL.jar'", self.constants)
        self.assertIn('OVIRT_ENGINE_POSTGRES_MODULE_DIR = os.path.join(', self.constants)
        for jar in SCRAM_RUNTIME_JARS:
            self.assertIn("'{jar}',".format(jar=jar), self.constants)

    def test_the_plugin_is_registered_so_it_actually_runs(self):
        # A plugin left out of createPlugins is never constructed and does
        # nothing, which looks exactly like the fix not being there.
        self.assertIn('from . import dwh_scram_runtime', self.plugins_init)
        self.assertIn('dwh_scram_runtime.Plugin(context=context)', self.plugins_init)

    def test_the_plugin_links_rather_than_copies(self):
        # A copy would go stale: an engine update carrying a corrected library
        # would leave the Data Warehouse on the old one.
        self.assertIn('os.symlink(source, target)', self.plugin)
        self.assertIn('SCRAM_RUNTIME_LINK_PREFIX', self.plugin)

    def test_the_plugin_refuses_to_continue_when_it_cannot_supply_the_runtime(self):
        # Silence here is what let this go unnoticed: the Data Warehouse fails
        # to authenticate and says so nowhere an administrator looks.
        self.assertEqual(2, self.plugin.count('raise RuntimeError('))
        self.assertIn('ovirt-engine-dwhd', self.plugin)

    def test_the_plugin_skips_a_host_without_the_data_warehouse(self):
        self.assertIn('def _dwh_java_lib_dirs(self):', self.plugin)
        self.assertIn('if not target_dirs:', self.plugin)

    def test_removal_takes_the_links_back(self):
        # They point into the engine's tree. Left behind after the engine is
        # removed they are dangling entries on another package's classpath.
        self.assertIn('def _remove_dwh_scram_runtime(self):', self.remove_plugin)
        self.assertIn('self._remove_dwh_scram_runtime()', self.remove_plugin)
        self.assertIn('DWH_JAVA_LIB_DIRS', self.remove_plugin)

    def test_the_audit_script_reports_the_gap_on_a_running_system(self):
        # Packaging can be right and the installed host still wrong - a Data
        # Warehouse installed after engine-setup last ran, for instance.
        self.assertIn('check_dwh_scram_runtime()', self.audit)
        self.assertIn('    check_dwh_scram_runtime\n', self.audit)
        self.assertIn('historyETL.jar', self.audit)
        self.assertIn('ovirt-engine-dwhd', self.audit)

    def test_the_audit_check_does_not_fire_before_scram_is_in_use(self):
        # The libraries are only needed once the database asks for SCRAM;
        # reporting their absence earlier makes every md5 host look broken.
        check = self.audit.split('check_dwh_scram_runtime() {', 1)[1]
        check = check.split('\n}\n', 1)[0]
        self.assertIn('if [ "$db_encrypt" != "scram-sha-256" ]; then', check)
        self.assertIn('log_info "Data Warehouse SCRAM runtime is absent', check)

    def test_the_hardening_document_names_the_data_warehouse(self):
        doc = SCRAM_DOC.read_text(encoding='utf-8')
        self.assertIn('ovirt-engine-dwhd', doc)
        self.assertIn('historyETL', doc)


if __name__ == '__main__':
    unittest.main()
