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
            {'postgresql.jar', 'client.jar', 'common.jar', 'saslprep.jar'}
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


if __name__ == '__main__':
    unittest.main()
