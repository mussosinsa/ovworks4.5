import unittest
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).parents[3]
MODULE_XML = (
    ROOT
    / 'backend/manager/dependencies/common/src/main/modules'
    / 'org/postgresql/main/module.xml'
)
COMMON_POM = ROOT / 'backend/manager/dependencies/common/pom.xml'


class PostgresqlJdbcScramModuleTest(unittest.TestCase):
    def test_postgresql_module_contains_scram_runtime_jars(self):
        tree = ElementTree.parse(MODULE_XML)
        namespace = {'m': 'urn:jboss:module:1.1'}
        resources = {
            element.attrib['path']
            for element in tree.findall('.//m:resource-root', namespace)
        }
        self.assertTrue(
            {'postgresql.jar', 'client.jar', 'common.jar'}
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


if __name__ == '__main__':
    unittest.main()
