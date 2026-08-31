import unittest
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).parents[3]
WEB_XML = (
    ROOT
    / 'frontend/webadmin/modules/webadmin/src/main/webapp/WEB-INF/web.xml'
)


class WebAdminCachePolicyTest(unittest.TestCase):
    def test_gwt_bootstrap_resources_are_never_stored(self):
        tree = ElementTree.parse(WEB_XML)
        namespace = {'j': 'http://java.sun.com/xml/ns/javaee'}
        params = {
            element.findtext('j:param-name', namespaces=namespace):
            element.findtext('j:param-value', namespaces=namespace)
            for element in tree.findall(
                './/j:filter[j:filter-name="CachingFilter"]/j:init-param',
                namespace,
            )
        }

        self.assertIn(r'.*WebAdmin\.html', params['no-store'])
        self.assertIn(r'.*\.nocache\..*', params['no-store'])
        self.assertNotIn('WebAdmin', params['no-cache'])
        self.assertNotIn('nocache', params['no-cache'])
        self.assertIn(r'.*\.cache\..*', params['cache'])


if __name__ == '__main__':
    unittest.main()
