import ast
import unittest
from pathlib import Path


CLIENT_CONTROL = (
    Path(__file__).parents[1]
    / "plugins"
    / "ovirt-engine-setup"
    / "ovirt-engine"
    / "config"
    / "client_control.py"
)


class ClientControlCompatibilityTest(unittest.TestCase):
    def test_encryption_stage_does_not_require_new_common_constant(self):
        """The plugin must load when engine-common comes from an older RPM."""
        tree = ast.parse(CLIENT_CONTROL.read_text(encoding="utf-8"))
        forbidden = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "DB_CREDENTIALS_ENCRYPTED"
            ):
                forbidden.append(node.lineno)
        self.assertEqual([], forbidden)

        assignments = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        self.assertEqual(
            "osetup.db.connection.credentials.encrypted",
            assignments["_DB_CREDENTIALS_ENCRYPTED"],
        )


if __name__ == "__main__":
    unittest.main()
