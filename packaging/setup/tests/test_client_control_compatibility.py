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

    def test_encryptor_directory_is_traversable_by_engine_service(self):
        source = CLIENT_CONTROL.read_text(encoding="utf-8")
        tree = ast.parse(source)
        method = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "_replace_encryptor_config"
        )
        method_source = ast.get_source_segment(source, method)
        self.assertIn("os.chmod(config_dir, 0o750)", method_source)
        self.assertIn("os.chmod(temporary_path, 0o640)", method_source)
        self.assertIn(
            "user=self.environment[oengcommcons.SystemEnv.USER_ROOT]",
            method_source,
        )
        self.assertIn(
            "group=self.environment[osetupcons.SystemEnv.GROUP_ENGINE]",
            method_source,
        )


if __name__ == "__main__":
    unittest.main()
