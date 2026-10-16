"""Public packaging and maintained-source validation regressions."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_libafl_dependency import ROOT, verify_source
from package_source import package, public_path
from prepare_dependencies import prepare


class PublicDeliveryTests(unittest.TestCase):
    def test_private_paths_rejected_even_if_tracked(self):
        for name in ("docs/workflow/notes.md", "docs/internal/plan.md", "AGENTS.md",
                     "examples/.env", "tools/client.key", "tools/license.hexlic", "tools/ida.reg",
                     "tmp/trace.json", "examples/target/program"):
            with self.subTest(name=name):
                self.assertFalse(public_path(name))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            (root / "AGENTS.md").write_text("private notes")
            subprocess.run(["git", "-C", str(root), "add", "--force", "AGENTS.md"], check=True)
            with self.assertRaisesRegex(ValueError, "public source policy"):
                package(root, root / "archive.tar.gz")

    def test_public_api_and_lockfiles_included(self):
        for name in ("docs/api.md", "README.md", "Cargo.lock", "examples/embedded/Cargo.lock",
                     "fmst-iib-api/src/context.rs", "skills/intervention-engineering/SKILL.md",
                     "assets/brand/logo.svg", "assets/brand/logo.png"):
            with self.subTest(name=name):
                self.assertTrue(public_path(name))

    def test_integrated_dependency_is_fetched_without_reapplying_patch(self):
        source = ROOT.parent / "lib/LibAFL"
        if not (source / ".git").exists():
            self.skipTest("requires prepared LibAFL Git checkout")
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "LibAFL"
            self.assertEqual(prepare(checkout, str(source))["patch_status"], "integrated")
            self.assertEqual(prepare(checkout)["status"], "passed")
            changed = checkout / "README.md"
            changed.write_text("local changes to preserve\n")
            with self.assertRaisesRegex(ValueError, "uncommitted"):
                prepare(checkout)
            self.assertEqual(changed.read_text(), "local changes to preserve\n")
            metadata_path = ROOT / "dependencies/libafl-qemu.json"
            metadata = json.loads(metadata_path.read_text())
            critical = checkout / metadata["patched_path"]
            critical.write_text(critical.read_text() + "\n// unexpected edit\n")
            with self.assertRaisesRegex(ValueError, "maintained source differs"):
                verify_source(checkout, metadata_path)


if __name__ == "__main__":
    unittest.main()
