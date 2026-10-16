"""Delivery failures must be detected before Cargo/native builds can start."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import offline


class OfflineDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def delivery(self):
        root = self.root / "delivery"
        root.mkdir()
        (root / "source.rs").write_text("original\n")
        record = {"schema_version": 1, "files": offline.inventory(root),
                  "builder": {"image_id": "sha256:original"}}
        record["delivery_id"] = offline.identity(record)
        offline.write_json(root / "DELIVERY.json", record)
        offline.verify(root)
        return root

    def test_modified_source_rejected(self):
        root = self.delivery()
        (root / "source.rs").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "source.rs"):
            offline.verify(root)

    def test_missing_source_rejected(self):
        root = self.delivery()
        (root / "source.rs").unlink()
        with self.assertRaisesRegex(ValueError, "source.rs"):
            offline.verify(root)

    def test_unexpected_file_rejected(self):
        root = self.delivery()
        (root / "extra-config").write_text("unrecorded\n")
        with self.assertRaisesRegex(ValueError, "extra-config"):
            offline.verify(root)

    def test_builder_metadata_tamper_rejected(self):
        root = self.delivery()
        record = json.loads((root / "DELIVERY.json").read_text())
        record["builder"]["image_id"] = "sha256:different"
        offline.write_json(root / "DELIVERY.json", record)
        with self.assertRaisesRegex(ValueError, "identity differs"):
            offline.verify(root)

    def test_symlink_escape_rejected(self):
        root = self.delivery()
        (root / "escape").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(ValueError, "symlink escapes"):
            offline.verify(root)

    def test_archive_traversal_rejected(self):
        archive = self.root / "bad.tar"
        with tarfile.open(archive, "w") as stream:
            member = tarfile.TarInfo("../outside")
            member.size = 1
            stream.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "escapes destination"):
            offline.extract(archive, self.root / "extracted")
        self.assertFalse((self.root / "outside").exists())

    def test_export_uses_commit_and_preserves_dirty_checkout(self):
        checkout = self.root / "repo"
        subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
        (checkout / "source").write_text("committed\n")
        subprocess.run(["git", "-C", str(checkout), "add", "source"], check=True)
        subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture"], check=True)
        commit = offline.output(["git", "-C", str(checkout), "rev-parse", "HEAD"])
        (checkout / "source").write_text("user changes\n")
        (checkout / "untracked").write_text("private resource\n")
        scratch = self.root / "scratch"
        scratch.mkdir()
        archive = self.root / "source.tar.gz"
        offline.export_git("libvharness", {"commit": commit, "repository": "unused"}, checkout, archive, scratch)
        extracted = self.root / "exported"
        offline.extract(archive, extracted)
        self.assertEqual((extracted / "source").read_text(), "committed\n")
        self.assertFalse((extracted / "untracked").exists())
        self.assertEqual((checkout / "source").read_text(), "user changes\n")
        self.assertTrue((checkout / "untracked").exists())


if __name__ == "__main__":
    unittest.main()
