import pathlib
import tempfile
import unittest
import zipfile

from scripts.build_pyodide_bundle import FIXED_TIMESTAMP, build_bundle, source_files


ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestPyodideBundle(unittest.TestCase):
    def test_bundle_contains_only_compilable_authlab_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "authlab-pyodide.zip"
            count = build_bundle(ROOT, destination)
            expected = [path.relative_to(ROOT).as_posix() for path in source_files(ROOT)]
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(archive.namelist(), expected)
                self.assertEqual(count, len(expected))
                self.assertIn("authlab/__init__.py", expected)
                for info in archive.infolist():
                    self.assertEqual(info.date_time, FIXED_TIMESTAMP)
                    source = archive.read(info).decode("utf-8")
                    compile(source, info.filename, "exec")

    def test_bundle_is_byte_for_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            first = pathlib.Path(directory) / "first.zip"
            second = pathlib.Path(directory) / "second.zip"
            build_bundle(ROOT, first)
            build_bundle(ROOT, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
