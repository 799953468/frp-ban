import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import zipfile


spec = importlib.util.spec_from_file_location("release", Path(__file__).parents[1] / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)

    def published(self, rid):
        source = self.work / rid
        source.mkdir()
        exe = "FrpBan.exe" if rid.startswith("win-") else "FrpBan"
        for name in (exe, "FrpBan.dll", "FrpBan.runtimeconfig.json",
                     "System.Private.CoreLib.dll", "libcoreclr.so", "dependency.dll"):
            (source / name).write_bytes(b"test payload")
        (source / "appsettings.json").write_bytes(
            (release.ROOT / "src/FrpBan/appsettings.json").read_bytes())
        (source / "appsettings.Development.json").write_text("{}")
        return source

    def all_assets(self):
        for rid in release.RIDS:
            for ext in release.extensions(rid):
                (self.work / release.asset_name("1.2.3", rid, ext)).write_bytes(b"asset")

    def test_only_stable_version_tags_are_accepted(self):
        self.assertEqual("1.2.3", release.version_from_tag("v1.2.3"))
        for tag in ("main", "1.2.3", "v1.2", "v1.2.3-rc.1", "v01.2.3", "v1.2.3/evil"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.version_from_tag(tag)

    def test_payload_keeps_runtime_and_dependencies_and_removes_dev_settings(self):
        source = self.published("linux-arm64")
        target = self.work / "payload"
        release.prepare_payload(source, target, "linux-arm64")
        for name in ("FrpBan", "System.Private.CoreLib.dll", "libcoreclr.so",
                     "dependency.dll", "LICENSE", "frps.toml.example", "README.md"):
            self.assertTrue((target / name).is_file(), name)
        self.assertFalse((target / "appsettings.Development.json").exists())
        self.assertTrue((target / "FrpBan").stat().st_mode & 0o111)

    def test_framework_dependent_output_is_rejected(self):
        source = self.published("linux-x64")
        (source / "System.Private.CoreLib.dll").unlink()
        with self.assertRaisesRegex(ValueError, "Incomplete self-contained"):
            release.prepare_payload(source, self.work / "payload", "linux-x64")

    def test_windows_zip_contains_config_runtime_and_launcher(self):
        source = self.published("win-arm64")
        payload = self.work / "payload"
        release.prepare_payload(source, payload, "win-arm64")
        release.portable_config(payload)
        release.archive(payload, "win-arm64", "1.2.3", self.work)
        archive = self.work / "frp-ban-1.2.3-win-arm64.zip"
        with zipfile.ZipFile(archive) as bundle:
            prefix = "frp-ban-1.2.3-win-arm64/"
            self.assertIn(prefix + "FrpBan.exe", bundle.namelist())
            self.assertIn(prefix + "System.Private.CoreLib.dll", bundle.namelist())
            self.assertIn(prefix + "frp-ban.cmd", bundle.namelist())
            settings = json.loads(bundle.read(prefix + "appsettings.json"))["PluginSettings"]
            self.assertEqual("data/bans.json", settings["BanFilePath"])
            self.assertEqual("certs/server.pfx", settings["Tls"]["CertificatePath"])

    def test_native_linux_packages_include_all_files_and_preserve_config(self):
        source = self.published("linux-x64")
        payload = self.work / "payload"
        release.prepare_payload(source, payload, "linux-x64")
        for packager in ("deb", "rpm", "archlinux", "apk"):
            with self.subTest(packager=packager):
                config = release.linux_config(payload, "linux-arm64", "1.2.3", packager)
                self.assertEqual("arm64", config["arch"])
                files = {item["dst"]: item for item in config["contents"]}
                self.assertIn("/opt/frp-ban/libcoreclr.so", files)
                self.assertIn("/opt/frp-ban/System.Private.CoreLib.dll", files)
                self.assertNotIn("/opt/frp-ban/appsettings.json", files)
                settings = files["/etc/frp-ban/appsettings.json"]
                self.assertEqual("config|noreplace", settings["type"])
                self.assertEqual(0o640, settings["file_info"]["mode"])
                self.assertIn("/etc/init.d/frp-ban" if packager == "apk" else
                              "/usr/lib/systemd/system/frp-ban.service", files)
                self.assertTrue(config["depends"])
                for script in config["scripts"].values():
                    self.assertTrue(Path(script).is_file())

    def test_linux_package_selection_respects_glibc_and_musl(self):
        self.assertEqual(("tar.gz", "apk"), release.extensions("linux-musl-arm64"))
        self.assertEqual(("tar.gz", "deb", "rpm", "pkg.tar.zst"),
                         release.extensions("linux-arm64"))

    def test_windows_and_macos_only_produce_archives_without_install_tools(self):
        sources = {rid: self.published(rid) for rid in ("win-x64", "osx-arm64")}
        for name in ("LICENSE", "frps.toml.example", "packaging/RELEASE_NOTES.md"):
            release.write(self.work / name, (release.ROOT / name).read_text())
        destination = self.work / "dist"
        with patch.object(release, "ROOT", self.work), patch.object(release, "run") as run:
            for rid, source in sources.items():
                release.package(rid, "1.2.3", source, destination)
            run.assert_not_called()
        self.assertEqual({"frp-ban-1.2.3-win-x64.zip", "frp-ban-1.2.3-osx-arm64.tar.gz"},
                         {path.name for path in destination.iterdir()})

    def test_checksums_cover_all_sixteen_assets(self):
        self.all_assets()
        release.checksums("1.2.3", self.work)
        lines = (self.work / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(16, len(lines))
        digest = hashlib.sha256(b"asset").hexdigest()
        self.assertTrue(all(line.startswith(digest + "  ") for line in lines))
        release.checksums("1.2.3", self.work)  # Safe when a job is retried.

    def test_missing_or_empty_assets_block_publication(self):
        self.all_assets()
        asset = self.work / "frp-ban-1.2.3-osx-arm64.tar.gz"
        asset.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "Empty or invalid"):
            release.checksums("1.2.3", self.work)
        asset.unlink()
        with self.assertRaisesRegex(ValueError, "Missing:"):
            release.checksums("1.2.3", self.work)

    def test_gitlab_uploads_persistent_assets_and_updates_existing_release(self):
        self.all_assets()
        release.checksums("1.2.3", self.work)
        calls = []
        existing = {"assets": {"links": [{"name": "SHA256SUMS", "id": 42}]}}

        class Response:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self):
                return json.dumps(self.body).encode()

        def transport(request, **kwargs):
            body = request.data
            if hasattr(body, "read"):
                body = body.read()
            calls.append((request.method, request.full_url, body))
            return Response(existing if request.method == "GET" else {})

        env = {"CI_API_V4_URL": "https://gitlab.example/api/v4",
               "CI_PROJECT_ID": "123", "CI_JOB_TOKEN": "test-only-token"}
        with patch.dict(release.os.environ, env), patch.object(release, "urlopen", transport):
            release.gitlab_release("v1.2.3", "1.2.3", self.work)
        uploads = [call for call in calls if "/packages/generic/" in call[1]]
        self.assertEqual(17, len(uploads))
        self.assertTrue(all(method == "PUT" and body for method, _, body in uploads))
        self.assertTrue(any(url.endswith("/assets/links/42") and method == "PUT"
                            for method, url, _ in calls))
        self.assertTrue(all("test-only-token" not in url for _, url, _ in calls))


if __name__ == "__main__":
    unittest.main()
