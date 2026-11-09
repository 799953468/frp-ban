import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile
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

    def published(self, rid, component="server"):
        source = self.work / component / rid
        source.mkdir(parents=True)
        app = release.COMPONENTS[component]
        assembly = app["assembly"]
        exe = assembly + (".exe" if rid.startswith("win-") else "")
        for name in (exe, f"{assembly}.dll", f"{assembly}.runtimeconfig.json",
                     "System.Private.CoreLib.dll", "libcoreclr.so", "dependency.dll"):
            (source / name).write_bytes(b"test payload")
        (source / "appsettings.json").write_bytes(
            (release.ROOT / "src" / app["project"] / "appsettings.json").read_bytes())
        if component == "client":
            shutil.copytree(release.ROOT / "src/FrpBan.Client/rules.d", source / "rules.d")
        (source / "appsettings.Development.json").write_text("{}")
        return source

    def all_assets(self):
        for component in release.COMPONENTS:
            for rid in release.RIDS:
                for ext in release.extensions(rid):
                    (self.work / release.asset_name("1.2.3", rid, ext, component)).write_bytes(b"asset")

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

    def test_checksums_cover_all_thirty_two_server_and_client_assets(self):
        self.all_assets()
        release.checksums("1.2.3", self.work)
        lines = (self.work / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(32, len(lines))
        digest = hashlib.sha256(b"asset").hexdigest()
        self.assertTrue(all(line.startswith(digest + "  ") for line in lines))
        release.checksums("1.2.3", self.work)  # Safe when a job is retried.

    def test_missing_or_empty_assets_block_publication(self):
        self.all_assets()
        asset = self.work / "frp-ban-client-1.2.3-osx-arm64.tar.gz"
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
        self.assertEqual(33, len(uploads))
        self.assertTrue(all(method == "PUT" and body for method, _, body in uploads))
        self.assertTrue(any(url.endswith("/assets/links/42") and method == "PUT"
                            for method, url, _ in calls))
        self.assertTrue(all("test-only-token" not in url for _, url, _ in calls))
        updates = [json.loads(body) for method, url, body in calls
                   if method == "PUT" and url.endswith("/releases/v1.2.3")]
        self.assertEqual("v1.2.3", updates[0]["name"])

    def test_client_archives_include_runtime_rules_config_and_correct_launcher(self):
        for rid in release.RIDS:
            with self.subTest(rid=rid):
                source = self.published(rid, "client")
                payload = self.work / f"payload-{rid}"
                release.prepare_payload(source, payload, rid, "client")
                release.portable_config(payload, "client")
                release.archive(payload, rid, "1.2.3", self.work, "client")
                prefix = f"frp-ban-client-1.2.3-{rid}/"
                extension = "zip" if rid.startswith("win-") else "tar.gz"
                path = self.work / release.asset_name("1.2.3", rid, extension, "client")
                if extension == "zip":
                    with zipfile.ZipFile(path) as bundle:
                        files = {name[len(prefix):]: bundle.read(name) for name in bundle.namelist()}
                    self.assertIn(b'"%~dp0FrpBan.Client.exe" %*', files["frp-ban-client.cmd"])
                    self.assertIn("FrpBan.Client.exe", files)
                else:
                    with tarfile.open(path) as bundle:
                        files = {item.name[len(prefix):]: bundle.extractfile(item).read()
                                 for item in bundle.getmembers() if item.isfile()}
                        for name in ("FrpBan.Client", "frp-ban-client"):
                            self.assertTrue(bundle.getmember(prefix + name).mode & 0o111)
                    self.assertIn(b'exec ./FrpBan.Client "$@"', files["frp-ban-client"])
                for name in ("FrpBan.Client.dll", "FrpBan.Client.runtimeconfig.json",
                             "System.Private.CoreLib.dll", "dependency.dll", "LICENSE", "README.md",
                             "rules.d/01-ssh-bruteforce.yaml", "rules.d/02-ssh-invalid-user.yaml"):
                    self.assertIn(name, files)
                self.assertNotIn("frps.toml.example", files)
                self.assertNotIn("appsettings.Development.json", files)
                settings = json.loads(files["appsettings.json"])["ClientSettings"]
                self.assertEqual("rules.d", settings["RulesPath"])
                self.assertEqual("logs/frp-ban-client-.log", settings["AppLogPath"])
                self.assertTrue(settings["Tls"]["ValidateServerCertificate"])

    def test_client_missing_rules_or_runtime_block_packaging(self):
        for filename in ("rules.d/01-ssh-bruteforce.yaml", "System.Private.CoreLib.dll",
                         "FrpBan.Client.dll", "FrpBan.Client.runtimeconfig.json", "FrpBan.Client"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "published"
                original = self.published("linux-x64", "client")
                shutil.move(original, source)
                (source / filename).unlink()
                with self.assertRaisesRegex(ValueError, "Incomplete self-contained"):
                    release.prepare_payload(source, Path(directory) / "payload", "linux-x64", "client")

    def test_native_client_packages_keep_rules_and_config_separate_from_server(self):
        source = self.published("linux-arm64", "client")
        payload = self.work / "payload"
        release.prepare_payload(source, payload, "linux-arm64", "client")
        for packager in ("deb", "rpm", "archlinux", "apk"):
            with self.subTest(packager=packager):
                config = release.linux_config(payload, "linux-arm64", "1.2.3", packager, "client")
                self.assertEqual("frp-ban-client", config["name"])
                self.assertEqual("arm64", config["arch"])
                files = {item["dst"]: item for item in config["contents"]}
                self.assertIn("/opt/frp-ban-client/FrpBan.Client", files)
                self.assertIn("/opt/frp-ban-client/System.Private.CoreLib.dll", files)
                self.assertNotIn("/opt/frp-ban-client/appsettings.json", files)
                for relative in ("appsettings.json", "rules.d/01-ssh-bruteforce.yaml",
                                 "rules.d/02-ssh-invalid-user.yaml"):
                    item = files[f"/etc/frp-ban-client/{relative}"]
                    self.assertEqual("config|noreplace", item["type"])
                    self.assertEqual({"mode": 0o640, "group": "frp-ban-client"}, item["file_info"])
                self.assertIn("/etc/init.d/frp-ban-client" if packager == "apk" else
                              "/usr/lib/systemd/system/frp-ban-client.service", files)
                self.assertIn("/usr/bin/frp-ban-client", files)
                self.assertTrue(all("/frp-ban/" not in path for path in files))
                for item in files.values():
                    self.assertTrue(Path(item["src"]).is_file(), item)
                for script in config["scripts"].values():
                    self.assertTrue(Path(script).is_file())
                if packager in ("archlinux", "apk"):
                    for script in config[packager]["scripts"].values():
                        self.assertTrue(Path(script).is_file())
                        self.assertIn("/client/", script)

    def test_build_selects_component_project_and_isolates_publish_directories(self):
        for component, app in release.COMPONENTS.items():
            with self.subTest(component=component), \
                    patch.object(release.sys, "argv", ["release.py", "build", "linux-x64", "v1.2.3",
                                                      "--component", component]), \
                    patch.object(release, "ROOT", self.work), \
                    patch.object(release, "run") as run, \
                    patch.object(release, "package") as package:
                release.main()
                published = self.work / "publish/binaries" / component / "linux-x64"
                command = run.call_args.args
                self.assertEqual(self.work / "src" / app["project"] / f"{app['project']}.csproj", command[2])
                self.assertIn("--self-contained", command)
                self.assertIn("-p:Version=1.2.3", command)
                self.assertEqual(published, command[-1])
                package.assert_called_once_with("linux-x64", "1.2.3", published,
                                                (self.work / "dist").resolve(), component)

    def test_full_package_matrix_includes_arch_linux_for_both_components(self):
        sources = {(component, rid): self.published(rid, component)
                   for component in release.COMPONENTS for rid in release.RIDS}
        root = self.work / "root"
        for name in ("LICENSE", "frps.toml.example"):
            release.write(root / name, (release.ROOT / name).read_text())
        shutil.copytree(release.ROOT / "packaging", root / "packaging")
        for app in release.COMPONENTS.values():
            shutil.copytree(release.ROOT / "src" / app["project"], root / "src" / app["project"],
                            ignore=shutil.ignore_patterns("bin", "obj"))
        destination = self.work / "dist"
        configs = []

        def nfpm(*args):
            self.assertEqual(("nfpm", "package", "--config"), args[:3])
            config = json.loads(Path(args[3]).read_text())
            settings = next(item for item in config["contents"] if item["dst"].endswith("/appsettings.json"))
            settings = json.loads(Path(settings["src"]).read_text())
            if config["name"] == "frp-ban-client":
                self.assertEqual("/var/log/frp-ban-client/frp-ban-client-.log",
                                 settings["ClientSettings"]["AppLogPath"])
                self.assertEqual("rules.d", settings["ClientSettings"]["RulesPath"])
            configs.append((args[5], config))
            Path(args[-1]).write_bytes(b"native package")

        with patch.object(release, "ROOT", root), patch.object(release, "run", nfpm):
            for (component, rid), source in sources.items():
                release.package(rid, "1.2.3", source, destination, component)
            release.checksums("1.2.3", destination)
        self.assertEqual(33, len(list(destination.iterdir())))
        self.assertEqual(16, len(configs))
        self.assertEqual(4, sum(packager == "archlinux" for packager, _ in configs))
        for component in release.COMPONENTS:
            for rid in ("linux-x64", "linux-arm64"):
                self.assertTrue((destination / release.asset_name("1.2.3", rid, "pkg.tar.zst", component)).is_file())


if __name__ == "__main__":
    unittest.main()
