import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "publish-gitlab-release.sh"
RIDS = (
    "win-x64", "win-arm64", "osx-x64", "osx-arm64",
    "linux-x64", "linux-arm64", "linux-musl-x64", "linux-musl-arm64",
)


class ReleaseApi(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def respond(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.server.existing_release is None:
            self.respond(404, {"message": "Release not found"})
        else:
            self.respond(200, self.server.existing_release)

    def receive(self, method):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((method, self.path, body, self.headers.get("JOB-TOKEN")))
        if "/packages/generic/" in self.path and self.server.reject_upload:
            self.respond(400, {"message": "Upload rejected"})
        else:
            self.respond(201 if method == "POST" else 200, {"message": "ok"})

    def do_PUT(self):
        self.receive("PUT")

    def do_POST(self):
        self.receive("POST")


class GitLabReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "dist").mkdir()
        (self.root / "packaging").mkdir()
        self.notes = "# v1.2.0\n\nEnglish notes with a quote: \"release\".\n"
        (self.root / "packaging/RELEASE_NOTES.md").write_text(self.notes)
        self.archives = {}
        for package in ("frp-ban", "frp-ban-client"):
            for rid in RIDS:
                extension = "zip" if rid.startswith("win-") else "tar.gz"
                name = f"{package}-1.2.0-{rid}.{extension}"
                self.archives[name] = f"test archive: {name}\n".encode()
                (self.root / "dist" / name).write_bytes(self.archives[name])

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ReleaseApi)
        self.server.requests = []
        self.server.existing_release = None
        self.server.reject_upload = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def publish(self):
        environment = dict(os.environ)
        environment.update({
            "CI_API_V4_URL": f"http://127.0.0.1:{self.server.server_port}/api/v4",
            "CI_PROJECT_ID": "8",
            "CI_JOB_TOKEN": "test-job-token",
            "CI_COMMIT_TAG": "v1.2.0",
            "NO_PROXY": "127.0.0.1",
            "no_proxy": "127.0.0.1",
        })
        return subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.root, env=environment,
            capture_output=True, text=True, timeout=30,
        )

    def test_publishes_complete_packages_checksums_and_release_notes(self):
        result = self.publish()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        uploads = [request for request in self.server.requests if "/packages/generic/" in request[1]]
        self.assertEqual(17, len(uploads))
        for method, path, body, token in uploads:
            self.assertEqual("PUT", method)
            self.assertEqual("test-job-token", token)
            name = path.rsplit("/", 1)[1]
            if name != "SHA256SUMS":
                self.assertEqual(self.archives[name], body)
        manifest = (self.root / "dist/SHA256SUMS").read_text().splitlines()
        self.assertEqual(16, len(manifest))
        for line in manifest:
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256(self.archives[name]).hexdigest(), digest)
        method, path, body, token = self.server.requests[-1]
        self.assertEqual(("POST", "/api/v4/projects/8/releases"), (method, path))
        release = json.loads(body)
        self.assertEqual("v1.2.0", release["name"])
        self.assertEqual("v1.2.0", release["tag_name"])
        self.assertEqual(self.notes, release["description"])
        self.assertEqual(set(self.archives) | {"SHA256SUMS"}, {link["name"] for link in release["assets"]["links"]})
        self.assertNotIn("test-job-token", result.stdout + result.stderr)

    def test_missing_archive_stops_before_upload_or_release(self):
        (self.root / "dist" / next(iter(self.archives))).unlink()
        result = self.publish()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Missing or invalid release archive", result.stderr)
        self.assertEqual([], self.server.requests)

    def test_failed_upload_does_not_publish_release(self):
        self.server.reject_upload = True
        result = self.publish()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(1, len(self.server.requests))
        self.assertIn("/packages/generic/", self.server.requests[0][1])

    def test_retry_updates_existing_link_and_adds_missing_links(self):
        first = next(iter(self.archives))
        self.server.existing_release = {"assets": {"links": [{"id": 42, "name": first}]}}
        result = self.publish()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        links = [request for request in self.server.requests if "/assets/links" in request[1]]
        self.assertEqual(17, len(links))
        self.assertEqual("PUT", links[0][0])
        self.assertTrue(links[0][1].endswith("/42"))
        self.assertEqual(16, sum(request[0] == "POST" for request in links))
        self.assertFalse(any(method == "POST" and path.endswith("/releases") for method, path, _, _ in self.server.requests))


if __name__ == "__main__":
    unittest.main()
