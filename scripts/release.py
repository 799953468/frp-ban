#!/usr/bin/env python3
"""Shared, dependency-free release orchestration for GitHub and GitLab."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile


ROOT = Path(__file__).resolve().parents[1]
RIDS = (
    "win-x64", "win-arm64", "osx-x64", "osx-arm64",
    "linux-x64", "linux-arm64", "linux-musl-x64", "linux-musl-arm64",
)
DEPENDENCIES = {
    "deb": ["libc6", "libgcc-s1", "libstdc++6", "zlib1g", "libicu-dev",
            "libssl3 | libssl3t64", "ca-certificates"],
    "rpm": ["glibc", "libgcc", "libstdc++", "zlib", "libicu", "openssl-libs",
            "ca-certificates", "shadow-utils"],
    "archlinux": ["glibc", "gcc-libs", "zlib", "icu", "openssl", "ca-certificates", "shadow"],
    "apk": ["musl", "libgcc", "libstdc++", "zlib", "icu-libs", "libssl3",
            "libcrypto3", "ca-certificates"],
}


def version_from_tag(tag):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("Release tag must be vMAJOR.MINOR.PATCH (for example v1.2.3)")
    return tag[1:]


def extensions(rid):
    if rid.startswith("win-"):
        return ("zip",)
    if rid.startswith("osx-"):
        return ("tar.gz",)
    if rid.startswith("linux-musl-"):
        return ("tar.gz", "apk")
    return ("tar.gz", "deb", "rpm", "pkg.tar.zst")


def asset_name(version, rid, extension):
    return f"frp-ban-{version}-{rid}.{extension}"


def run(*args):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def write_json(path, value):
    write(path, json.dumps(value, indent=2) + "\n")


def prepare_payload(published, target, rid):
    """Keep the entire self-contained publish output, including native libraries."""
    executable = "FrpBan.exe" if rid.startswith("win-") else "FrpBan"
    for required in (executable, "FrpBan.dll", "FrpBan.runtimeconfig.json",
                     "System.Private.CoreLib.dll", "appsettings.json"):
        if not (published / required).is_file():
            raise ValueError(f"Incomplete self-contained publish output: {published / required}")
    shutil.copytree(published, target)
    # Development settings should never change an installed server's behavior.
    for path in target.glob("appsettings.*.json"):
        path.unlink()
    for name in ("LICENSE", "frps.toml.example"):
        shutil.copy2(ROOT / name, target / name)
    shutil.copy2(ROOT / "packaging/RELEASE_NOTES.md", target / "README.md")
    if not rid.startswith("win-"):
        (target / executable).chmod(0o755)


def portable_config(payload):
    config = json.loads((payload / "appsettings.json").read_text())
    settings = config["PluginSettings"]
    settings["BanFilePath"] = "data/bans.json"
    settings["AppLogPath"] = "logs/frp-ban-.log"
    settings["Tls"]["CertificatePath"] = "certs/server.pfx"
    write_json(payload / "appsettings.json", config)


def archive(payload, rid, version, destination):
    name = asset_name(version, rid, "zip" if rid.startswith("win-") else "tar.gz")
    prefix = name.removesuffix(".zip").removesuffix(".tar.gz")
    if rid.startswith("win-"):
        write(payload / "frp-ban.cmd",
              '@echo off\r\ncd /d "%~dp0"\r\n"%~dp0FrpBan.exe" %*\r\n')
        with zipfile.ZipFile(destination / name, "w", zipfile.ZIP_DEFLATED) as output:
            for path in sorted(payload.rglob("*")):
                if path.is_file():
                    output.write(path, f"{prefix}/{path.relative_to(payload).as_posix()}")
    else:
        write(payload / "frp-ban", '#!/bin/sh\nset -eu\ncd "$(dirname "$0")"\nexec ./FrpBan "$@"\n', 0o755)
        with tarfile.open(destination / name, "w:gz") as output:
            output.add(payload, arcname=prefix)


def linux_config(payload, rid, version, packager):
    contents = []
    for path in sorted(payload.rglob("*")):
        if path.is_file() and path.name != "appsettings.json":
            contents.append({"src": str(path),
                             "dst": f"/opt/frp-ban/{path.relative_to(payload).as_posix()}"})
    contents.extend([
        {"src": str(payload / "appsettings.json"), "dst": "/etc/frp-ban/appsettings.json",
         "type": "config|noreplace", "file_info": {"mode": 0o640, "group": "frp-ban"}},
        {"src": str(ROOT / "packaging/linux/frp-ban"), "dst": "/usr/bin/frp-ban",
         "file_info": {"mode": 0o755}},
    ])
    if packager == "apk":
        contents.append({"src": str(ROOT / "packaging/linux/frp-ban.openrc"),
                         "dst": "/etc/init.d/frp-ban", "file_info": {"mode": 0o755}})
    else:
        contents.append({"src": str(ROOT / "packaging/linux/frp-ban.service"),
                         "dst": "/usr/lib/systemd/system/frp-ban.service"})
    config = {
        "name": "frp-ban", "arch": "arm64" if rid.endswith("arm64") else "amd64",
        "platform": "linux", "version": version, "release": "1",
        "maintainer": "FRP Ban Maintainers <799953468@users.noreply.github.com>",
        "description": "TLS-encrypted IP banning server for FRP",
        "homepage": "https://github.com/799953468/frp-ban", "license": "MIT",
        "depends": DEPENDENCIES[packager], "contents": contents,
        "scripts": {name: str(ROOT / f"packaging/linux/{name}.sh") for name in
                    ("preinstall", "postinstall", "preremove", "postremove")},
    }
    if packager == "deb":
        config["depends"] = [*config["depends"], "passwd"]
    if packager == "archlinux":
        config["archlinux"] = {"scripts": {
            "preupgrade": str(ROOT / "packaging/linux/preinstall.sh"),
            "postupgrade": str(ROOT / "packaging/linux/postinstall.sh"),
        }}
    if packager == "apk":
        config["apk"] = {"scripts": {
            "preupgrade": str(ROOT / "packaging/linux/preinstall.sh"),
            "postupgrade": str(ROOT / "packaging/linux/postinstall.sh"),
        }}
    return config


def linux_packages(payload, rid, version, work, destination):
    # Restore system paths after producing the portable archive.
    shutil.copy2(ROOT / "src/FrpBan/appsettings.json", payload / "appsettings.json")
    (payload / "frp-ban").unlink()
    formats = ("apk",) if "musl" in rid else ("deb", "rpm", "archlinux")
    for packager in formats:
        config_path = work / f"nfpm-{packager}.json"
        write_json(config_path, linux_config(payload, rid, version, packager))
        extension = "pkg.tar.zst" if packager == "archlinux" else packager
        run("nfpm", "package", "--config", config_path, "--packager", packager,
            "--target", destination / asset_name(version, rid, extension))


def package(rid, version, published, destination):
    work = ROOT / "publish/packages" / rid
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    destination.mkdir(parents=True, exist_ok=True)
    payload = work / "payload"
    prepare_payload(published, payload, rid)
    portable_config(payload)
    archive(payload, rid, version, destination)
    if rid.startswith("linux-"):
        linux_packages(payload, rid, version, work, destination)


def checksums(version, destination):
    expected = {asset_name(version, rid, ext) for rid in RIDS for ext in extensions(rid)}
    actual = {path.name for path in destination.iterdir() if path.name != "SHA256SUMS"}
    if actual != expected:
        raise ValueError(f"Asset set mismatch. Missing: {sorted(expected - actual)}; "
                         f"unexpected: {sorted(actual - expected)}")
    lines = []
    for name in sorted(expected):
        path = destination / name
        if not path.is_file() or not path.stat().st_size:
            raise ValueError(f"Empty or invalid asset: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {name}\n")
    write(destination / "SHA256SUMS", "".join(lines))
    print(f"Verified {len(expected)} release assets; wrote SHA256SUMS", flush=True)


def gitlab_release(tag, version, destination):
    """Persist assets in the Generic Package Registry before linking a release."""
    api = os.environ["CI_API_V4_URL"].rstrip("/")
    project = quote(os.environ["CI_PROJECT_ID"], safe="")
    token = os.environ["CI_JOB_TOKEN"]
    base = f"{api}/projects/{project}"

    def request(method, url, data=None, length=None):
        headers = {"JOB-TOKEN": token}
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            headers["Content-Type"] = "application/octet-stream"
            headers["Content-Length"] = str(length)
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=300) as response:
            body = response.read()
            return json.loads(body) if body else None

    release_url = f"{base}/releases/{quote(tag, safe='')}"
    try:
        existing = request("GET", release_url)
    except HTTPError as error:
        if error.code != 404:
            raise
        existing = None
    links = []
    for path in sorted(destination.iterdir()):
        url = f"{base}/packages/generic/frp-ban/{version}/{quote(path.name, safe='')}"
        with path.open("rb") as source:
            request("PUT", url, source, path.stat().st_size)
        links.append({"name": path.name, "url": url,
                      "direct_asset_path": f"/{path.name}", "link_type": "package"})
        print(f"Uploaded {path.name}", flush=True)
    description = (ROOT / "packaging/RELEASE_NOTES.md").read_text()
    body = {"name": f"FRP Ban {tag}", "description": description}
    if existing is None:
        request("POST", f"{base}/releases", {**body, "tag_name": tag, "assets": {"links": links}})
    else:
        request("PUT", release_url, body)
        old_links = {link["name"]: link["id"] for link in existing["assets"]["links"]}
        for link in links:
            url = f"{release_url}/assets/links"
            if link["name"] in old_links:
                request("PUT", f"{url}/{old_links[link['name']]}", link)
            else:
                request("POST", url, link)
    print(f"Published GitLab release {tag}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "build", "package", "checksums", "gitlab"):
        child = commands.add_parser(command)
        if command in ("build", "package"):
            child.add_argument("rid", choices=RIDS)
        child.add_argument("tag")
        child.add_argument("--output", type=Path, default=ROOT / "dist")
        if command == "package":
            child.add_argument("--publish-dir", type=Path, required=True)
    args = parser.parse_args()
    version = version_from_tag(args.tag)
    destination = args.output.resolve()
    if args.command == "validate":
        print(version)
    elif args.command in ("build", "package"):
        if args.command == "build":
            published = ROOT / "publish/binaries" / args.rid
            if published.exists():
                shutil.rmtree(published)
            run("dotnet", "publish", ROOT / "src/FrpBan/FrpBan.csproj", "-c", "Release",
                "-r", args.rid, "--self-contained", "true", "-p:PublishSingleFile=false",
                "-p:PublishTrimmed=false", f"-p:Version={version}", "-o", published)
        else:
            published = args.publish_dir.resolve()
        package(args.rid, version, published, destination)
    elif args.command == "checksums":
        checksums(version, destination)
    else:
        checksums(version, destination)
        gitlab_release(args.tag, version, destination)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
