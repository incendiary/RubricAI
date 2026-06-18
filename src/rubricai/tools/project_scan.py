"""project_scan MCP tool — scan a project directory and return a BOM + environment hints."""

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _validate_path(path_str: str) -> Path:
    """Resolve and validate scan target. Rejects '..' traversal attempts."""
    raw = Path(path_str)
    if ".." in raw.parts:
        raise ValueError(
            f"Path traversal not allowed: '..' is not permitted in the path ({path_str!r})."
        )
    p = raw.expanduser().resolve()
    if not p.exists():
        raise ValueError(f"Path does not exist: {p}")
    if not p.is_dir():
        raise ValueError(f"Path is not a directory: {p}")
    return p


# --- Individual parsers, each returns list[dict] of BOM entries ---


def _parse_requirements_txt(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for req_file in sorted(root.glob("requirements*.txt")):
        for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip extras/env markers: package[extra]>=version ; python_version>="3.8"
            line = re.sub(r"\s*;.*$", "", line)
            m = re.match(r"^([A-Za-z0-9][\w.\-]*)", line)
            if not m:
                continue
            name = m.group(1)
            ver_m = re.search(r"[=~<>!]+\s*([^\s,]+)", line[len(name) :])
            version = ver_m.group(1) if ver_m else "unknown"
            entries.append({"name": name, "version": version, "type": "pypi"})
    return entries


def _parse_pyproject_toml(root: Path) -> list[dict[str, Any]]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return []
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return []
    deps = data.get("project", {}).get("dependencies", [])
    entries = []
    for dep in deps:
        m = re.match(r"^([A-Za-z0-9][\w.\-]*)", dep)
        if not m:
            continue
        name = m.group(1)
        ver_m = re.search(r"[=~<>!]+\s*([^\s,\[]+)", dep[len(name) :])
        version = ver_m.group(1) if ver_m else "unknown"
        entries.append({"name": name, "version": version, "type": "pypi"})
    return entries


def _parse_package_json(root: Path) -> list[dict[str, Any]]:
    pkg = root / "package.json"
    if not pkg.exists():
        return []
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except Exception:
        return []
    entries = []
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            # version strings like "^1.2.3", "~2.0.0", ">=3.0.0 <4.0.0"
            clean_ver = re.sub(r"^[^0-9]*", "", str(version)) or str(version)
            entries.append({"name": name, "version": clean_ver, "type": "npm"})
    return entries


def _parse_pom_xml(root: Path) -> list[dict[str, Any]]:
    pom = root / "pom.xml"
    if not pom.exists():
        return []
    try:
        tree = ET.parse(pom)
    except Exception:
        return []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    entries = []
    for dep in tree.findall(".//m:dependency", ns) or tree.findall(".//dependency"):
        g = dep.findtext("m:groupId", namespaces=ns) or dep.findtext("groupId") or ""
        a = (
            dep.findtext("m:artifactId", namespaces=ns)
            or dep.findtext("artifactId")
            or ""
        )
        v = (
            dep.findtext("m:version", namespaces=ns)
            or dep.findtext("version")
            or "unknown"
        )
        if g and a:
            entries.append({"name": f"{g}:{a}", "version": v.strip(), "type": "maven"})
    return entries


def _parse_go_mod(root: Path) -> list[dict[str, Any]]:
    gomod = root / "go.mod"
    if not gomod.exists():
        return []
    entries = []
    in_require = False
    for line in gomod.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        # Single-line: require github.com/foo/bar v1.2.3
        m = re.match(r"^require\s+(\S+)\s+(\S+)", line)
        if not m and in_require:
            m = re.match(r"^(\S+)\s+(v[^\s/]+)", line)
        if m:
            entries.append({"name": m.group(1), "version": m.group(2), "type": "go"})
    return entries


def _parse_gemfile_lock(root: Path) -> list[dict[str, Any]]:
    gemfile = root / "Gemfile.lock"
    if not gemfile.exists():
        return []
    entries = []
    in_specs = False
    for line in gemfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and stripped == "":
            in_specs = False
            continue
        if in_specs:
            # "    gem_name (version)"
            m = re.match(r"^\s{4}([A-Za-z0-9][\w.\-]*)\s+\(([^)]+)\)", line)
            if m:
                entries.append(
                    {"name": m.group(1), "version": m.group(2), "type": "ruby"}
                )
    return entries


def _parse_terraform(root: Path) -> list[dict[str, Any]]:
    tf_files = list(root.glob("*.tf")) + list(root.glob("**/*.tf"))
    if not tf_files:
        return []
    entries = []
    seen: set[str] = set()

    provider_re = re.compile(
        r'source\s*=\s*"([^"]+)".*?(?:version\s*=\s*"([^"]+)")?', re.DOTALL
    )
    module_re = re.compile(
        r'module\s+"[^"]+"\s*\{[^}]*source\s*=\s*"([^"]+)"[^}]*(?:version\s*=\s*"([^"]+)")?',
        re.DOTALL,
    )

    for tf in tf_files:
        text = tf.read_text(encoding="utf-8", errors="replace")
        # Required providers block
        req_block = re.search(r"required_providers\s*\{([^}]+)\}", text, re.DOTALL)
        if req_block:
            for m in provider_re.finditer(req_block.group(1)):
                source = m.group(1)
                version = m.group(2) or "unknown"
                key = f"provider:{source}"
                if key not in seen:
                    seen.add(key)
                    entries.append(
                        {
                            "name": source,
                            "version": version,
                            "type": "terraform_provider",
                        }
                    )
        # Module sources
        for m in module_re.finditer(text):
            source = m.group(1)
            version = m.group(2) or "unknown"
            key = f"module:{source}"
            if key not in seen:
                seen.add(key)
                entries.append(
                    {"name": source, "version": version, "type": "terraform_module"}
                )
    return entries


def _parse_dockerfile(root: Path) -> list[dict[str, Any]]:
    dockerfile = root / "Dockerfile"
    if not dockerfile.exists():
        return []
    entries = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^FROM\s+(\S+)", line.strip(), re.IGNORECASE)
        if m and m.group(1).lower() != "scratch":
            image = m.group(1)
            # Separate name:tag
            if ":" in image:
                name, version = image.rsplit(":", 1)
            else:
                name, version = image, "latest"
            entries.append({"name": name, "version": version, "type": "docker_image"})
    return entries


def _parse_docker_compose(root: Path) -> list[dict[str, Any]]:
    for candidate in ("docker-compose.yml", "docker-compose.yaml", "compose.yml"):
        compose = root / candidate
        if compose.exists():
            break
    else:
        return []
    try:
        import yaml  # optional — not in stdlib

        data = yaml.safe_load(compose.read_text(encoding="utf-8"))
    except Exception:
        # yaml not installed or parse error — fall back to regex
        entries = []
        for line in compose.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s+image:\s*(\S+)", line)
            if m:
                image = m.group(1).strip("\"'")
                name, version = (
                    image.rsplit(":", 1) if ":" in image else (image, "latest")
                )
                entries.append(
                    {"name": name, "version": version, "type": "docker_image"}
                )
        return entries
    entries = []
    for svc in (data or {}).get("services", {}).values():
        image = svc.get("image", "")
        if image:
            name, version = image.rsplit(":", 1) if ":" in image else (image, "latest")
            entries.append({"name": name, "version": version, "type": "docker_image"})
    return entries


# --- Project type detection ---

_TYPE_INDICATORS: dict[str, list[str]] = {
    "python": ["requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg"],
    "node": ["package.json"],
    "java": ["pom.xml", "build.gradle"],
    "go": ["go.mod"],
    "ruby": ["Gemfile", "Gemfile.lock"],
    "terraform": ["*.tf"],
    "docker": [
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
    ],
}


def _detect_types(root: Path, include: list[str] | None) -> list[str]:
    detected = []
    for ptype, patterns in _TYPE_INDICATORS.items():
        if include and ptype not in include:
            continue
        for pattern in patterns:
            if list(root.glob(pattern)):
                detected.append(ptype)
                break
    return detected


_PARSERS: dict[str, Any] = {
    "python": [_parse_requirements_txt, _parse_pyproject_toml],
    "node": [_parse_package_json],
    "java": [_parse_pom_xml],
    "go": [_parse_go_mod],
    "ruby": [_parse_gemfile_lock],
    "terraform": [_parse_terraform],
    "docker": [_parse_dockerfile, _parse_docker_compose],
}


def _build_summary(project_types: list[str], bom: list[dict]) -> str:
    if not project_types:
        return "No recognised project manifest files found."
    type_str = " + ".join(project_types)
    return (
        f"Detected {type_str} project with {len(bom)} component(s). "
        "Pass the BOM to bom_update() to register it with an environment."
    )


def _environment_hints(root: Path, project_types: list[str]) -> dict[str, Any]:
    hints: dict[str, Any] = {}
    if "terraform" in project_types:
        hints["project_type"] = "iac"
        hints["cloud_provider_hint"] = _detect_cloud_provider(root)
    elif project_types:
        hints["project_type"] = "application"
    return hints


def _detect_cloud_provider(root: Path) -> str | None:
    tf_text = ""
    for tf in list(root.glob("*.tf"))[:5]:
        tf_text += tf.read_text(encoding="utf-8", errors="replace")
    if "hashicorp/aws" in tf_text or '"aws"' in tf_text:
        return "aws"
    if "hashicorp/azurerm" in tf_text or '"azurerm"' in tf_text:
        return "azure"
    if "hashicorp/google" in tf_text or '"google"' in tf_text:
        return "gcp"
    return None


def project_scan(
    path: str = ".",
    include: list[str] | None = None,
) -> dict[str, Any]:
    """Scan a project directory and return a BOM + environment summary.

    Args:
        path: Directory to scan. Defaults to current working directory.
              Path traversal via '..' is rejected.
        include: Restrict scan to these project types. Options: python, node,
                 java, go, ruby, terraform, docker. Omit to detect all types.

    Returns:
        Dict with keys:
            ``project_type`` (list of detected types),
            ``bom`` (list of BomEntry-compatible dicts),
            ``environment_hints`` (suggested env_write fields),
            ``scan_summary`` (human-readable summary).
    """
    root = _validate_path(path)
    project_types = _detect_types(root, include)

    bom: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for ptype in project_types:
        for parser in _PARSERS.get(ptype, []):
            for entry in parser(root):
                key = (entry["name"], entry.get("type", ""))
                if key not in seen:
                    seen.add(key)
                    bom.append(entry)

    return {
        "project_type": project_types,
        "bom": bom,
        "environment_hints": _environment_hints(root, project_types),
        "scan_summary": _build_summary(project_types, bom),
    }
