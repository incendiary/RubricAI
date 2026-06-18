"""project_scan tool tests — manifest parsing + safety checks."""

import json
import textwrap
from pathlib import Path

import pytest

from src.rubricai.tools.project_scan import project_scan


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    return tmp_path


class TestPythonProject:
    def test_requirements_txt(self, tmp_project: Path):
        (tmp_project / "requirements.txt").write_text(
            "requests==2.31.0\nflask>=2.3.0\n# comment\n-r other.txt\n"
        )
        result = project_scan(str(tmp_project))
        assert "python" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "requests" in names
        assert "flask" in names
        versions = {e["name"]: e["version"] for e in result["bom"]}
        assert versions["requests"] == "2.31.0"

    def test_pyproject_toml_dependencies(self, tmp_project: Path):
        (tmp_project / "pyproject.toml").write_text(textwrap.dedent("""\
                [project]
                name = "myapp"
                dependencies = [
                    "httpx>=0.25.0",
                    "pydantic~=2.5",
                ]
                """))
        result = project_scan(str(tmp_project))
        assert "python" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "httpx" in names
        assert "pydantic" in names

    def test_types_are_pypi(self, tmp_project: Path):
        (tmp_project / "requirements.txt").write_text("boto3==1.34.0\n")
        result = project_scan(str(tmp_project))
        entry = next(e for e in result["bom"] if e["name"] == "boto3")
        assert entry["type"] == "pypi"

    def test_deduplication(self, tmp_project: Path):
        # requirements.txt and pyproject.toml both list the same package
        (tmp_project / "requirements.txt").write_text("requests==2.31.0\n")
        (tmp_project / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.30.0"]\n'
        )
        result = project_scan(str(tmp_project))
        names = [e["name"] for e in result["bom"]]
        assert names.count("requests") == 1


class TestNodeProject:
    def test_package_json(self, tmp_project: Path):
        (tmp_project / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
                    "devDependencies": {"jest": "^29.0.0"},
                }
            )
        )
        result = project_scan(str(tmp_project))
        assert "node" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

    def test_types_are_npm(self, tmp_project: Path):
        (tmp_project / "package.json").write_text(
            json.dumps({"dependencies": {"express": "4.18.0"}})
        )
        result = project_scan(str(tmp_project))
        entry = next(e for e in result["bom"] if e["name"] == "express")
        assert entry["type"] == "npm"


class TestTerraformProject:
    def test_provider_detected(self, tmp_project: Path):
        (tmp_project / "main.tf").write_text(textwrap.dedent("""\
                terraform {
                  required_providers {
                    aws = {
                      source  = "hashicorp/aws"
                      version = "~> 5.0"
                    }
                  }
                }
                """))
        result = project_scan(str(tmp_project))
        assert "terraform" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "hashicorp/aws" in names

    def test_module_detected(self, tmp_project: Path):
        (tmp_project / "vpc.tf").write_text(textwrap.dedent("""\
                module "vpc" {
                  source  = "terraform-aws-modules/vpc/aws"
                  version = "5.1.0"
                }
                """))
        result = project_scan(str(tmp_project))
        assert "terraform" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "terraform-aws-modules/vpc/aws" in names

    def test_cloud_provider_hint_aws(self, tmp_project: Path):
        (tmp_project / "main.tf").write_text(
            'provider "aws" { region = "us-east-1" }\n'
        )
        result = project_scan(str(tmp_project))
        assert result["environment_hints"].get("cloud_provider_hint") == "aws"

    def test_iac_project_type_hint(self, tmp_project: Path):
        (tmp_project / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        result = project_scan(str(tmp_project))
        assert result["environment_hints"].get("project_type") == "iac"


class TestDockerProject:
    def test_dockerfile_base_image(self, tmp_project: Path):
        (tmp_project / "Dockerfile").write_text(
            "FROM python:3.11-slim\nRUN pip install flask\n"
        )
        result = project_scan(str(tmp_project))
        assert "docker" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "python" in names
        entry = next(e for e in result["bom"] if e["name"] == "python")
        assert entry["version"] == "3.11-slim"

    def test_docker_compose_images(self, tmp_project: Path):
        (tmp_project / "docker-compose.yml").write_text(textwrap.dedent("""\
                services:
                  web:
                    image: nginx:1.25
                  db:
                    image: postgres:15
                """))
        result = project_scan(str(tmp_project))
        assert "docker" in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "nginx" in names
        assert "postgres" in names

    def test_scratch_image_excluded(self, tmp_project: Path):
        (tmp_project / "Dockerfile").write_text("FROM scratch\nCOPY myapp /myapp\n")
        result = project_scan(str(tmp_project))
        names = [e["name"] for e in result["bom"]]
        assert "scratch" not in names


class TestPathSafety:
    def test_path_traversal_rejected(self, tmp_project: Path):
        with pytest.raises(ValueError, match="traversal"):
            project_scan("../etc")

    def test_nested_traversal_rejected(self):
        with pytest.raises(ValueError, match="traversal"):
            project_scan("/tmp/foo/../../etc/passwd")

    def test_nonexistent_path_rejected(self):
        with pytest.raises(ValueError, match="does not exist"):
            project_scan("/nonexistent/path/that/cannot/exist/xyz123")

    def test_file_path_rejected(self, tmp_project: Path):
        f = tmp_project / "myfile.txt"
        f.write_text("hello")
        with pytest.raises(ValueError, match="not a directory"):
            project_scan(str(f))


class TestEmptyProject:
    def test_empty_dir_returns_empty_bom(self, tmp_project: Path):
        result = project_scan(str(tmp_project))
        assert result["project_type"] == []
        assert result["bom"] == []
        assert "No recognised" in result["scan_summary"]

    def test_include_filter_limits_detection(self, tmp_project: Path):
        (tmp_project / "requirements.txt").write_text("flask==2.3.0\n")
        (tmp_project / "package.json").write_text(
            json.dumps({"dependencies": {"express": "4.18.0"}})
        )
        result = project_scan(str(tmp_project), include=["python"])
        assert "node" not in result["project_type"]
        names = [e["name"] for e in result["bom"]]
        assert "express" not in names


class TestRenderPromptTarget:
    """Verify pycharm target renders without error."""

    def test_pycharm_target_exists(self):
        from scripts.render_prompt import TARGETS

        assert "pycharm" in TARGETS

    def test_pycharm_template_exists(self):
        from scripts.render_prompt import TEMPLATES_DIR

        assert (TEMPLATES_DIR / "pycharm.md.j2").exists()

    def test_pycharm_render_produces_output(self, tmp_path: Path, monkeypatch):
        from scripts import render_prompt

        monkeypatch.setattr(render_prompt, "OUT_DIR", tmp_path)
        out = render_prompt.render("pycharm")
        assert out.exists()
        content = out.read_text()
        assert "project_scan" in content
        assert "PyCharm" in content
