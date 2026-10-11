# ruff: noqa: S108 - /tmp paths are inside the sandbox, as Semgrep reports them
"""Fixtures and report builders for the Semgrep tests.

The vulnerable fixtures contain deliberately insecure *code patterns* (synthetic; no real
credentials). Each lists the rule ids it must trigger, by line.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from sentinel_worker.scanners.semgrep import VERSION

PREFIX = "tmp.input.config."
RULE = "sentinelpipe."

VULNERABLE: dict[str, tuple[str, str, set[tuple[int, str]]]] = {
    "java": (
        "src/main/java/app/Users.java",
        """package app;
import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
class Users {
  ResultSet find(Connection c, String id) throws Exception {
    Statement s = c.createStatement();
    return s.executeQuery("SELECT * FROM users WHERE id = " + id);
  }
  void run(String host) throws Exception {
    Runtime.getRuntime().exec("ping " + host);
    Object o = new ObjectInputStream(new FileInputStream(host)).readObject();
    MessageDigest.getInstance("MD5");
  }
}
""",
        {
            (8, "java.sql-injection-string-concatenation"),
            (11, "java.command-injection-runtime-exec"),
            (12, "java.insecure-deserialization"),
            (13, "java.weak-hash-algorithm"),
        },
    ),
    "python": (
        "app/handlers.py",
        """import hashlib
import os
import pickle
import subprocess
import yaml


def handle(cmd, cursor, blob):
    subprocess.run(cmd, shell=True)
    os.system(cmd)
    eval(cmd)
    pickle.loads(blob)
    yaml.load(blob)
    cursor.execute("SELECT * FROM t WHERE id = %s" % cmd)
    cursor.execute(f"SELECT * FROM t WHERE name = '{cmd}'")
    return hashlib.md5(blob).hexdigest()
""",
        {
            (9, "python.command-injection-shell"),
            (10, "python.command-injection-shell"),
            (11, "python.code-injection-eval"),
            (12, "python.insecure-deserialization"),
            (13, "python.insecure-deserialization"),
            (14, "python.sql-injection-string-formatting"),
            (15, "python.sql-injection-string-formatting"),
            (16, "python.weak-hash-algorithm"),
        },
    ),
    "javascript": (
        "web/server.js",
        """const cp = require("child_process");
const crypto = require("crypto");
function handle(input, element) {
  eval(input);
  cp.exec("ls " + input);
  element.innerHTML = input;
  return crypto.createHash("md5").update(input).digest("hex");
}
module.exports = handle;
""",
        {
            (4, "javascript.code-injection-eval"),
            (5, "javascript.command-injection-child-process"),
            (6, "javascript.dom-xss-inner-html"),
            (7, "javascript.weak-hash-algorithm"),
        },
    ),
    "typescript": (
        "web/client.ts",
        """import { exec } from "child_process";
import * as crypto from "crypto";
export function handle(input: string, element: HTMLElement): string {
  eval(input);
  exec("ls " + input);
  element.outerHTML = input;
  const fn = new Function("a", input);
  return crypto.createHash("sha1").update(input).digest("hex");
}
""",
        {
            (4, "javascript.code-injection-eval"),
            (5, "javascript.command-injection-child-process"),
            (6, "javascript.dom-xss-inner-html"),
            (7, "javascript.code-injection-eval"),
            (8, "javascript.weak-hash-algorithm"),
        },
    ),
}

CLEAN: dict[str, tuple[str, str]] = {
    "java": (
        "src/main/java/app/Safe.java",
        """package app;
import java.security.MessageDigest;
import java.sql.*;
class Safe {
  ResultSet find(Connection c, String id) throws Exception {
    PreparedStatement p = c.prepareStatement("SELECT * FROM users WHERE id = ?");
    p.setString(1, id);
    MessageDigest.getInstance("SHA-256");
    new ProcessBuilder("ping", "-c", "1", "localhost").start();
    return p.executeQuery();
  }
}
""",
    ),
    "python": (
        "app/safe.py",
        """import hashlib
import subprocess
import yaml


def handle(name, cursor, blob):
    subprocess.run(["ls", name], check=True)
    cursor.execute("SELECT * FROM t WHERE name = %s", (name,))
    yaml.safe_load(blob)
    hashlib.md5(blob, usedforsecurity=False)
    return hashlib.sha256(blob).hexdigest()
""",
    ),
    "javascript": (
        "web/safe.js",
        """const { execFile } = require("child_process");
const crypto = require("crypto");
function handle(input, element) {
  execFile("ls", [input]);
  element.textContent = input;
  return crypto.createHash("sha256").update(input).digest("hex");
}
module.exports = handle;
""",
    ),
    "typescript": (
        "web/safe.ts",
        """import { spawn } from "child_process";
import * as crypto from "crypto";
export function handle(input: string, element: HTMLElement): string {
  spawn("ls", [input]);
  element.textContent = input;
  return crypto.createHash("sha256").update(input).digest("hex");
}
""",
    ),
}


def rule_ids(expected: set[tuple[int, str]]) -> set[tuple[int, str]]:
    return {(line, RULE + suffix) for line, suffix in expected}


def result(
    path: str,
    rule: str = "python.code-injection-eval",
    line: int = 1,
    severity: str = "ERROR",
    **extra: Any,
) -> dict[str, Any]:
    """One ``results`` entry of a Semgrep 1.179.0 JSON report, as observed."""
    return {
        "check_id": PREFIX + RULE + rule,
        "path": f"/tmp/input/repo/{path}",
        "start": {"line": line, "col": 5, "offset": 10},
        "end": {"line": line, "col": 12, "offset": 17},
        "extra": {
            "message": "message from the report (never used)",
            "metadata": {"cwe": ["CWE-1"]},
            "severity": severity,
            "fingerprint": "requires login",
            "lines": "requires login",
            "validation_state": "NO_VALIDATOR",
            "engine_kind": "OSS",
        }
        | extra,
    }


def report(
    results: list[dict[str, Any]] | None = None,
    scanned: list[str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    **overrides: Any,
) -> bytes:
    document: dict[str, Any] = {
        "version": VERSION,
        "results": results or [],
        "errors": errors or [],
        "paths": {"scanned": [f"/tmp/input/repo/{p}" for p in (scanned or [])]},
        "skipped_rules": [],
        "engine_requested": "OSS",
        "interfile_languages_used": [],
    }
    document.update(overrides)
    return json.dumps(document).encode("utf-8")


def envelope(
    report_bytes: bytes,
    name: str = "semgrep-report.json",
    python_failed: list[str] | None = None,
    python_check: bytes | None = None,
) -> bytes:
    """sandbox-output.v1 as the Semgrep script emits it: the report and the Python syntax
    check (``{"failed": [...]}``)."""
    check = (
        python_check
        if python_check is not None
        else json.dumps({"failed": python_failed or []}).encode("utf-8")
    )
    artifacts = [(name, report_bytes), ("python-syntax.json", check)]
    return json.dumps(
        {
            "schema_version": 1,
            "artifacts": [
                {
                    "name": artifact_name,
                    "media_type": "application/json",
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
                for artifact_name, content in artifacts
            ],
        }
    ).encode("utf-8")
