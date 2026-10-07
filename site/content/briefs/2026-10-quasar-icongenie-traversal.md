---
title: Path Traversal and Arbitrary File Write in Quasar Icon Genie
slug: 2026-10-quasar-icongenie-traversal
description: The Quasar Icon Genie CLI tool is vulnerable to path traversal via malicious JSON configuration profiles, allowing attackers to overwrite arbitrary files on the local filesystem.
date: "2026-10-07T16:59:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-106103
    cvss: 7.1
---

The Quasar Framework's Icon Genie CLI tool (specifically `@quasar/icongenie`) is vulnerable to a path traversal vulnerability (CVE-2026-106103) that allows arbitrary file writes on the host system. The vulnerability exists within the profile processing logic, where the `folder` and `name` attributes for icon assets are loaded from a user-supplied JSON file without adequate validation. The
