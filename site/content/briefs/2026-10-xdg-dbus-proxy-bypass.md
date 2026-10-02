---
title: Sandbox Escape via D-Bus Message Filtering Bypass in xdg-dbus-proxy
slug: 2026-10-xdg-dbus-proxy-bypass
description: A vulnerability in xdg-dbus-proxy versions prior to 0.1.9 allows a compromised Flatpak application to bypass security filters and escape the sandbox via malformed D-Bus reply serials.
date: "2026-10-02T14:25:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flatpak:xdg-dbus-proxy:*:*:*:*:*:*:*:*
tags:
  - sandbox-escape
  - privilege-escalation
  - linux
vendors:
  - Flatpak
products:
  - xdg-dbus-proxy (< 0.1.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1204
    technique_name: User Execution
    evidence: A malicious or compromised Flatpak app could use this to achieve arbitrary code execution outside its sandbox.
    confidence_band: high
cves:
  - id: CVE-2026-94422
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94422
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade xdg-dbus-proxy to version 0.1.9 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-94422 fixed in version 0.1.9
  mitigation_plan:
    - priority: immediate
      action: Patch xdg-dbus-proxy to 0.1.9 or later
      owner: IT Operations
      addresses: CVE-2026-94422
      evidence: NVD vulnerability disclosure
---

CVE-2026-94422 involves an incorrect implementation of message filtering within xdg-dbus-proxy versions prior to 0.1.9. This utility, which is responsible for enforcing security boundaries for Flatpak applications, fails to correctly validate the reply serial number field on D-Bus messages. An attacker who controls a sandboxed application can inject a reply serial number into non-reply messages, tricking the proxy into incorrectly routing or authorizing messages that should have been blocked. This vulnerability enables a malicious or compromised application to escape the intended sandbox isolation, leading to arbitrary code execution on the underlying host system. While primarily impacting Flatpak environments, the tool is also utilized by other sandboxing frameworks such as Firejail, expanding the potential attack surface. Defenders should prioritize updating xdg-dbus-proxy to version 0.1.9 or later across all Linux systems hosting sandboxed applications.

## Impact

The vulnerability results in a full bypass of the sandbox security model. A successful exploit allows a malicious application to execute arbitrary code with the privileges of the user running the sandbox, potentially leading to unauthorized data access, persistence, or lateral movement within the environment.

## Recommendation

- Upgrade xdg-dbus-proxy to version 0.1.9 or later on all Linux distributions.
- Review environments utilizing sandboxing frameworks like Flatpak or Firejail to ensure the host package repository reflects the patched version.
- Audit logs for unexpected D-Bus communications originating from sandboxed process IDs.
