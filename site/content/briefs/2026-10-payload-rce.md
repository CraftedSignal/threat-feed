---
title: Remote Code Execution in @payloadcms/plugin-form-builder
slug: 2026-10-payload-rce
description: A critical remote code execution vulnerability (CVE-2026-105857) in @payloadcms/plugin-form-builder allows unauthenticated attackers to execute arbitrary code via crafted form submissions.
date: "2026-10-07T22:46:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:payload:payloadcms_plugin_form_builder:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application-vulnerability
  - payloadcms
vendors:
  - Payload
products:
  - '@payloadcms/plugin-form-builder (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)'
cves:
  - id: CVE-2026-105857
    cvss: 10
references:
  - https://github.com/advisories/GHSA-r488-j9vj-wx3q
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105857
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade @payloadcms/plugin-form-builder to 3.90.0 or 4.0.0-canary.34
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies these versions as the necessary security patches for CVE-2026-105857
  mitigation_plan:
    - priority: immediate
      action: Patch @payloadcms/plugin-form-builder to 3.90.0 or later
      owner: IT Operations
      addresses: CVE-2026-105857
      evidence: GHSA-r488-j9vj-wx3q
---

The @payloadcms/plugin-form-builder package, used within the Payload CMS ecosystem, contains a critical vulnerability (CVE-2026-105857) that permits remote code execution. The issue stems from insecure handling of user-supplied data during form submissions. Attackers can craft malicious input within a form field that, when processed by the application, is evaluated or executed by the underlying server-side environment. This flaw affects versions of the plugin prior to 3.90.0 and specific versions in the 4.0.0-canary release cycle. Because the vulnerability is triggered via form submission endpoints, it is a high-value target for threat actors looking to gain initial access to servers hosting Payload CMS instances. Immediate patching is required to prevent compromise of the host infrastructure.

## Impact

Successful exploitation of this vulnerability leads to full remote code execution on the application server. This can result in unauthorized data access, lateral movement within the network, and complete system compromise. Organizations running Payload CMS installations using the affected plugin versions are at risk of server takeover.

## Recommendation

- Upgrade the @payloadcms/plugin-form-builder package to version 3.90.0 or higher immediately.
- For those on the canary track, upgrade to version 4.0.0-canary.34 or higher.
- Monitor web server access logs for anomalous POST requests directed at form submission endpoints that include unexpected payloads or shell-like characters.
