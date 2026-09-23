---
title: Authenticated OS Command Injection in OpenC3 COSMOS
slug: 2026-09-openc3-rce
description: Authenticated users can achieve arbitrary OS command execution in the OpenC3 COSMOS API via shell metacharacter injection in the pypi_url configuration setting during plugin installation.
date: "2026-09-23T19:57:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openc3:openc3:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - cve-2026-77601
vendors:
  - OpenC3
products:
  - openc3 (>= 5.12.0, <= 7.2.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Shell metacharacters in the setting value are executed by /bin/sh.
    confidence_band: high
cves:
  - id: CVE-2026-77601
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-vp3w-52v9-q57f
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Monitor API logs for set_setting calls containing shell metacharacters in the pypi_url field
      owner: SOC
      due: 24h
      evidence: PoC demonstrates injection via set_setting JSON-RPC params.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched release or implement code-level sanitization using ProcessManager.spawn as described in the brief
      owner: IT Operations
      addresses: CVE-2026-77601
      evidence: Suggested fix from GHSA advisory.
---

OpenC3 COSMOS, specifically the `openc3-cosmos-cmd-tlm-api` service, is vulnerable to authenticated OS command injection via the `pypi_url` setting. An attacker can use the JSON-RPC method `set_setting` to update this configuration with a string containing shell metacharacters. During the plugin installation process, the application incorrectly uses Ruby backticks to invoke `/openc3/bin/pipinstall`, passing the unsanitized `pypi_url` directly to `/bin/sh`. This behavior impacts OpenC3 versions 5.12.0 through 7.2.1. In the open-source edition, the vulnerability is accessible to any authenticated user due to improper authorization checks in `openc3/lib/openc3/utilities/authorization.rb`. Successful exploitation results in command execution as the `openc3` service user (uid 1001) within the application container, granting access to sensitive credentials, Redis/Valkey secrets, and bucket storage.

## Attack Chain

1. Attacker authenticates to the `POST /openc3-api/auth/verify` endpoint to obtain a valid session token.
2. Attacker invokes the `set_setting` JSON-RPC method via `POST /openc3-api/api` to set the `pypi_url` parameter to a malicious payload (e.g., `https://pypi.org ; <command> ; #`).
3. Attacker prepares a malicious plugin gem containing a `requirements.txt` or `pyproject.toml` file to trigger the Python installation logic.
4. Attacker uploads the malicious plugin via `POST /openc3-api/plugins`.
5. Attacker triggers the plugin installation using the hash obtained from the upload via `POST /openc3-api/plugins/install/<id>`.
6. The `openc3/lib/openc3/models/plugin_model.rb` script executes the injected payload through the Ruby backtick operator, which spawns `/bin/sh -c`.
7. The operating system executes the malicious command with the privileges of the `openc3` service user.

## Impact

Successful exploitation allows for full control of the `openc3` service account inside the container. This leads to the exfiltration or modification of telemetry and commanding data, compromise of cloud storage (S3) credentials, and access to internal Redis/Valkey configuration passwords. This vulnerability enables lateral movement or deeper persistence within the scope of the affected container.

## Recommendation

1. Upgrade OpenC3 to a patched version once available; monitor vendor security advisories for the specific release addressing CVE-2026-77601.
2. Apply the code-level mitigation by replacing the Ruby backtick execution in `plugin_model.rb` with an `OpenC3::ProcessManager.spawn` call using an argument array to prevent shell interpretation.
3. Implement input validation on the `pypi_url` setting to restrict values to legitimate HTTP or HTTPS URLs.
4. Review audit logs for anomalous `set_setting` calls involving JSON-RPC where the parameter values contain shell metacharacters like `;`, `&`, `|`, or backticks.
