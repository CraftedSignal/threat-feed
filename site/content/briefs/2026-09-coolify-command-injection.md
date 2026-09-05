---
title: Command Injection Vulnerability in Coolify
slug: 2026-09-coolify-command-injection
description: Coolify versions before 4.2.0 are vulnerable to command injection via environment variable keys, allowing authenticated attackers to execute arbitrary commands on the underlying host server.
date: "2026-09-02T03:10:31Z"
lastmod: "2026-09-05T11:31:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:coolify:coolify:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - cloud
  - authentication-bypass
  - web-application
vendors:
  - Coolify
products:
  - Coolify (< 4.2.0)
  - Coolify (< 4.2.0)
  - Coolify (<= 4.3.17)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated attackers can inject shell metacharacters into environment variable keys to execute arbitrary commands on the server host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Coolify before 4.2.0 fails to properly escape environment variable key names in Docker commands executed over SSH.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Coolify through 4.3.17 contains an authentication bypass vulnerability in the OAuth callback handler.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Attackers can register a victim's email address on any enabled OAuth provider to obtain authenticated sessions as that user.
    confidence_band: high
cves:
  - id: CVE-2026-84694
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84694
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3150
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86117
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all Coolify installations to version 4.2.0 or later.
      owner: IT Operations
      due: 24h
      evidence: NVD advisory identifies version 4.2.0 as the remediation for CVE-2026-84694.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict SSH access/permissions for Coolify managed hosts.
      owner: IT Operations
      addresses: CVE-2026-84694
      evidence: Vulnerability allows execution via SSH-based Docker management commands.
updates:
  - at: "2026-09-02T12:02:08Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3150
  - at: "2026-09-05T11:31:33Z"
    level: L2
    summary: added coverage for Coolify (<= 4.3.17)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-86117
---

Coolify versions prior to 4.2.0 contain a critical vulnerability identified as CVE-2026-84694. The flaw exists in how the application handles environment variable key names when constructing Docker commands for execution over SSH on managed host servers. Specifically, the application fails to properly sanitize or escape input, enabling an authenticated attacker to inject shell metacharacters into the environment variable key fields. When Coolify triggers a Docker command (such as 'docker run' or 'docker exec') using these unsanitized variables, the injected characters are interpreted by the host shell, resulting in arbitrary code execution outside the container context. This vulnerability poses a high risk to infrastructure security, as it allows escalation from the Coolify application interface to full host-level access on connected managed servers.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary commands on the host server where Coolify manages Docker containers. This effectively grants the attacker control over the host operating system, potentially leading to unauthorized data access, persistence, privilege escalation, and lateral movement within the infrastructure.

## Recommendation

Prioritize the immediate upgrade of all Coolify instances to version 4.2.0 or later to remediate CVE-2026-84694. For infrastructure hardening, restrict the permissions of the SSH service account used by Coolify to communicate with managed hosts, applying the principle of least privilege to limit the scope of potential command injection impact.
