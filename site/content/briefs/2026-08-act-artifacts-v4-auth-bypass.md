---
title: Authentication Bypass and Artifact Manipulation in 'act' HTTP Artifacts V4 Backend
slug: 2026-08-act-artifacts-v4-auth-bypass
description: The 'act' tool's HTTP Artifacts V4 backend suffers from an authentication bypass and hardcoded HMAC key vulnerability (CVE-2026-76847), allowing unauthorized network actors to access, modify, or delete artifacts and exfiltrate secrets.
date: "2026-08-24T16:02:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - nektos
products:
  - act
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Any client that can reach it may read, overwrite or delete the artifacts of a concurrently running job with no credentials, exposing build outputs such as secrets and deployment credentials.
    confidence_band: high
cves:
  - id: CVE-2026-76847
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76847
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch act tool to version containing fix for CVE-2026-76847
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76847 advisory
    - action: Bind act artifact server to loopback address (127.0.0.1)
      owner: IT Operations
      due: 24h
      evidence: The --artifact-server-addr flag defaults to the host's outbound address rather than loopback
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to act artifact server port via host firewall
      owner: IT Operations
      addresses: CVE-2026-76847
      evidence: The --artifact-server-addr flag defaults to the host's outbound address rather than loopback
---

The 'act' tool, used for running GitHub Actions locally, exposes a critical security vulnerability (CVE-2026-76847) in its HTTP Artifacts V4 backend implementation. Introduced to support actions/upload-artifact@v4 and actions/download-artifact@v4, this backend fails to validate the `workflow_run_backend_id` parameter against the requesting task, essentially disabling access control. Furthermore, the backend uses a static, hardcoded four-byte HMAC key (0xba 0xdb 0xee 0xf0) for signing artifact URLs. The flawed construction of these signatures, combined with the fact that the artifact server defaults to listening on all network interfaces rather than loopback, allows any reachable attacker to read, overwrite, or delete build artifacts. This vulnerability enables the theft of sensitive data such as hardcoded secrets, API keys, or deployment credentials, and allows attackers to inject malicious files into the CI/CD pipeline of a target machine.

## Impact

Successful exploitation allows for the complete compromise of CI/CD build outputs handled by the 'act' tool. Unauthorized actors can exfiltrate sensitive environment variables, deployment tokens, and build artifacts, or manipulate files to facilitate supply-chain attacks on build processes. Given the hardcoded key and lack of network binding restrictions, any attacker with network visibility to the host running 'act' can perform these operations without credentials.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

- Update the 'act' tool to the latest patched version immediately to resolve CVE-2026-76847.
- Inspect existing network configurations for hosts running 'act'; ensure that artifact server ports are not exposed to untrusted networks.
- Implement network-level egress and ingress filtering to restrict access to the 'act' artifact server port (typically configured via `--artifact-server-addr`) to localhost only.
- Audit CI/CD logs for unauthorized access to artifact endpoints or unexpected artifact modification events if the tool was previously deployed in a shared or non-isolated environment.
