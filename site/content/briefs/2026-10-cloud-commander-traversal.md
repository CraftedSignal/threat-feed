---
title: Path Traversal Vulnerability in Cloud Commander
slug: 2026-10-cloud-commander-traversal
description: Cloud Commander versions 19.20.2 through 19.21.1 are vulnerable to a path traversal flaw in the GET /api/v1/pack endpoint allowing unauthenticated file exfiltration.
date: "2026-10-14T16:36:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cloudcmd:cloudcmd:19.20.2:*:*:*:*:*:*:*
  - cpe:2.3:a:cloudcmd:cloudcmd:19.21.1:*:*:*:*:*:*:*
vendors:
  - Cloud Commander
products:
  - cloudcmd (19.20.2 - 19.21.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can send percent-encoded directory traversal sequences in the pack request path to read arbitrary files outside the configured --root directory.
    confidence_band: high
cves:
  - id: CVE-2026-110690
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110690
rules:
  - title: Detects CVE-2026-110690 Exploitation - Path Traversal in Cloud Commander
    description: Detects exploitation of CVE-2026-110690 via path traversal sequences in the pack API endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade cloudcmd to a version outside the vulnerable range (19.20.2-19.21.1)
      owner: IT Operations
      due: 24h
      evidence: Source states affected versions are 19.20.2 through 19.21.1.
  hunt_leads:
    - lead: Search logs for requests to /api/v1/pack with traversal sequences like %2e%2e%2f or ../
      technique_id: T1083
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary file read via this endpoint using traversal sequences.
  mitigation_plan:
    - priority: immediate
      action: Patch cloudcmd
      owner: IT Operations
      addresses: CVE-2026-110690
      evidence: NVD vulnerability details
---

Cloud Commander (cloudcmd) versions 19.20.2 through 19.21.1 contain a path traversal vulnerability in the GET /api/v1/pack endpoint. The flaw exists because the onGET handler at server/rest/index.js improperly calls an unguarded root() function rather than the secure root.resolve() validation wrapper used elsewhere in the application. An unauthenticated attacker can exploit this by sending percent-encoded directory traversal sequences within the pack request path. When processed, the application accesses files outside the intended root directory, archives them into a .tar.gz file, and streams the archive back to the requester. This allows attackers to exfiltrate sensitive host files such as /etc/passwd or SSH private keys. Given the ease of exploitation, organizations running affected versions of Cloud Commander should restrict access to the application or upgrade to a patched version immediately.

## Impact

Successful exploitation allows an unauthenticated remote attacker to read arbitrary files from the underlying host filesystem. This leads to the exposure of sensitive configuration files, system credentials, and SSH private keys, potentially resulting in full system compromise or lateral movement. The vulnerability impacts any environment utilizing these versions of Cloud Commander for remote file management.

## Recommendation

* Upgrade Cloud Commander to a version outside of the 19.20.2 through 19.21.1 range immediately.
* Implement strict ingress filtering for the Cloud Commander API endpoints, specifically denying requests to /api/v1/pack containing traversal characters (e.g., ../).
* Enable web server access logs to audit all requests to /api/v1/pack and identify anomalous paths containing directory traversal patterns.
