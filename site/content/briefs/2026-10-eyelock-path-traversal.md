---
brief_id: brief-2026-10-20-eyelock-path-traversal
event_id: brief-2026-10-20-eyelock-path-traversal
revision: 1
activity_at: "2026-10-20T21:54:04Z"
title: 'EyeLock nano NXT: Path traversal in logdownload.php (CVE-2016-20104)'
slug: 2026-10-eyelock-path-traversal
description: EyeLock nano NXT biometric devices contain a path traversal vulnerability in logdownload.php that allows unauthenticated attackers to read arbitrary system files via the path parameter.
date: "2026-10-20T21:54:04Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:eyelock:nano_nxt:3.05.1193:*:*:*:*:*:*:*
  - cpe:2.3:a:eyelock:nano_nxt:3.04.1108:*:*:*:*:*:*:*
  - cpe:2.3:a:eyelock:nano_nxt:3.03.944:*:*:*:*:*:*:*
  - cpe:2.3:a:eyelock:nano_nxt:3.01.646:*:*:*:*:*:*:*
tags:
  - path-traversal
  - iiot
  - information-disclosure
vendors:
  - EyeLock
products:
  - nano NXT (3.05.1193, 3.04.1108, 3.03.944, 3.01.646)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can send GET requests to /scripts/logdownload.php with traversal sequences like ../../etc/passwd.
    confidence_band: high
cves:
  - id: CVE-2016-20104
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20104
rules:
  - title: Detects CVE-2016-20104 Exploitation - Path Traversal in logdownload.php
    description: Detects GET requests to logdownload.php containing path traversal sequences indicating an attempt to read files like /etc/passwd
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch EyeLock nano NXT devices to the latest secure version available from the vendor
      owner: IT Operations
      due: 48h
      evidence: Vulnerable versions are explicitly documented in CVE-2016-20104
  hunt_leads:
    - lead: Identify GET requests to /scripts/logdownload.php with path traversal in access logs
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Shadowserver reported in-the-wild exploitation activity
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to EyeLock nano NXT management interfaces
      owner: IT Operations
      addresses: CVE-2016-20104
      evidence: Vulnerability is exposed via unauthenticated GET request
---

EyeLock nano NXT biometric authentication devices (firmware versions 3.05.1193, 3.04.1108, 3.03.944, and 3.01.646) are vulnerable to an unauthenticated path traversal vulnerability identified as CVE-2016-20104. The issue resides within the logdownload.php script, which fails to sanitize user-supplied input provided via the path parameter. By submitting a crafted GET request containing directory traversal sequences (such as ../), an attacker can access sensitive system files outside of the intended directory, such as /etc/passwd. The Shadowserver Foundation reported observing in-the-wild exploitation of this vulnerability starting on October 19, 2023. This is a high-severity flaw as it allows for information disclosure without authentication on edge-exposed biometric hardware.

## Impact

Successful exploitation of CVE-2016-20104 allows unauthorized attackers to read arbitrary files from the EyeLock nano NXT device filesystem. This can lead to the exposure of sensitive configuration files, credential hashes, or system information, potentially facilitating further unauthorized access or device compromise in physical security environments.

## Recommendation

1. Audit network perimeters to identify and restrict internet access to the web management interface of EyeLock nano NXT devices.
2. If the devices are currently running vulnerable versions (3.05.1193, 3.04.1108, 3.03.944, or 3.01.646), prioritize applying the vendor-provided firmware security update to remediate CVE-2016-20104.
3. Deploy the provided Sigma rule to monitor for exploitation attempts targeting the logdownload.php script.
