---
brief_id: brief-2026-10-26-openstamanager-rce
event_id: brief-2026-10-26-openstamanager-rce
revision: 1
activity_at: "2026-10-26T20:04:35Z"
title: 'OpenSTAManager: Authenticated OS Command Injection (CVE-2025-69212)'
slug: 2026-10-openstamanager-rce
description: OpenSTAManager versions 2.9.8 and earlier contain an authenticated remote code execution vulnerability (CVE-2025-69212) due to improper file path sanitization in the importFE_ZIP plugin.
date: "2026-10-26T20:04:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of detection rules
cpes:
  - cpe:2.3:a:devcode:openstamanager:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - vulnerability
vendors:
  - Devcode
products:
  - OpenSTAManager (<= 2.9.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OS Command Injection in decodeP7M via unsanitized file path derived from uploaded ZIPs .p7m file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Authenticated import RCE in OpenSTAManager.
    confidence_band: high
cves:
  - id: CVE-2025-69212
    cvss: 8.8
    epss: 0.01944
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-69212
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-OPENSTAMANAGER_CVE_2025_69212_DETECT
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-OPENSTAMANAGER_CVE_2025_69212_DETECT&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2025-69212 Exploitation - POST to importFE_ZIP
    description: Detects potential exploitation of CVE-2025-69212 by monitoring POST requests to the vulnerable importFE_ZIP plugin actions script.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory OpenSTAManager instances
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects OpenSTAManager versions <= 2.9.8
    - action: Deploy web server detection rules to identify exploitation attempts
      owner: Detection Engineering
      due: 24h
      evidence: Exploit targets plugins/importFE_ZIP/actions.php
  enrichment_needed:
    - item: Fixed version
      owner: CTI
      reason: Necessary for remediation planning
      evidence: Source notes version <= 2.9.8 are vulnerable
  hunt_leads:
    - lead: Identify unusual process creation spawned by the web server service account
      technique_id: T1203
      data_needed:
        - Process creation telemetry (e.g., Sysmon Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows OS command injection on the server
  mitigation_plan:
    - priority: immediate
      action: Disable the importFE_ZIP plugin if not actively required
      owner: IT Operations
      addresses: CVE-2025-69212
      evidence: Vulnerability is isolated to plugins/importFE_ZIP/actions.php
---

CVE-2025-69212 is a critical authenticated remote code execution vulnerability affecting OpenSTAManager versions 2.9.8 and earlier. The flaw resides in the 'plugins/importFE_ZIP/actions.php' file within the 'decodeP7M' function. An attacker with low-privileged access can leverage unsanitized file paths derived from an uploaded ZIP archive to perform OS command injection on the host server.

## Impact
Successful exploitation allows an authenticated attacker to execute arbitrary OS commands with the privileges of the web server process, potentially leading to full system compromise.

## Recommendation
- Inventory all deployments of OpenSTAManager and identify versions 2.9.8 or earlier.
- Upgrade OpenSTAManager to a patched version once released by the vendor.
- Implement strict file upload validation and restrict access to the 'plugins/importFE_ZIP/' directory.
- Monitor web server access logs for anomalous POST requests directed at 'plugins/importFE_ZIP/actions.php'.
