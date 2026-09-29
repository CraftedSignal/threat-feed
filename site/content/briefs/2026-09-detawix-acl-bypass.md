---
title: Access Control Bypass in DetaWix Mobile Web Portal
slug: 2026-09-detawix-acl-bypass
description: The DetaWix Mobile Web Portal contains an improper access control vulnerability (CVE-2026-86450) that allows unauthenticated or unauthorized users to access sensitive functionality and exfiltrate data.
date: "2026-09-29T18:28:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:parla_auto_automotive_trading:detawix_mobile_web_portal:*:*:*:*:*:*:*:*
vendors:
  - Parla Auto Automotive Trading Limited Company
products:
  - DetaWix Mobile Web Portal (< 1.0.19)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The DetaWix Mobile Web Portal contains a vulnerability where sensitive information is improperly exposed in sent data due to a failure to properly constrain functionality via ACLs.
    confidence_band: med
cves:
  - id: CVE-2026-86450
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86450
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade DetaWix Mobile Web Portal to version 1.0.19 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-86450 vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v1.0.19 or later.
      owner: IT Operations
      addresses: CVE-2026-86450
      evidence: NVD advisory
---

DetaWix Mobile Web Portal versions prior to 1.0.19 contain a critical vulnerability, tracked as CVE-2026-86450, involving the insertion of sensitive information into sent data. The root cause is a failure to properly constrain functionality via Access Control Lists (ACLs). This flaw allows unauthorized actors to interact with internal portal functions that should otherwise be restricted. Exploitation of this vulnerability could lead to the exposure of sensitive PII or business information. Organizations utilizing the DetaWix platform must prioritize patching to version 1.0.19 or later to mitigate the risk of data exposure.

## Impact

Successful exploitation allows unauthorized access to restricted application functions. This can lead to the exfiltration of sensitive information processed by the DetaWix Mobile Web Portal. The scope of impact includes potential unauthorized data access within automotive trading environments where this portal is deployed.

## Recommendation

* Patch the DetaWix Mobile Web Portal to version 1.0.19 or later immediately.
* Audit access logs for anomalous requests directed at restricted API endpoints or administrative functionalities within the portal.
* Review web server logs for high-frequency requests from non-authenticated sessions targeting sensitive data paths.
