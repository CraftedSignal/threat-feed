---
brief_id: brief-2026-10-27-gfi-kerioconnect-xss
event_id: brief-2026-10-27-gfi-kerioconnect-xss
revision: 1
activity_at: "2026-10-27T18:02:25Z"
title: 'GFI KerioConnect: Stored Cross-Site Scripting in Webmail (CVE-2026-112353)'
slug: 2026-10-gfi-kerioconnect-xss
description: GFI KerioConnect versions before 10.0.8 Patch 2 are susceptible to stored XSS via maliciously crafted SVG attachments, allowing attackers to execute arbitrary JavaScript in authenticated user sessions.
date: "2026-10-27T18:02:25Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source-confirmed vulnerability and patch availability
cpes:
  - cpe:2.3:a:gfi:kerioconnect:*:*:*:*:*:*:*:*
tags:
  - cve-2026-112353
  - xss
  - webmail
  - data-theft
vendors:
  - GFI
products:
  - KerioConnect (< 10.0.8 Patch 2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.001
    subtechnique_name: Spearphishing Attachment
    evidence: Proofpoint Threat Research has observed exploitation in the wild as a credential and mailbox stealer.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.007
    subtechnique_name: JavaScript
    evidence: allows a remote attacker to run JavaScript in a victim's authenticated Webmail session by uploading a crafted SVG email attachment
    confidence_band: high
cves:
  - id: CVE-2026-112353
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112353
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all KerioConnect instances to 10.0.8 Patch 2 or higher
      owner: IT Operations
      due: 24h
      evidence: GFI KerioConnect (Kerio Connect) before 10.0.8 Patch 2 contains a stored cross-site scripting vulnerability
  hunt_leads:
    - lead: Monitor web access logs for requests to the temporary-download endpoint originating from unexpected or malicious-looking file requests
      technique_id: T1566.001
      data_needed:
        - KerioConnect Webmail application logs
        - HTTP access logs related to temporary-download paths
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can exploit the temporary-download endpoint's insufficient Content-Security-Policy sandbox
  mitigation_plan:
    - priority: immediate
      action: Upgrade KerioConnect to 10.0.8 Patch 2
      owner: IT Operations
      addresses: CVE-2026-112353
      evidence: GFI KerioConnect before 10.0.8 Patch 2 contains a stored cross-site scripting vulnerability
---

GFI KerioConnect (Kerio Connect) versions prior to 10.0.8 Patch 2 contain a stored cross-site scripting (XSS) vulnerability within the Webmail component. The vulnerability arises from insufficient sanitization of event-handler attributes in SVG email attachments. Exploitation allows remote attackers to execute arbitrary JavaScript in the context of an authenticated victim's session. Proofpoint Threat Research has confirmed in-the-wild exploitation of this vulnerability for credential and mailbox data theft.

## Attack Chain
1. Attacker crafts a malicious SVG file containing JavaScript within event-handler attributes.
2. Attacker sends the crafted SVG file as an email attachment to a targeted user.
3. Victim accesses their account via the vulnerable KerioConnect Webmail interface.
4. Victim interacts with or triggers a preview of the malicious email attachment.
5. The KerioConnect temporary-download endpoint serves the SVG content.
6. Due to an insufficient Content-Security-Policy (CSP) sandbox, the embedded JavaScript executes in the victim's browser session.
7. Malicious scripts exfiltrate user credentials or mailbox contents to an attacker-controlled server.

## Impact
Confirmed exploitation results in unauthorized credential theft and access to mailbox contents for authenticated users.

## Recommendation
Upgrade all GFI KerioConnect installations to version 10.0.8 Patch 2 or later immediately.
