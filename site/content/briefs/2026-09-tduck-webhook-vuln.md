---
title: Unauthenticated Form Submission Exfiltration in TDuck
slug: 2026-09-tduck-webhook-vuln
description: TDuck survey form through version 5.3 contains a vulnerability allowing authenticated attackers to attach unauthorized webhooks to arbitrary forms for data exfiltration.
date: "2026-09-16T19:51:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tduck:tduck:*:*:*:*:*:*:*:*
vendors:
  - TDuck
products:
  - TDuck (<= 5.3)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: This allows an authenticated attacker to attach malicious webhooks to arbitrary forms, leading to the unauthorized exfiltration of submission data to attacker-controlled external or internal endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-92602
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92602
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade TDuck to the latest version beyond 5.3
      owner: IT Operations
      addresses: CVE-2026-92602
      evidence: Source identifies vulnerability in versions <= 5.3
---

TDuck survey form versions 5.3 and earlier contain a critical vulnerability in the WebhookConfigController. The application fails to properly validate webhook destination URLs and lacks sufficient authorization checks to verify form ownership. This flaw allows an authenticated attacker to associate arbitrary webhook endpoints with any form within the instance. By doing so, the attacker can intercept and exfiltrate sensitive submission data as it is processed by the application. This vulnerability is significant as it facilitates the silent theft of user-provided data, potentially leading to unauthorized access to PII or internal organizational information. Impacted organizations using TDuck for data collection must identify and update instances to a patched version to prevent data exfiltration.

## Impact

Successful exploitation allows authenticated attackers to exfiltrate all incoming form submissions to external or internal attacker-controlled endpoints. This impacts any organization relying on TDuck for private survey data collection, resulting in a complete breach of confidentiality for submitted form data.

## Recommendation

Update TDuck to the latest patched version immediately. Monitor server-side web application logs for unusual POST requests directed toward the WebhookConfigController, specifically tracking associations of new or unknown external webhook URLs to existing forms.
