---
brief_id: brief-2026-10-27-onyx-craft-xss
event_id: brief-2026-10-27-onyx-craft-xss
revision: 1
activity_at: "2026-10-27T01:09:20Z"
title: 'Onyx Craft: Stored Cross-Site Scripting via iframe sandbox bypass (CVE-2026-116004)'
slug: 2026-10-onyx-craft-xss
description: Onyx Craft versions through 5.0.0 contain a stored Cross-Site Scripting vulnerability in the output preview panel caused by insecure iframe sandbox configuration, allowing malicious preview content to access the parent document DOM.
date: "2026-10-27T01:09:20Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - cpe:2.3:a:onyx:craft:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - cve-2026-116004
vendors:
  - Onyx
products:
  - Onyx Craft (<= 5.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An iframe sandbox starts as a locked room. Each sandbox token opens one capability. allow-scripts lets code run. allow-same-origin gives the document its real origin instead of an isolated opaque origin.
    confidence_band: high
cves:
  - id: CVE-2026-116004
    cvss: 3.5
    epss: 0.00199
    kev_status: "false"
references:
  - https://vulners.com/cve/CVE-2026-116004
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116004
  - https://github.com/onyx-dot-app/onyx/blob/711a0479f1630dcce38f8f58212a63080702b753/web/src/app/craft/components/output-panel/PreviewTab.tsx
  - https://sploitus.com/exploit?id=811587BD-D24F-5F13-8E83-AD8B36E24DE8&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit current Onyx Craft deployments for usage of the vulnerable output preview component.
      owner: SOC
      due: 48h
      evidence: Vulnerability in craft output preview component documented in source.
  hunt_leads:
    - lead: Identify abnormal DOM modification events or script errors originating from iframe elements within the Onyx Craft application context.
      technique_id: T1190
      data_needed:
        - Browser console logs
        - Application performance monitoring (APM) telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'The dangerous condition is the combination of three facts: attacker-controlled preview content + iframe can execute scripts + iframe keeps its real origin.'
  mitigation_plan:
    - priority: immediate
      action: Serve generated previews from a dedicated origin with no shared cookies or application privileges.
      owner: IT Operations
      addresses: CVE-2026-116004
      evidence: Remediation section in the provided vulnerability report.
---

Onyx Craft versions up to and including 5.0.0 are vulnerable to stored Cross-Site Scripting (XSS) due to an unsafe iframe sandbox configuration within the craft output preview component. The component uses both `allow-scripts` and `allow-same-origin` attributes in the iframe sandbox. When the parent application and the rendered preview share the same origin, this combination permits framed JavaScript to bypass sandbox restrictions and modify the parent document's DOM. This vulnerability is tracked as CVE-2026-116004.

## Impact
Successful exploitation allows an attacker to execute arbitrary JavaScript within the context of the parent application when a victim views attacker-controlled preview content. This can lead to unauthorized modification of the parent document, potential session hijacking, or data theft, depending on the privileges and sensitive information present in the parent application context.

## Recommendation
- Upgrade Onyx Craft to a patched version once released.
- Implement a dedicated, isolated origin (subdomain) to serve generated preview content, ensuring it does not share cookies or application privileges with the main application.
- Remove the `allow-same-origin` flag from iframe sandbox configurations where application requirements permit.
- Apply a restrictive Content Security Policy (CSP) to preview content.
- Implement browser regression tests to assert that preview content cannot access or modify the parent DOM.
