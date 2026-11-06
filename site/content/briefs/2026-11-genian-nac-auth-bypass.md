---
brief_id: brief-2026-11-06-genian-nac-auth-bypass
event_id: brief-2026-11-06-genian-nac-auth-bypass
revision: 1
activity_at: "2026-11-06T02:20:48Z"
title: Genians Genian NAC/ZTNA authentication bypass (CVE-2026-76142)
slug: 2026-11-genian-nac-auth-bypass
description: A critical unauthenticated IPC routing flaw (CVE-2026-76142) in Genian NAC and ZTNA allows remote attackers to perform arbitrary actions, including service disruption and unauthorized email relaying.
date: "2026-11-06T02:20:48Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - MalHyuk
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of web server proxy logs
vendors:
  - Genians
products:
  - Genian NAC (<= 5.0.75 LTS)
  - Genian ZTNA (<= 5.0.75 LTS)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Genian NAC/ZTNA fronts its policy server with an Apache reverse proxy that forwards /gnrpcsvc to the internal centerd process without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-76142
    epss: 0.00333
    kev_status: "false"
references:
  - https://github.com/genians/security-research/security/advisories/GHSA-qf3p-2jpg-3h95
  - https://sploitus.com/exploit?id=E512421A-351C-519E-931E-88C38E69ABA2
  - https://sploitus.com/exploit?id=E512421A-351C-519E-931E-88C38E69ABA2&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-76142 exploitation - Unauthenticated access to gnrpcsvc
    description: Detects potential exploitation of CVE-2026-76142 by identifying requests to the vulnerable gnrpcsvc endpoint via the Apache web server proxy.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Genian NAC/ZTNA to versions > 5.0.75 LTS
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory (GHSA-qf3p-2jpg-3h95)
  hunt_leads:
    - lead: Search web server logs for HTTP requests to /gnrpcsvc/ from non-authorized internal or external IP ranges.
      technique_id: T1190
      data_needed:
        - Apache access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The /gnrpcsvc handler performs arbitrary actions without authentication.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the /gnrpcsvc URI via Apache reverse proxy rules
      owner: IT Operations
      addresses: CVE-2026-76142
      evidence: The proxy configuration currently admits external traffic into the internal IPC trust zone.
---

Genian NAC and ZTNA products contain a critical vulnerability where the internal `gnrpcsvc` SOAP handler, exposed via an Apache reverse proxy, lacks authentication. The service was designed for trusted internal IPC, and the misconfiguration allows unauthenticated external requests to trigger internal functions with elevated authority. The vulnerability was disclosed with a working Proof of Concept (PoC) on 2026-11-05.

## Impact
Successful exploitation allows remote, unauthenticated attackers to perform several high-impact actions:
- Unauthorized email relaying through organizational SMTP infrastructure (impersonation/phishing).
- Service control, including stop/restart commands (denial of service/NAC bypass).
- Disclosure of sensitive information regarding managed nodes.

## Recommendation
- Patch Genian NAC and ZTNA to versions greater than 5.0.75 LTS immediately per the vendor advisory (GHSA-qf3p-2jpg-3h95).
- Review and tighten the Apache reverse proxy configuration to restrict access to the `/gnrpcsvc` URI path, ensuring it is not accessible from external network interfaces.
- Implement internal caller validation within the `centerd` process and associated IPC handlers as a defense-in-depth measure.
