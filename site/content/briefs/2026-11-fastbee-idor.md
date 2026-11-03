---
brief_id: brief-2026-11-03-fastbee-idor
event_id: brief-2026-11-03-fastbee-idor
revision: 1
activity_at: "2026-11-03T18:02:48Z"
title: 'FastBee: Insecure direct object reference in ProductController (CVE-2026-121556)'
slug: 2026-11-fastbee-idor
description: FastBee versions through 2.1.0 contain an insecure direct object reference (IDOR) vulnerability in the ProductController that allows authenticated tenants to access, modify, or delete the resources of other tenants by manipulating product IDs.
date: "2026-11-03T18:02:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified; no atomic exploit provided, thus no Sigma rule included.
cpes:
  - cpe:2.3:a:fastbee:fastbee:*:*:*:*:*:*:*:*
vendors:
  - FastBee
products:
  - FastBee (<= 2.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: authenticated tenant users can... overwrite product configuration including tenant_id
    confidence_band: high
cves:
  - id: CVE-2026-121556
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121556
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all FastBee deployments and identify version 2.1.0 or lower
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-121556 affects FastBee through 2.1.0
  hunt_leads:
    - lead: Hunt for sequential access patterns in ProductController requests
      technique_id: T1068
      data_needed:
        - Web server access logs or application audit logs for ProductController
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can enumerate sequential product IDs to read MQTT account, password, and secret values
  mitigation_plan:
    - priority: immediate
      action: Apply official patches for CVE-2026-121556 once released
      owner: IT Operations
      addresses: CVE-2026-121556
      evidence: NVD advisory for CVE-2026-121556
---

FastBee through version 2.1.0 is affected by an insecure direct object reference (IDOR) vulnerability located in the ProductController. The application fails to properly validate the authorization of authenticated tenant users when accessing specific product resources. By supplying sequential product IDs, a malicious tenant user can access, overwrite configurations (including the tenant_id), or delete products belonging to other tenants. This unauthorized access includes the exposure of sensitive data such as MQTT accounts, passwords, and secret values.

## Impact

Successful exploitation allows authenticated users to achieve unauthorized data disclosure, configuration modification, and data deletion across tenant boundaries. Sensitive information including MQTT credentials and secret keys is exposed, and unauthorized manipulation of tenant configurations can lead to service disruption or cross-tenant data compromise.

## Recommendation

- Identify all instances of FastBee version 2.1.0 or earlier within the environment.
- Review vendor release notes and apply security patches as soon as they are available to remediate CVE-2026-121556.
- Until patching is possible, restrict access to the application to trusted users and implement strict input validation at the web application firewall (WAF) level to monitor for unusual patterns in product ID requests.
- Audit logs for the ProductController to identify anomalous sequences of product ID access by a single tenant user.
