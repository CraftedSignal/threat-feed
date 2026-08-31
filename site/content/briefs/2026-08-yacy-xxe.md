---
title: 'CVE-2026-82880: XML External Entity Injection in YaCy Search Server'
slug: 2026-08-yacy-xxe
description: YaCy Search Server through 1.941 is vulnerable to XML external entity (XXE) injection, allowing attackers to exfiltrate local files into the searchable index.
date: "2026-08-31T12:00:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yacy:yacy:*:*:*:*:*:*:*:*
vendors:
  - YaCy
products:
  - YaCy Search Server (<= 1.941)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can publish malicious documents with DOCTYPE declarations containing SYSTEM entities pointing to local files, causing the crawler to exfiltrate file contents into the searchable index.
    confidence_band: high
cves:
  - id: CVE-2026-82880
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82880
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade YaCy Search Server to the latest secure version post-1.941
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82880 vulnerability in versions <= 1.941
  mitigation_plan:
    - priority: immediate
      action: Review search index for unexpected file content indicators
      owner: Security Operations
      addresses: CVE-2026-82880
      evidence: Source describes exfiltration into searchable index
---

YaCy Search Server versions up to 1.941 contain a critical XML external entity (XXE) injection vulnerability. The flaw exists within the application's SVG, FreeMind, and OpenSearch document parsers, which fail to properly disable external entity resolution during processing. An attacker can exploit this by uploading or submitting a crafted malicious document containing a DOCTYPE declaration with a SYSTEM entity that references local files. When the YaCy crawler processes these documents, it interprets the malicious entity, resolves the reference to the local file system, and includes the contents of the targeted files within the search index. This results in the exposure of sensitive local files via the search interface, effectively allowing for unauthorized data access and potential exfiltration.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to arbitrary files on the system hosting the YaCy Search Server. Exposure of sensitive configuration files, credentials, or system data through the searchable index poses a high risk to organizational data confidentiality.

## Recommendation

- Upgrade to a version of YaCy Search Server beyond 1.941 that addresses the insecure XML parser configuration.
- Review the searchable index for suspicious or unexpected file content that may indicate exploitation attempts.
- Apply the principle of least privilege to the account running the YaCy process to limit access to sensitive files on the host system.
