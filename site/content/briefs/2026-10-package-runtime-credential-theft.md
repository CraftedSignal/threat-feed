---
brief_id: brief-2026-10-24-package-runtime-credential-theft
event_id: brief-2026-10-24-package-runtime-credential-theft
revision: 2
activity_at: "2026-10-26T22:22:10Z"
revision_history:
  - revision: 2
    at: "2026-10-26T22:22:10Z"
    checksum: sha256:d7c78a732826e21934571038be5ba9c589991bd36ac5cd49b820fb67c6fd62b2
    summary: new IOCs
    changed_fields:
      - iocs
      - lastmod
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_secret_file_access_followed_by_imds_request.toml
title: Credential Theft via Package Runtime Secret Access and IMDS Request
slug: 2026-10-package-runtime-credential-theft
description: Credential-stealing malware embedded in compromised software packages uses language runtimes to exfiltrate local developer secrets before querying cloud instance metadata services to hijack cloud workload identities.
date: "2026-10-24T03:34:49Z"
lastmod: "2026-10-26T22:21:25Z"
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
  validation_status: Verified against Elastic detection logic.
tags:
  - supply-chain
  - credential-access
  - imds
  - python
  - nodejs
affected_os:
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Identifies a Python, Node.js, Bun, Deno, Ruby, PHP or Perl runtime, or a binary executing from a package install location, that opens a developer secret.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.004
    subtechnique_name: Private Keys
    evidence: Identifies a Python, Node.js, Bun, Deno, Ruby, PHP or Perl runtime, or a binary executing from a package install location, that opens a developer secret (SSH keys...)
    confidence_band: high
references:
  - https://www.wiz.io/blog/litellm-compromised-steals-credentials
  - https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_secret_file_access_followed_by_imds_request.toml
iocs:
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 169.254.170.2
  - type: ip
    value: 169.254.170.23
  - type: ip
    value: 100.100.100.200
ioc_counts:
  ip: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection logic to monitor interpreter processes accessing sensitive local files followed by network requests to known IMDS endpoints.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rules provided by Elastic.
  hunt_leads:
    - lead: Search for unauthorized network connections from developer interpreters (python, node, ruby) to 169.254.169.254 or related cloud metadata IPs.
      technique_id: T1552
      data_needed:
        - 'Network connection logs (destination IP: 169.254.169.254)'
        - Process creation logs (process name/path)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of IMDS target for credential exfiltration.
updates:
  - at: "2026-10-26T22:21:25Z"
    level: L1
    summary: new IOCs
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_secret_file_access_followed_by_imds_request.toml
---

This threat involves credential-stealing malware delivered through compromised packages (e.g., PyPI, npm) that leverages package runtimes (Python, Node.js, Bun, Deno, Ruby, PHP, or Perl) to access local developer secrets. Following the harvesting of sensitive files such as SSH keys, registry tokens, or AI coding assistant credentials, the malicious process connects to cloud Instance Metadata Service (IMDS) endpoints within one minute to exfiltrate or hijack instance-level credentials. This sequence is characteristic of supply chain attacks where a malicious package is imported, executing its payload during interpreter runtime. Cloud SDKs are excluded from this behavior analysis as they typically read provider-specific credential chains before falling back to IMDS.

## Impact

Successful exploitation results in the exfiltration of sensitive local developer credentials (SSH keys, Git/GitHub/Vault tokens) and the potential hijacking of cloud instance roles, allowing attackers to access cloud resources associated with the victim's identity.

## Recommendation

- Implement monitoring for the access of sensitive credential paths by language interpreters and build-tool runtimes.
- Enforce IMDSv2 with a hop limit of 1 and scope instance IAM roles to least privilege to minimize the impact of credential theft.
- Audit and rotate credentials immediately if suspicious file access followed by IMDS network activity is observed.
- Review environment dependencies for recently updated or suspect package versions in `site-packages`, `node_modules`, or virtual environments.
