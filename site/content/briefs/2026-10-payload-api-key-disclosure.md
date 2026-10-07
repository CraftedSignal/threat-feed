---
title: Payload API Key Disclosure via Document Read Access
slug: 2026-10-payload-api-key-disclosure
description: A vulnerability in Payload CMS versions 3.x and 4.x-canary allows unauthorized users with document read permissions to access active API keys stored within authentication collections.
date: "2026-10-06T18:47:38Z"
lastmod: "2026-10-07T22:50:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:payloadcms:payload:*:*:*:*:*:node.js:*:*
tags:
  - information-disclosure
  - cms
  - authentication
  - web-application
  - cve-2026-105847
  - web-vulnerability
  - access-control
  - sqli
  - vulnerability
  - high-confidence-source
  - remote-code-execution
  - web-application-vulnerability
  - session-hijacking
  - credential-theft
  - cve-2026-105861
  - xss
  - web-security
  - file-deletion
  - path-traversal
  - content-management-system
vendors:
  - Payload
products:
  - payload (>= 3.0.0 < 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)
  - Payload (>= 3.0.0, < 3.90.0)
  - Payload (>= 4.0.0-canary.0, < 4.0.0-canary.34)
  - Payload (3.0.0 - 3.89.9)
  - Payload (4.0.0-canary.0 - 4.0.0-canary.33)
  - Payload (3.0.0 <= version < 3.88.0, 4.0.0-canary.0 <= version < 4.0.0-canary.27)
  - Payload (v3.x < 3.87.0)
  - Payload (v4.0.0-canary < 4.0.0-canary.20)
  - Payload (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)
  - Payload (v3.0.0 to <3.90.0)
  - Payload (v4.0.0-canary.0 to <4.0.0-canary.34)
  - Payload (< 3.90.0)
  - Payload (< 3.90.0, >= 4.0.0-canary.0, < 4.0.0-canary.34)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Users with read access to other user documents could access their active API keys.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Token refresh and password reset responses could return fields that the requesting user did not have access to.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A user with query access could use polymorphic join filters to infer hidden or read-restricted field values, including password-reset tokens.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The duplicate operation copies field values from the source document even when a field is hidden, or its access.read or access.create rule would reject the value for that caller.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A user can submit a request that exploits a SQL Injection vulnerability in Payload.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.003
    technique_name: Use Alternate Authentication Material
    evidence: An attacker could potentially influence the claims within a JWT or similar token, leading to improper authentication or authorization bypass.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: Under certain external upload configurations, Payload could send authentication data to a destination that was not verified as trusted.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: A malicious SVG file upload could bypass sanitization, be stored, and execute attacker-controlled JavaScript (XSS)
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An uploaded XML file and stylesheet could execute JavaScript in the Payload origin when a logged-in user opens the file.
    confidence_band: high
cves:
  - id: CVE-2026-105849
references:
  - https://github.com/advisories/GHSA-238x-w2j9-gwwr
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105849
  - https://github.com/advisories/GHSA-xgv3-crq2-6f69
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105853
  - https://github.com/advisories/GHSA-fpww-c55p-cjv6
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105847
  - https://github.com/advisories/GHSA-vc4h-q48j-5hcx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105851
  - https://github.com/advisories/GHSA-v49j-62m6-pgrr
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105845
  - https://github.com/advisories/GHSA-4ww4-68q3-h7g5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106100
  - https://github.com/advisories/GHSA-f7hx-52q9-hcrf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105859
  - https://github.com/advisories/GHSA-66wr-7vmr-p5jq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105863
  - https://github.com/advisories/GHSA-97rh-rhh2-7vjv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105858
  - https://github.com/advisories/GHSA-pj5h-5q6c-3pfx
  - https://github.com/advisories/GHSA-2pwp-2369-8fg3
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105862
  - https://github.com/advisories/GHSA-p223-2wr2-j562
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105865
  - https://github.com/advisories/GHSA-9qpg-3cf8-w33x
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105868
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade Payload CMS to 3.90.0 or 4.0.0-canary.34
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies these versions for remediation of CVE-2026-105849
  mitigation_plan:
    - priority: immediate
      action: Rotate all API keys generated under affected versions
      owner: Security Team
      addresses: CVE-2026-105849
      evidence: Source recommends rotating any API key that may have been exposed
updates:
  - at: "2026-10-07T22:49:26Z"
    level: L2
    summary: added coverage for Payload (< 3.90.0) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-97rh-rhh2-7vjv
  - at: "2026-10-07T22:49:42Z"
    level: L2
    summary: added coverage for Payload (>= 3.0.0, < 3.90.0) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-pj5h-5q6c-3pfx
  - at: "2026-10-07T22:49:50Z"
    level: L2
    summary: added coverage for Payload (< 3.90.0, >= 4.0.0-canary.0, < 4.0.0-canary.34)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2pwp-2369-8fg3
  - at: "2026-10-07T22:49:58Z"
    level: L2
    summary: added coverage for Payload (< 3.90.0) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-p223-2wr2-j562
  - at: "2026-10-07T22:50:22Z"
    level: L2
    summary: added coverage for Payload (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9qpg-3cf8-w33x
---

Payload CMS versions prior to 3.90.0 and 4.0.0-canary.34 are vulnerable to an API key disclosure flaw, tracked as CVE-2026-105849. This vulnerability manifests in deployments where the `useAPIKey` authentication feature is enabled. Due to insecure access control logic, users who possess read access to documents within an authentication collection can view sensitive API keys belonging to other users. Because these keys hold the permissions of the target account, successful exploitation allows an attacker to masquerade as the compromised user until the key is rotated or disabled. This impacts organizations relying on Payload for authentication and document management, particularly those with permissive document access policies.

## Impact

Successful exploitation allows unauthorized users to retrieve valid API keys of other users, leading to account takeover. The impact is significant for applications where API keys manage sensitive operations or provide access to protected administrative functions. Users must immediately verify document read permissions and rotate any keys potentially exposed during the window of vulnerability.

## Recommendation

* Upgrade Payload CMS to version 3.90.0 or 4.0.0-canary.34 to patch CVE-2026-105849.
* Audit document read permissions in the CMS and restrict access to authentication collections to authorized users only.
* Disable the `useAPIKey` feature if not strictly required for application functionality.
* Perform a mandatory rotation of all active API keys generated while the affected versions were in use to mitigate potential unauthorized access.
