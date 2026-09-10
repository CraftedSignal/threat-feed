---
title: Credential Disclosure in Renovate via Malicious Pagination Links
slug: 2026-09-renovate-credential-leak
description: Renovate improperly validates HTTP 'Link' headers during GitHub API interactions, allowing a compromised GitHub server to exfiltrate configured credentials by redirecting pagination requests to an attacker-controlled host.
date: "2026-09-10T15:14:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mend:renovate:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - supply-chain
  - vulnerability
vendors:
  - Mend
products:
  - Renovate (< 44.11.3)
  - Mend Renovate CE/EE (< 15.4.0)
  - Mend Renovate Enterprise Edition (< 10.4.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Renovate sends the credentials configured for that host to the URL given as the 'next' page.
    confidence_band: high
cves:
  - id: CVE-2026-88881
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88881
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Renovate to 44.11.3 or later
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in renovate 44.11.3, Mend Renovate CE/EE 15.4.0, and mend-renovate-enterprise-edition 10.4.0.
  mitigation_plan:
    - priority: immediate
      action: Remove RENOVATE_X_REBASE_PAGINATION_LINKS configuration.
      owner: Security Engineering
      addresses: CVE-2026-88881
      evidence: The pre-existing RENOVATE_X_REBASE_PAGINATION_LINKS option disables the new host check.
---

Renovate, a widely used dependency update tool, contains a vulnerability (CVE-2026-88881) where it fails to validate the hostname of pagination links provided in HTTP 'Link' headers when interacting with GitHub-compatible servers. Under normal operation, Renovate follows 'next' page links provided by the server to traverse API results. However, if a GitHub-compatible server (repository host or datasource) is compromised or controlled by an attacker, it can supply a 'next' link pointing to an arbitrary, attacker-controlled domain. Renovate will subsequently send its configured credentials for the original host to this malicious destination. This impacts organizations using Renovate versions prior to 44.11.3, as well as Mend Renovate CE/EE and Enterprise Edition versions 15.4.0 and 10.4.0 respectively. There is no configuration-based workaround; the existing RENOVATE_X_REBASE_PAGINATION_LINKS option serves to disable the new host check and should not be used as a mitigation.

## Impact

The vulnerability poses a high risk of credential theft, specifically targeting the tokens or credentials configured within the Renovate instance to authenticate against GitHub or GitHub-compatible infrastructure. If exploited, an attacker could capture these credentials and leverage them to access private repositories, modify code, or perform unauthorized administrative actions within the victim's GitHub environment. This affects all sectors relying on automated dependency management through Renovate.

## Recommendation

1. Upgrade Renovate npm package and container images to 44.11.3 or later immediately.
2. Upgrade Mend Renovate CE/EE helm chart to 15.4.0 or later.
3. Upgrade Mend Renovate Enterprise Edition helm chart to 10.4.0 or later.
4. Review access logs and outbound network traffic originating from Renovate runners for connections to unexpected or unauthorized domains following GitHub API interactions.
5. Ensure that the RENOVATE_X_REBASE_PAGINATION_LINKS environment variable is not set to true, as it explicitly disables host validation.
