---
title: Information Disclosure in Renovate via Azure DevOps Pipeline Logs
slug: 2026-08-renovate-token-leak
description: Renovate versions 19.180.0 through 23.25.0 insecurely log Git authorization headers when interacting with Azure DevOps, potentially exposing sensitive bot credentials in pipeline logs.
date: "2026-08-19T14:33:06Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - renovatebot
  - Microsoft
products:
  - Renovate (19.180.0-23.25.0)
  - Azure DevOps
cves:
  - id: CVE-2020-37267
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37267
  - https://github.com/renovatebot/renovate/security/advisories/GHSA-36rh-ggpr-j3gj
  - https://www.vulncheck.com/advisories/renovate-before-token-leakage-via-logs
---

Renovate versions 19.180.0 through 23.25.0 contain a vulnerability (CVE-2020-37267) related to sensitive information exposure within execution logs. When the application is configured to interact with Azure DevOps, it utilizes the 'git http.extraheader=AUTHORIZATION' parameter to authenticate repository operations. The application fails to redact this header before writing to server or pipeline logs. Consequently, any actor with read access to the CI/CD pipeline logs or persistent build artifacts can retrieve the authorization tokens used by the Renovate bot. This facilitates unauthorized access to the repositories or services authenticated by the bot's credentials. The issue was addressed in version 23.25.1. Organizations utilizing Renovate with Azure DevOps should audit log storage for exposed tokens and perform credential revocation and rotation if exposure is suspected.

## Impact

Successful exploitation allows unauthorized third parties to gain access to bot credentials stored within log files. This can result in unauthorized code access, repository manipulation, or lateral movement within the development environment depending on the scope and permissions associated with the leaked token.

## Recommendation

- Upgrade Renovate to version 23.25.1 or later immediately to patch CVE-2020-37267.
- Revoke and regenerate all Azure DevOps authorization tokens associated with Renovate bot accounts that have been active in pipeline environments since the deployment of vulnerable versions.
- Audit CI/CD pipeline log access controls to restrict visibility to authorized personnel only.
- Implement log scanning for sensitive patterns in Azure DevOps pipeline logs to identify potential historic exposures.
