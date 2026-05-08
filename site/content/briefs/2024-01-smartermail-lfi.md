---
title: SmarterTools SmarterMail Local File Inclusion Vulnerability (CVE-2026-7807)
slug: 2024-01-smartermail-lfi
description: SmarterTools SmarterMail builds prior to 9560 contain a local file inclusion vulnerability in the /api/v1/report/summary/{type} API endpoint (CVE-2026-7807) that allows authenticated users to read arbitrary .json files, potentially leading to credential compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lfi
  - file-inclusion
  - credential-access
  - smartermail
vendors:
  - SmarterTools
products:
  - SmarterMail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-7807
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7807
rules:
  - title: Detect SmarterMail LFI Attempt
    description: Detects CVE-2026-7807 exploitation attempt — HTTP request to the /api/v1/report/summary endpoint with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SmarterMail JSON File Access via LFI
    description: Detects access to common .json config files via CVE-2026-7807
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

SmarterTools SmarterMail, a widely used mail server software, is vulnerable to a local file inclusion (LFI) flaw tracked as CVE-2026-7807. This vulnerability affects builds prior to 9560. Authenticated users can exploit the vulnerability by crafting specific requests to the `/api/v1/report/summary/{type}` API endpoint, enabling them to read arbitrary `.json` files from the server's file system. Successful exploitation, combined with weak encryption and hardcoded keys, may allow attackers to decrypt and steal stored passwords and 2FA secrets for all users. This poses a significant risk to the confidentiality and integrity of the SmarterMail server and its user accounts.

## Attack Chain

1. An attacker authenticates to the SmarterMail web interface.
2. The attacker crafts a malicious HTTP GET request to the `/api/v1/report/summary/{type}` endpoint.
3. The `{type}` parameter is manipulated to include a path traversal sequence (e.g., `../../../../`) to target a specific `.json` file outside the intended directory.
4. The SmarterMail server processes the request without proper input validation, allowing the attacker to read the contents of the specified `.json` file.
5. The attacker targets `.json` files containing sensitive information, such as configuration files or password stores.
6. The attacker leverages weak encryption algorithms and hardcoded keys (if present) to decrypt the contents of the stolen `.json` files.
7. The attacker extracts user credentials, including passwords and 2FA secrets, from the decrypted data.
8. The attacker uses the stolen credentials to compromise user accounts and gain unauthorized access to sensitive data.

## Impact

Successful exploitation of CVE-2026-7807 can lead to the complete compromise of a SmarterMail server. Attackers can steal user credentials, including passwords and 2FA secrets, potentially impacting all users on the system. This access enables attackers to read sensitive emails, send malicious emails, and potentially pivot to other systems on the network. The impact includes data breaches, financial loss, and reputational damage.

## Recommendation

*   Upgrade SmarterMail to build 9560 or later to patch CVE-2026-7807 (reference: overview).
*   Implement the Sigma rule `Detect SmarterMail LFI Attempt` to detect exploitation attempts against the `/api/v1/report/summary/{type}` endpoint (reference: rules).
*   Monitor web server logs for suspicious requests containing path traversal sequences in the `/api/v1/report/summary/{type}` endpoint (reference: rules logsource).
