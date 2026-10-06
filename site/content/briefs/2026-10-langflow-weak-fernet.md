---
title: Langflow Insecure Credential Encryption and Key Derivation
slug: 2026-10-langflow-weak-fernet
description: Langflow versions 1.10.0 and earlier use a non-cryptographic PRNG to derive Fernet keys from short SECRET_KEYs, allowing unauthenticated attackers who obtain the secret key file to perform offline decryption of all stored user credentials.
date: "2026-10-06T00:44:45Z"
lastmod: "2026-10-06T00:48:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - vulnerability
  - langflow
vendors:
  - Langflow
products:
  - Langflow (<= 1.10.0)
  - langflow (>= 1.7.2, < 1.10.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker who obtains the SECRET_KEY (e.g., via the MCP path traversal in this repo) can reconstruct the exact Fernet key offline and decrypt every credential stored in the database.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The application uses Python's exec() function to validate user-supplied code; however, it fails to account for Python decorators, which are evaluated at definition time.
    confidence_band: high
cves:
  - id: CVE-2026-9205
    cvss: 7.4
    epss: 0.00417
references:
  - https://github.com/advisories/GHSA-jxw3-mjmx-3pqm
  - https://github.com/langflow-ai/langflow/pull/13704
  - https://github.com/advisories/GHSA-w584-2h2r-2hvf
  - https://github.com/langflow-ai/langflow/pull/13696
rules:
  - title: Detect CVE-2026-51886 Exploitation - Malicious Decorators in Validate Code API
    description: Detects potential exploitation attempts of CVE-2026-51886 by monitoring for malicious Python decorators in requests to the Langflow validation API
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Langflow to version 1.10.1 or later.
      owner: IT Operations
      due: 24h
      evidence: 'Fixed in v1.10.1 by PR #13704.'
    - action: Perform a global rotation of all credentials stored within the Langflow application.
      owner: IT Operations
      due: 48h
      evidence: All stored user credentials are at risk in any Langflow deployment where an attacker can read the secret_key file.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v1.10.1 to address CVE-2026-9205.
      owner: IT Operations
      addresses: CVE-2026-9205
      evidence: 'Fixed in v1.10.1 by PR #13704.'
updates:
  - at: "2026-10-06T00:48:35Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-51886 Exploitation - Malicious Decorators in Validate Code API'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-w584-2h2r-2hvf
---

Langflow versions 1.10.0 and earlier contain a critical cryptographic vulnerability in the handling of Fernet encryption keys used for storing sensitive user credentials, such as LLM API keys and database passwords. The application's `_ensure_valid_key` function incorrectly utilizes Python's non-cryptographic `random` module (Mersenne Twister) seeded with the instance's `SECRET_KEY` when that key is shorter than 32 characters. Because this process is fully deterministic, an attacker who obtains the `secret_key` file can recreate the encryption key offline without brute force. Furthermore, even when the `SECRET_KEY` is 32 characters or longer, the application uses the raw key directly as the Fernet key. This flaw is particularly dangerous when paired with file-read vulnerabilities, such as the MCP path traversal, which allow unauthorized access to the `secret_key` file and the underlying SQLite database. Once these files are exfiltrated, an attacker can decrypt all stored `Credential`-type variables across the entire instance.

## Attack Chain

1. Attacker identifies a target Langflow instance (v1.10.0 or earlier).
2. Attacker leverages an auxiliary vulnerability, such as MCP path traversal (GHSA-95rw-c7w3-xh7f), to bypass access controls.
3. Attacker exfiltrates the configuration file located at `/app/data/.cache/langflow/secret_key`.
4. Attacker exfiltrates the application database file `langflow.db` using the same file-read primitive.
5. Attacker checks the length of the exfiltrated `secret_key` to determine if the PRNG branch or raw-key branch applies.
6. Attacker executes an offline decryption script using the recovered `secret_key` and the extracted ciphertext from the `variable` table.
7. Attacker successfully recovers all stored API keys, database passwords, and OAuth tokens for all users on the instance.

## Impact

Successful exploitation allows for the complete compromise of all stored credentials on a Langflow instance. This includes sensitive third-party API keys (OpenAI, Anthropic), database connection strings, and webhook secrets. In multi-tenant environments, this vulnerability permits a single attacker with low-level privileges to exfiltrate every credential stored by every user on the platform. The decryption process is entirely offline, ensuring the attacker leaves no server-side log traces during the credential recovery phase.

## Recommendation

1. Upgrade Langflow to version 1.10.1 or later immediately to implement secure SHA-256 key derivation and mitigate the weak PRNG issue.
2. Rotate all API keys, database passwords, and other credentials previously stored in any Langflow instance that was running an affected version.
3. Inspect file access logs for unauthorized attempts to read the `/app/data/.cache/langflow/` directory or the `langflow.db` file to identify potential prior exploitation.
4. Ensure that the `SECRET_KEY` is set to a cryptographically secure random string of at least 32 characters to align with updated security requirements.
