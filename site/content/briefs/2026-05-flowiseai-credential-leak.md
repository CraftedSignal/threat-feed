---
title: FlowiseAI Credential Data Leak via Filtered API Request
slug: 2026-05-flowiseai-credential-leak
description: FlowiseAI versions 3.1.1 and earlier leak encrypted credential data when API requests include a `credentialName` filter, potentially leading to full credential theft if combined with access to the encryption key.
date: "2026-05-14T14:59:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - data-leak
  - web-application
vendors:
  - FlowiseAI
products:
  - flowise (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-7g73-99r4-m4mj
rules:
  - title: Detect FlowiseAI Credential API Leak
    description: Detects attempts to retrieve credentials via the FlowiseAI API with the credentialName filter, potentially exposing encrypted data.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
  - title: Detect FlowiseAI Encryption Key Access
    description: Detects unauthorized access to the FlowiseAI encryption key file, which could be used to decrypt exfiltrated credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - file_event
      - linux
rules_count: 2
---

FlowiseAI, a low-code platform for building AI applications, is vulnerable to a high-severity credential data leak. Versions 3.1.1 and earlier fail to properly sanitize API responses when fetching credentials using a `credentialName` filter. This oversight exposes the `encryptedData` field, which should be omitted to protect sensitive information. An authenticated attacker can exploit this vulnerability to extract encrypted API keys, passwords, and tokens used to access services like OpenAI and AWS. Successful exploitation, coupled with unauthorized access to the `~/.flowise/encryption.key` file, allows for complete credential theft, potentially compromising integrated services and sensitive data. This vulnerability was published on May 14, 2026.

## Attack Chain

1. An attacker gains authenticated access to a FlowiseAI instance.
2. The attacker crafts an API request to the `/api/v1/credentials` endpoint.
3. The request includes the `credentialName` parameter to filter the credentials being fetched, such as `credentialName=openAIApi`.
4. The FlowiseAI server processes the request via `packages/server/src/services/credentials/index.ts`.
5. Due to a flaw in the code at lines 62-63 and 70-71, the `encryptedData` field is not stripped from the API response.
6. The server returns the API response containing the `encryptedData` field, which includes AES-encrypted credentials.
7. If the attacker gains access to the `~/.flowise/encryption.key` file (often written with default permissions), they can decrypt the `encryptedData`.
8. The attacker obtains the plaintext credentials, enabling them to compromise integrated services and data.

## Impact

Successful exploitation of this vulnerability allows authenticated users to steal encrypted credential data from FlowiseAI instances. If the attacker also gains access to the encryption key, this leads to full credential theft, potentially compromising integrated services like OpenAI and AWS. The number of victims is dependent on the number of vulnerable FlowiseAI instances exposed to authenticated attackers. If successful, the attacker could gain unauthorized access to critical cloud services and sensitive data, leading to significant financial and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Detect FlowiseAI Credential API Leak` to identify requests that could be used to exploit this vulnerability by monitoring webserver logs for requests to the `/api/v1/credentials` endpoint with the `credentialName` parameter present in the URL.
*   Upgrade FlowiseAI to a version greater than 3.1.1 to patch the vulnerability as per the information in the advisory.
*   Monitor file access events for unauthorized access to the `~/.flowise/encryption.key` file using the `Detect FlowiseAI Encryption Key Access` Sigma rule to prevent credential decryption after exfiltration.
