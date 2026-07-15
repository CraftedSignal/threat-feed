---
title: Insecure Permission Assignment for Garmin OAuth Token Store
slug: 2026-07-insecure-garminconnect-permissions
description: The `garminconnect` Python library versions 0.3.4 and earlier insecurely assigned world-readable file permissions to the `garmin_tokens.json` OAuth token store, allowing local attackers on multi-user systems to steal refresh tokens and gain persistent, unauthorized access to victims' Garmin Connect accounts.
date: "2026-07-15T17:34:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - insecure-permissions
  - credential-theft
  - local-privilege-escalation
  - vulnerability
products:
  - garminconnect (<= 0.3.4)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: A separate, unprivileged user on the same machine could read the file with a plain `open()` — no elevated privileges required — and extract the refresh token.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
    evidence: The file contains the DI **refresh token**, so any other local user on a shared host could read it and obtain persistent, unauthorized access to the victim's Garmin Connect account.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The stolen refresh token can be exchanged for fresh access tokens via Garmin's OAuth endpoint, granting ongoing access to the victim's account
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Local credential theft / privilege escalation on multi-user Linux or macOS hosts running under a permissive umask.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wjhr-76vg-2hvc
---

The `garminconnect` Python library, specifically versions 0.3.4 and older, contained a critical vulnerability (CVE-2026-54447) related to insecure file permission assignment. When the library created or updated the `garmin_tokens.json` file, which stores sensitive Garmin OAuth refresh tokens, it failed to explicitly set restrictive file permissions. Under common Linux and macOS `umask` settings, this resulted in the `garmin_tokens.json` file being world-readable (0o644). This flaw allowed any unprivileged local user on a multi-user system to read the file, extract the refresh token, and consequently gain persistent, unauthorized access to the victim's Garmin Connect account. This issue was identified and reported by EQSTLab. The vulnerability impacts users who have configured the `garminconnect` library to interact with their Garmin accounts on shared host environments.

## Attack Chain

1. A user installs and configures the `garminconnect` library version 0.3.4 or earlier on a multi-user Linux or macOS system and authenticates with their Garmin Connect account.
2. The `garminconnect` library calls `Client.dump()`, persisting OAuth tokens, including the `di_refresh_token` and `di_client_id`, to the file `~/.garminconnect/garmin_tokens.json`.
3. Due to the `Client.dump()` function not specifying a `mode` argument for file creation, and the system operating under a default umask (e.g., `022`), the `garmin_tokens.json` file is created with world-readable permissions (0o644).
4. A separate, unprivileged local user on the same shared system discovers and reads the `~/.garminconnect/garmin_tokens.json` file, which contains the sensitive OAuth refresh token.
5. The attacker extracts the `di_refresh_token` and `di_client_id` from the world-readable JSON file.
6. The attacker then uses the stolen `di_refresh_token` and `di_client_id` to exchange for fresh access tokens from Garmin's OAuth endpoint, bypassing the need for re-authentication.
7. The attacker uses these valid access tokens to gain unauthorized, persistent access to the victim's Garmin Connect account, enabling access to health data, activity history, and device management features.

## Impact

Successful exploitation of CVE-2026-54447 leads to local credential theft and unauthorized access to victims' Garmin Connect accounts. On multi-user Linux or macOS hosts, any local, unprivileged user can read the `garmin_tokens.json` file, which contains the refresh token. This allows the attacker to obtain persistent access to the victim's Garmin Connect data, including sensitive health and fitness information, activity history, and device management capabilities, until the stolen refresh token is explicitly revoked. The primary risk is unauthorized access to personal data and potential account hijacking.

## Recommendation

* **Upgrade garminconnect**: Immediately upgrade the `garminconnect` library to version 0.3.5 or later to mitigate CVE-2026-54447 by running `pip install --upgrade garminconnect`.
* **Remediate existing files**: Manually set secure permissions for the token store by executing `chmod 700 ~/.garminconnect` and `chmod 600 ~/.garminconnect/garmin_tokens.json` to protect existing `garmin_tokens.json` files.
* **Rotate compromised tokens**: If the `garmin_tokens.json` file was exposed on a shared host, treat the refresh token as compromised. Delete the existing token store (e.g., `rm ~/.garminconnect/garmin_tokens.json`) and log in again using the `garminconnect` library to mint a fresh, securely stored token.
