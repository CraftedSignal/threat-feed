---
title: Budibase SSRF via Trivial .tar.gz Substring Bypass in Plugin URL Upload
slug: 2026-05-budibase-ssrf
description: Budibase is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation of the plugin URL upload endpoint (`/api/plugin`), which checks for the presence of `.tar.gz` as a substring, enabling attackers to potentially access internal services and sensitive information.
date: "2026-05-11T16:22:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - budibase
  - vulnerability
vendors:
  - Budibase
products:
  - Budibase (Self-Hosted)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xh5j-727m-w6gg
rules:
  - title: Detect Budibase SSRF Attempt via Plugin URL - Direct Access
    description: Detects Budibase SSRF attempts via the plugin URL upload endpoint by checking for requests to internal IP addresses with the `.tar.gz` bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Budibase SSRF Attempt via Plugin URL - Open Redirect
    description: Detects Budibase SSRF attempts via the plugin URL upload endpoint by checking for requests that might involve an open redirect to internal IPs, identified by the presence of `.tar.gz` in the initial URL.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Budibase, a self-hosted low-code platform, is vulnerable to Server-Side Request Forgery (SSRF) in versions 3.34.11 and earlier. The vulnerability resides in the Plugin URL upload endpoint (`/api/plugin`), which utilizes a weak URL validation check that only verifies the presence of the `.tar.gz` substring anywhere in the provided URL. This insufficient validation allows attackers with low privileges (Global Builder role) to bypass intended security measures and potentially access internal services, such as AWS IMDS, CouchDB, and Redis. This is especially critical in deployments where the default SSRF blacklist has been disabled or bypassed, as demonstrated by the BLACKLIST_IPS bypass. Successful exploitation could lead to the disclosure of sensitive information including IAM credentials, application databases, and session tokens.

## Attack Chain

1. An attacker gains access to a Budibase instance with Global Builder privileges.
2. The attacker crafts a malicious URL containing the `.tar.gz` substring, such as `http://169.254.169.254/.tar.gz` to target the AWS IMDS endpoint.
3. The attacker sends a `POST` request to the `/api/plugin` endpoint with the crafted URL in the `url` parameter.
4. The Budibase server-side code checks if the URL includes `.tar.gz`. The malicious URL passes this check.
5. The `downloadUnzipTarball` function attempts to download and unzip the tarball from the provided URL.
6. The `fetchWithBlacklist` function is called to fetch the URL, potentially bypassing the intended SSRF protection.
7. If the blacklist is disabled or bypassed (as with BLACKLIST_IPS="" or a redirect), the request is sent to the attacker-specified internal target.
8. The target system (e.g., AWS IMDS) responds, potentially revealing sensitive information.

## Impact

Successful exploitation of this SSRF vulnerability could lead to the exposure of sensitive data within the internal network. In a chained attack, where the `BLACKLIST_IPS` is empty, attackers can directly access AWS IMDS, CouchDB, and Redis instances, potentially obtaining IAM credentials, application databases, and session tokens. Even with the default blacklist active, attackers might be able to exploit open redirect chains to reach internal IPs. The number of affected instances depends on the prevalence of self-hosted Budibase deployments and the configuration of their SSRF protections.

## Recommendation

*   Deploy the Sigma rule "Detect Budibase SSRF Attempt via Plugin URL - Direct Access" to identify direct access attempts to internal IP addresses via the plugin URL upload (`/api/plugin`) endpoint using the `.tar.gz` bypass.
*   Deploy the Sigma rule "Detect Budibase SSRF Attempt via Plugin URL - Open Redirect" to identify attempts to exploit open redirects to reach internal IPs via the plugin URL upload.
*   Implement the recommended fixes from the advisory, specifically replacing the substring check with proper URL parsing and extension validation, as detailed in the "Recommended Fixes" section of this brief.
*   If you must allow plugin uploads from URLs, implement a hostname allowlist as described in "Fix 3" in the advisory, and restrict plugin URL downloads to explicitly approved domains.
