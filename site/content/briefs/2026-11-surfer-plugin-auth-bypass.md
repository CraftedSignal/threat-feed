---
brief_id: brief-2026-11-07-surfer-plugin-auth-bypass
event_id: brief-2026-11-07-surfer-plugin-auth-bypass
revision: 1
activity_at: "2026-11-07T14:09:32Z"
title: 'Surfer WordPress Plugin: Broken access control (CVE-2026-112222)'
slug: 2026-11-surfer-plugin-auth-bypass
description: A broken access control vulnerability in the Surfer WordPress plugin (CVE-2026-112222) allows authenticated Subscribers to exfiltrate API keys via profile page requests and perform unauthorized REST API actions.
date: "2026-11-07T14:09:32Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of web log fields
cpes:
  - cpe:2.3:a:surferseo:surfer:3.1:*:*:*:*:wordpress:*:*
vendors:
  - Surfer
products:
  - Surfer plugin (3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A broken access control vulnerability in the Surfer plugin allows Subscribers to read the API access key.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: A Subscriber who opens /wp-admin/profile.php?post_type=post gets a page with a wpsurfer JavaScript object that contains the stored wpsurfer_api_access_key option.
    confidence_band: high
cves:
  - id: CVE-2026-112222
    cvss: 5.4
    epss: 0.00168
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=7D645F17-2829-57D7-A3C2-5338B91C7C32
  - https://sploitus.com/exploit?id=7D645F17-2829-57D7-A3C2-5338B91C7C32&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential CVE-2026-112222 Exploitation - Access to Profile Page with post_type Parameter
    description: Detects requests to the WordPress profile page with a post_type parameter, which may indicate an attempt to exploit the Surfer plugin vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for exploitation attempts
      owner: Detection Engineering
      due: 24h
      evidence: PoC demonstrates exploitation via crafted GET requests
  hunt_leads:
    - lead: Review web server logs for requests to /wp-json/surferseo/v1/import_post/ accompanied by anomalous Bearer tokens
      technique_id: T1552.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The PoC demonstrates using the stolen key to authenticate to the REST API route
  mitigation_plan:
    - priority: immediate
      action: Disable the Surfer plugin until a security patch is released by the vendor
      owner: IT Operations
      addresses: CVE-2026-112222
      evidence: Plugin is vulnerable to unauthorized API key exposure
---

The Surfer WordPress plugin is vulnerable to a broken access control issue (CVE-2026-112222) where low-privileged users (Subscribers) can obtain the API access key used for plugin authentication. By visiting the profile page with a crafted `post_type` parameter, the API key is exposed within a rendered JavaScript object. This key can be used as a Bearer token for the plugin’s REST API endpoints.

## Attack Chain

1. Attacker authenticates to the WordPress site as a user with the 'Subscriber' role.
2. Attacker performs a GET request to `/wp-admin/profile.php?post_type=post`.
3. The server renders the profile page including the `wpsurfer` JavaScript object.
4. The object contains the `api_key` property, exposing the `wpsurfer_api_access_key` configuration value.
5. Attacker extracts the key from the HTML response body.
6. Attacker uses the extracted key in a `Bearer` token header to query or post to the `surferseo/v1` REST API endpoints.

## Impact

Successful exploitation allows a low-privileged user to obtain administrative API access, potentially enabling unauthorized modification of site content through the plugin's REST API, such as importing posts.

## Recommendation

- Audit WordPress user accounts to ensure only authorized individuals hold active Subscriber roles.
- Monitor web access logs for anomalous requests to `/wp-admin/profile.php` containing the `post_type` query parameter, especially from user accounts with the Subscriber role.
- Review plugin configurations and monitor the `wpsurfer_api_access_key` for indicators of compromise.
- Apply patches for the Surfer plugin as soon as the vendor makes them available.
