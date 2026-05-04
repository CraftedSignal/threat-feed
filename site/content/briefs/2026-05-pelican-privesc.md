---
title: Pelican Web UI Privilege Escalation Vulnerability
slug: 2026-05-pelican-privesc
description: A privilege escalation vulnerability in Pelican WebUI versions v7.21 to v7.24 allows authenticated users to gain admin privileges by manipulating database records, potentially leading to configuration modification, API token creation, and password changes.
date: "2026-05-04T21:24:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - webui
  - pelican
vendors:
  - Pelican
  - GitHub
products:
  - pelicanplatform/pelican
  - github.com
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-rpfr-x88x-xwcw
  - https://gist.github.com/jhiemstrawisc/8c4b2b3ec5cb2ca06537d9439dc16cc9
iocs:
  - type: url
    value: https://gist.github.com/jhiemstrawisc/8c4b2b3ec5cb2ca06537d9439dc16cc9
ioc_counts:
  url: 1
rules:
  - title: Detect Execution of Mitigation Script
    description: Detects execution of the `mitigate-user-escalation.sh` script used to remediate the Pelican WebUI privilege escalation vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious SQLite Activity Related to Pelican WebUI
    description: Detects SQLite commands potentially indicative of exploitation of the Pelican WebUI privilege escalation vulnerability, focusing on user table modifications.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On April 2nd, 2026, a privilege escalation vulnerability was identified in the Pelican Web User Interface (WebUI) affecting versions v7.21 to v7.24. This vulnerability allows any authenticated user via OAuth to gain admin privileges under specific configurations, including servers with `Server.UIAdminUsers` where listed users haven't logged in or `Server.AdminGroups` with `Issuer.GroupSource` set to `internal` where an admin hasn't logged in. Successful exploitation permits attackers to modify server configurations, create API tokens, and change admin passwords. The OSDF operations team mitigated this vulnerability for core services, but mitigation may be required for other caches and origins. There is currently no evidence this attack has been exploited in services managed by OSDF operators.

## Attack Chain

1. An attacker gains initial access to the Pelican WebUI by authenticating via OIDC.
2. The attacker identifies a valid `Server.UIAdminUsers` username or `Server.AdminGroups` group name for an admin who has not yet logged into the WebUI.
3. The attacker crafts malicious database records designed to grant admin privileges upon subsequent login.
4. The attacker injects these records into the Pelican server's SQLite database, potentially using API endpoints or other methods to interact with the database.
5. The attacker logs out of the WebUI.
6. The attacker logs back into the WebUI.
7. The server grants the attacker admin privileges based on the manipulated database records.
8. The attacker modifies server configurations, creates persistent API tokens, or changes admin passwords.

## Impact

The successful exploitation of this vulnerability poses a significant risk to Pelican servers and the wider federation they support. A compromised Director service could have high federation-wide impact, enabling denial of service and redirection to malicious registries. Registry services also have high federation-wide impact, with attackers potentially poisoning namespaces. Compromised Origins could lead to high data exposure and tampering risks by enabling unauthorized writes and changing export paths. Caches present a medium data exposure risk, as attackers could expose cached protected data.

## Recommendation

*   Run the provided mitigation script (`mitigate-user-escalation.sh` from https://gist.github.com/jhiemstrawisc/8c4b2b3ec5cb2ca06537d9439dc16cc9) to audit the database for signs of exploitation and block further exploitation.
*   Upgrade Pelican servers to a patched release (>=v7.21.5, >=v7.22.3, >=v7.23.3, >=v7.24.2).
*   If unable to upgrade immediately, disable the vulnerable configuration by commenting out `UIAdminUsers` and `AdminGroups` settings in the `pelican.yaml` configuration file.
*   Monitor process executions for the `mitigate-user-escalation.sh` script and review associated user and API token changes. Deploy the provided Sigma rule to detect potential malicious activity.
