---
title: Juju CloudSpec API Authorization Bypass (CVE-2026-5412)
slug: 2026-04-juju-auth-bypass
description: CVE-2026-5412 describes an authorization issue in Juju versions prior to 2.9.57 and 3.6.21, where a low-privileged authenticated user can call the CloudSpec API method to extract cloud credentials used to bootstrap the controller, leading to sensitive credential exposure.
date: "2026-04-10T13:16:45Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - authorization
  - cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-5412
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5412
rules:
  - title: Detect Juju CloudSpec API Access
    description: Detects unauthorized access to the Juju CloudSpec API endpoint, indicating a potential attempt to exploit CVE-2026-5412.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect Juju API Request with Suspicious User Agent
    description: Detects Juju API requests with unusual user agents, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5412 identifies an authorization bypass vulnerability affecting Juju, an open-source service orchestration tool. Specifically, versions prior to 2.9.57 and 3.6.21 are susceptible. An authenticated user with low privileges can exploit this vulnerability by invoking the CloudSpec API method. This method, intended for controller bootstrapping, inadvertently exposes sensitive cloud credentials when accessed by unauthorized users. Successful exploitation grants access to the credentials used to manage the cloud environment where Juju is deployed. This poses a significant risk, potentially allowing attackers to compromise the entire cloud infrastructure managed by the vulnerable Juju controller. Defenders should prioritize patching vulnerable Juju deployments.

## Attack Chain

1.  Attacker authenticates to the Juju controller with a low-privileged account.
2.  The attacker crafts a malicious API request to the `CloudSpec` method.
3.  The Juju controller, lacking proper authorization checks, processes the request.
4.  The `CloudSpec` method retrieves the cloud credentials used for bootstrapping.
5.  The controller returns the cloud credentials to the attacker.
6.  Attacker obtains the sensitive cloud credentials, such as AWS access keys or Azure service principal secrets.
7.  The attacker uses the stolen cloud credentials to access and control cloud resources.
8.  Attacker achieves complete compromise of the cloud environment.

## Impact

Successful exploitation of CVE-2026-5412 allows a low-privileged, authenticated attacker to steal cloud credentials. This can lead to complete compromise of the cloud infrastructure managed by the vulnerable Juju controller. The impact includes unauthorized access to data, potential data breaches, denial of service, and the ability to deploy malicious workloads within the cloud environment. The severity is heightened by the ease of exploitation and the high value of the exposed cloud credentials.

## Recommendation

*   Upgrade Juju controllers to versions 2.9.57 or 3.6.21 to remediate CVE-2026-5412.
*   Implement the Sigma rule "Detect Juju CloudSpec API Access" to detect unauthorized calls to the CloudSpec API method in Juju environments.
*   Monitor Juju controller logs for suspicious API requests originating from low-privileged accounts.
*   Review and enforce strict access control policies within the cloud environment to limit the impact of compromised credentials.
