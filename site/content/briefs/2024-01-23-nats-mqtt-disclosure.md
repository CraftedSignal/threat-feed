---
title: NATS Server MQTT Password Disclosure Vulnerability
slug: 2024-01-23-nats-mqtt-disclosure
description: The NATS server exposes MQTT passwords in plaintext via monitoring endpoints due to incorrect classification as JWTs, affecting versions before v2.12.6 or v2.11.15.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nats
  - mqtt
  - credential-access
  - vulnerability
vendors:
  - NATS
products:
  - NATS server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-v722-jcv5-w7mc
rules:
  - title: Detect NATS Server Monitoring Endpoint Access
    description: Detects access to the NATS server monitoring endpoint, which could indicate attempts to exploit the password disclosure vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Detect NATS Server Version < 2.11.15
    description: Detects NATS server running version less than 2.11.15 by checking response headers
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Detect NATS Server Version between 2.12.0-RC.1 and 2.12.6
    description: Detects NATS server running version between 2.12.0-RC.1 and 2.12.6 by checking response headers
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
rules_count: 3
---

NATS.io is a high-performance open-source pub-sub distributed communication technology. The NATS server provides an MQTT client interface. A vulnerability exists where MQTT passwords, when used with usercodes, are incorrectly classified as non-authenticating identity statements (JWT) and exposed via monitoring endpoints. This vulnerability affects NATS server versions before v2.12.6 and v2.11.15. Successful exploitation allows unauthorized access to MQTT credentials, potentially leading to broader access within the NATS environment. Defenders should prioritize patching and securing monitoring endpoints to mitigate this risk. The reported CVE is CVE-2026-33216.

## Attack Chain

1.  Attacker identifies a NATS server instance running a vulnerable version (prior to v2.12.6 or v2.11.15) with MQTT enabled.
2.  MQTT is configured to use usercodes/passwords for authentication.
3.  Attacker accesses the monitoring endpoint of the NATS server. This could be via a direct connection or through a proxy.
4.  The NATS server incorrectly classifies the MQTT password as a non-authenticating JWT.
5.  The server exposes the plaintext MQTT password in the monitoring endpoint's output.
6.  The attacker retrieves the plaintext MQTT password from the monitoring endpoint.
7.  Attacker uses the compromised MQTT credentials to authenticate to the NATS server via the MQTT client interface.
8.  Attacker gains unauthorized access to NATS server resources and pub-sub channels accessible to the compromised MQTT user.

## Impact

Successful exploitation of this vulnerability (CVE-2026-33216) allows an attacker to gain unauthorized access to MQTT credentials. This can lead to the attacker gaining access to sensitive data being transmitted through the NATS pub-sub system. The impact depends on the privileges associated with the compromised MQTT user and the data accessible through the NATS channels it can access. If the monitoring endpoint is exposed to the internet, the risk is significantly increased.

## Recommendation

*   Upgrade NATS server instances to version v2.12.6 or v2.11.15 or later to remediate the vulnerability (CVE-2026-33216).
*   Implement strong access controls on the NATS server monitoring endpoints as suggested in the advisory to prevent unauthorized access.
*   Deploy the Sigma rule `Detect NATS Server Monitoring Endpoint Access` to identify suspicious access attempts to the monitoring endpoint.
