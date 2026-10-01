---
title: Authorization Vulnerabilities in Meari IoT Cloud Platform OpenAPI Service
slug: 2026-10-meari-iot-auth-flaws
description: Multiple missing authorization vulnerabilities in the Meari IoT Cloud Platform OpenAPI Service allow authenticated users to access sensitive device data and manipulate configurations for unauthorized devices.
date: "2026-10-01T17:06:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - iot
  - vulnerability
  - cloud
  - authorization
vendors:
  - Meari
products:
  - Meari IoT Cloud Platform OpenAPI Service (all versions)
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-06
  - https://www.cve.org/CVERecord?id=CVE-2026-101104
  - https://www.cve.org/CVERecord?id=CVE-2026-96613
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate Meari IoT Cloud Platform endpoints from public internet access
      owner: IT Operations
      due: 24h
      evidence: CISA recommendation to minimize network exposure
  mitigation_plan:
    - priority: immediate
      action: Place affected devices behind firewalls and VPNs
      owner: IT Operations
      addresses: CVE-2026-101104, CVE-2026-96613
      evidence: CISA recommended practices
---

The Meari IoT Cloud Platform OpenAPI Service suffers from critical authorization flaws, identified as CVE-2026-101104 and CVE-2026-96613. Both vulnerabilities stem from improper enforcement of authorization checks (CWE-862). Authenticated users can interact with API endpoints to access the complete device shadow - including credentials, owner details, and telemetry data - for any device by simply specifying its device ID. Furthermore, these flaws permit unauthorized manipulation of device configurations and the triggering of unintended device behaviors. The vulnerabilities affect all versions of the service, and Meari has not provided a remediation plan. Organizations relying on this platform face risks of unauthorized device control and sensitive data exposure, necessitating strict network access controls to mitigate the impact of these unpatchable service vulnerabilities.

## Impact

Successful exploitation could lead to unauthorized access to sensitive information including device credentials, network telemetry, and owner data. Additionally, attackers can manipulate device settings, leading to potential service disruption or unauthorized control of IoT assets across commercial and IT sectors globally.

## Recommendation

- Immediately restrict access to the Meari IoT Cloud Platform OpenAPI Service by placing all affected control system networks behind robust firewalls to prevent unauthorized external access.
- Enforce strict perimeter security and isolate control system networks from general business network traffic.
- Mandate the use of secure remote access methods such as VPNs for authorized users, while performing regular audits of VPN integrity and connection policies.
- Conduct an impact assessment to identify all business processes reliant on the Meari IoT Cloud Platform and evaluate alternative, more secure service providers given the lack of planned patches for these vulnerabilities.
