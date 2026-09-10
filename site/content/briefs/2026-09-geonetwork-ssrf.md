---
title: Unauthenticated Server-Side Request Forgery in GeoNetwork Web Module
slug: 2026-09-geonetwork-ssrf
description: An unauthenticated server-side request forgery vulnerability (CVE-2026-55864) in the GeoNetwork SLD tool allows attackers to perform unauthorized outbound requests and potentially disclose internal XML data.
date: "2026-09-10T00:51:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:geonetwork-opensource:gn-web-app:*:*:*:*:*:*:*:*
vendors:
  - GeoNetwork
products:
  - gn-web-app (4.4.0 - 4.4.11)
  - gn-web-app (4.0.0 - 4.2.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The SLD tooling endpoint POST /api/tools/ogc/sld takes a caller-supplied WMS server URL and performs a server-side HTTP GET to it, with no validation.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: This enables internal data disclosure... and reconnaissance of the internal network all from an anonymous position.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5hx7-j24v-rffj
  - https://github.com/geonetwork/core-geonetwork/pull/9343
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55864
rules:
  - title: Detects CVE-2026-55864 Exploitation - SSRF via SLD Tooling Endpoint
    description: Detects exploitation of the GeoNetwork SLD tool by identifying unauthenticated POST requests to the /api/tools/ogc/sld endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade gn-web-app to 4.4.12 or 4.2.17
      owner: IT Operations
      due: 48h
      evidence: Source explicitly lists 4.4.12 and 4.2.17 as patched releases
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network traffic from the GeoNetwork application server to only permitted WMS endpoints
      owner: Network Engineering
      addresses: CVE-2026-55864
      evidence: SSRF vulnerability allows arbitrary outbound HTTP requests
---

GeoNetwork version 4.4.0 through 4.4.11 and 4.0.0 through 4.2.16 are affected by an unauthenticated Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-55864. The vulnerability resides in the SLD tooling endpoint located at /api/tools/ogc/sld. This endpoint accepts a WMS server URL parameter from an unauthenticated user and performs a server-side HTTP GET request to the provided destination without validation. 

If the requested resource returns XML content, the application may store and display the output, turning this into a non-blind SSRF. Attackers can leverage this to conduct network reconnaissance against internal infrastructure, interact with internal services that are not publicly exposed, or potentially exfiltrate sensitive information from internal files if they return XML-based responses. This poses a significant risk to internal network segmentation and data confidentiality.

## Impact

The vulnerability allows unauthenticated attackers to probe internal networks, bypass firewall restrictions to access internal services, and exfiltrate internal configuration data or other sensitive resources formatted as XML. This could lead to full internal network reconnaissance and unauthorized data disclosure.

## Recommendation

- Upgrade to GeoNetwork 4.4.12 or 4.2.17 to remediate CVE-2026-55864.
- Implement network egress filtering on the GeoNetwork server to restrict outbound connections to known, trusted WMS server endpoints.
- Deploy detection rules to monitor for unauthorized requests to the /api/tools/ogc/sld endpoint.
