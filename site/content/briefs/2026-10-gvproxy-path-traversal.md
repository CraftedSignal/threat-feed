---
title: Arbitrary File Deletion via Path Traversal in gvproxy
slug: 2026-10-gvproxy-path-traversal
description: An unauthenticated path traversal vulnerability in the gvproxy component of gvisor-tap-vsock allows attackers to delete arbitrary files on the host filesystem via the /services/forwarder/expose endpoint.
date: "2026-10-09T13:22:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:gvisor-tap-vsock:gvisor-tap-vsock:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - rce-prevention
products:
  - gvproxy (gvisor-tap-vsock)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The unauthenticated /services/forwarder/expose endpoint does not validate the caller-supplied socket path, allowing an attacker to delete arbitrary files on the host system.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The unauthenticated /services/forwarder/expose endpoint does not validate the caller-supplied socket path, allowing an attacker to delete arbitrary files on the host system.
    confidence_band: high
cves:
  - id: CVE-2026-107935
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107935
rules:
  - title: Detect CVE-2026-107935 Exploitation - Path Traversal in gvproxy
    description: Detects potential exploitation attempts of CVE-2026-107935 by monitoring for suspicious path traversal patterns in the socket path parameter of the /services/forwarder/expose endpoint.
    platform: sigma
    severity: critical
    tactics:
      - impact
      - initial_access
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Deploy Sigma detection rule to web server logs
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-107935 exploitation detection
  mitigation_plan:
    - priority: immediate
      action: Identify and restrict access to the /services/forwarder/expose endpoint
      owner: IT Operations
      addresses: CVE-2026-107935
      evidence: Source reporting of unauthenticated endpoint
---

CVE-2026-107935 is a critical path traversal vulnerability residing in gvproxy, which serves as a network forwarder within the gvisor-tap-vsock package. The flaw exists due to insufficient input validation on the /services/forwarder/expose API endpoint. By submitting a crafted request containing a malicious socket path, an unauthenticated attacker can manipulate the application to perform file operations outside of the intended directory. Because the application interacts directly with the host system, this lack of path sanitization allows an attacker to trigger the deletion of arbitrary files on the host filesystem. This vulnerability poses a significant risk to the integrity of systems utilizing gvproxy, particularly in containerized or virtualized environments where host-level access is highly sensitive. Defenders should prioritize auditing web-based logs for suspicious POST requests to the affected endpoint and identify deployments of gvisor-tap-vsock to prepare for patching.

## Impact

Successful exploitation of this vulnerability results in arbitrary file deletion on the host operating system. This can lead to system instability, service disruption, or the removal of sensitive configuration files and security-critical binaries. Any environment utilizing the gvisor-tap-vsock stack for network forwarding is potentially at risk of host-level impact if the gvproxy service is exposed to an untrusted network.

## Recommendation

* Monitor webserver and proxy logs for incoming requests targeting the /services/forwarder/expose URI to identify potential exploitation attempts.
* Audit environments to locate instances of gvisor-tap-vsock and gvproxy.
* Apply patches immediately upon release by the maintainers of the gvisor-tap-vsock package.
* Ensure that the gvproxy endpoint is restricted to authorized internal traffic only, preventing unauthenticated access from untrusted sources.
