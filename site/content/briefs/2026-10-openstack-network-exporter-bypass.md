---
title: CVE-2026-83535 Authentication Bypass in OpenStack Network Exporter
slug: 2026-10-openstack-network-exporter-bypass
description: A fail-open vulnerability in openstack-network-exporter allows adjacent network attackers to bypass authentication and exfiltrate sensitive OVS and OVN dataplane metrics when TLS is not properly configured.
date: "2026-10-12T20:32:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openstack:openstack_network_exporter:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-security
  - information-disclosure
vendors:
  - OpenStack
products:
  - openstack-network-exporter
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Consequently, an attacker can enumerate bridge names, port counters, OVN controller state, and host topology, leading to information disclosure.
    confidence_band: high
cves:
  - id: CVE-2026-83535
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83535
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Audit openstack-network-exporter configurations for TLS implementation.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies TLS omission as the root cause of the auth bypass.
  mitigation_plan:
    - priority: immediate
      action: Enable mandatory TLS and restrict network access via ACLs.
      owner: IT Operations
      addresses: CVE-2026-83535
      evidence: Source identifies lack of TLS as the primary vector for exploitation.
---

CVE-2026-83535 is a security vulnerability in the openstack-network-exporter component caused by an insecure fail-open design. When an operator enables user authentication but fails to properly configure or explicitly omits Transport Layer Security (TLS), the authentication mechanism is bypassed silently. This flaw allows attackers on the adjacent network to access highly sensitive dataplane metrics from Open vSwitch (OVS) and Open Virtual Network (OVN) without providing credentials. By querying these endpoints, an unauthorized party can obtain detailed host topology, bridge configurations, active port counters, and internal controller states. This information disclosure provides significant reconnaissance value to an attacker, potentially mapping the internal network structure of a cloud environment to facilitate further exploitation.

## Impact

The vulnerability results in unauthorized information disclosure of critical network infrastructure telemetry. Impacted organizations include those running OpenStack environments where network exporters are deployed. Successful exploitation enables adjacent network attackers to map host topology and OVN controller states, potentially revealing details about the internal architecture and traffic patterns of the cloud environment. There is currently no reported impact on system integrity, but the exposure of configuration data serves as a foundation for further network-based attacks.

## Recommendation

* Immediately audit current openstack-network-exporter deployments to ensure TLS is enforced alongside user authentication.
* Disable the network-exporter until TLS can be verified and implemented if immediate enforcement is not possible.
* Configure host-based firewalls or network access control lists (ACLs) to restrict access to the exporter's listening port to trusted management IPs only.
* Monitor network traffic logs for unauthorized access attempts to the openstack-network-exporter port, looking for requests that do not include valid authentication headers or originate from unexpected subnets.
