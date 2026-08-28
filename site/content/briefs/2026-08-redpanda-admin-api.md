---
title: 'CVE-2026-82266: Unauthenticated Redpanda Admin API Access'
slug: 2026-08-redpanda-admin-api
description: Redpanda versions 26.2.2 and earlier insecurely expose the Admin API on port 9644 by default without authentication enabled, allowing remote attackers to perform superuser actions.
date: "2026-08-28T21:35:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:redpanda:redpanda:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - api-security
vendors:
  - Redpanda
products:
  - Redpanda (<= 26.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can reach port 9644 without credentials to create and delete broker accounts, modify cluster configuration, and disrupt partition replication.
    confidence_band: high
cves:
  - id: CVE-2026-82266
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82266
rules:
  - title: Detect Unauthenticated Redpanda Admin API Requests
    description: Detects unauthorized access attempts to the Redpanda Admin API port 9644. This rule triggers on any connection to the management port from unauthorized network segments.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict network access to port 9644
      owner: IT Operations
      due: 24h
      evidence: Source states Redpanda binds Admin API to 0.0.0.0:9644 by default
  mitigation_plan:
    - priority: immediate
      action: Upgrade Redpanda to version > 26.2.2
      owner: IT Operations
      addresses: CVE-2026-82266
      evidence: Vulnerability affects Redpanda through 26.2.2
---

Redpanda versions 26.2.2 and earlier contain a critical configuration vulnerability where the Admin API is bound to 0.0.0.0:9644 by default, and the `admin_api_require_auth` setting defaults to false. This configuration treats all incoming requests as having superuser privileges. An unauthenticated attacker with network access to the management port can perform sensitive operations, including the creation or deletion of broker accounts, modification of cluster-wide configurations, and the disruption of partition replication. This effectively grants an attacker full administrative control over the Redpanda cluster. Because this is a default behavior in older versions, any cluster exposed to the internet or an untrusted network segment without additional firewall controls is at risk of complete compromise.

## Impact

Successful exploitation grants an attacker full administrative access to the Redpanda cluster. Observed impacts include unauthorized manipulation of cluster state, credential theft or modification of service accounts, and catastrophic data disruption through partition manipulation or service shutdown. This vulnerability poses a severe risk to data integrity and availability in any environment where the management API is reachable from outside a strictly controlled local segment.

## Recommendation

Prioritized actions for security teams:
- Immediately restrict network access to port 9644 to only known, trusted administrative IP addresses using host-based firewalls or network security groups.
- Upgrade all Redpanda deployments to a version greater than 26.2.2 where the default configuration requires authentication.
- Review cluster configuration files to verify that `admin_api_require_auth` is explicitly set to true.
- Audit logs for the Admin API to identify any unauthorized requests originating from unexpected IP addresses.
