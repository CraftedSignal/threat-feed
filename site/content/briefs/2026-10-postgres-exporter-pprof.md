---
title: Information Disclosure via Exposed net/http/pprof in postgres-exporter
slug: 2026-10-postgres-exporter-pprof
description: An unauthenticated exposure of Go pprof debug endpoints in postgres-exporter allows remote attackers to perform information disclosure of credentials and process memory or trigger a denial of service.
date: "2026-10-06T20:57:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:prometheus-community:postgres-exporter:*:*:*:*:*:*:*:*
vendors:
  - prometheus-community
products:
  - postgres-exporter
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: This allows for information disclosure, potentially revealing process arguments, full goroutine stacks, and sensitive data like database connection strings or passwords from heap dumps.
    confidence_band: high
cves:
  - id: CVE-2026-83550
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83550
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict network access to postgres-exporter metrics port via NetworkPolicies
      owner: IT Operations
      due: 24h
      evidence: Source notes vulnerability is accessible to remote attackers within the cluster network
  mitigation_plan:
    - priority: immediate
      action: Upgrade postgres-exporter to a patched version once released
      owner: IT Operations
      addresses: CVE-2026-83550
      evidence: Source identifies CVE-2026-83550 as the vulnerability ID
---

The postgres-exporter software contains a vulnerability (CVE-2026-83550) stemming from the blank import of the 'net/http/pprof' package. This unintended inclusion exposes Go debug endpoints on the default metrics listener port without requiring authentication. Any attacker with network access to the postgres-exporter instance - typically within a Kubernetes pod network or cluster environment - can query these endpoints to retrieve sensitive runtime data.

The exposed information includes process arguments, full goroutine stacks, and memory content, which may contain hardcoded database connection strings, credentials, or sensitive application data extracted via heap dumps. Furthermore, an attacker can intentionally initiate CPU profiling tasks, leading to resource exhaustion and denial of service. The impact is significant for environments where internal cluster traffic is not strictly partitioned or where the metrics port is exposed to wider network segments.

## Impact

Successful exploitation leads to unauthorized information disclosure, potentially resulting in the compromise of database credentials or internal system configuration details. Additionally, the vulnerability permits denial of service attacks against the exporter, which can disrupt monitoring pipelines and impact observability of the associated PostgreSQL instances.

## Recommendation

- Audit network ingress policies for all pods running postgres-exporter to ensure the metrics port is not exposed to untrusted network segments.
- Upgrade the postgres-exporter deployment to a version where 'net/http/pprof' has been removed from the build.
- Implement network-level access control, such as Kubernetes NetworkPolicies, to restrict access to the metrics port to known monitoring server IPs only.
- Scan memory-resident secrets and configuration to ensure that the risk of credential leakage via heap dumps is mitigated by rotating any potentially exposed database passwords.
