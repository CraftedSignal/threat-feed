---
title: AWS Discovery API Calls from VPN ASN for the First Time by Identity
slug: 2026-07-aws-discovery-vpn-asn
description: This threat detection rule identifies initial reconnaissance activities within AWS by flagging an IAM principal's first-time invocation of sensitive discovery APIs, such as GetCallerIdentity, ListUsers, ListBuckets, and DescribeInstances, when the originating IP address is associated with consumer VPNs, high-usage hosting providers, or networks linked to threat groups like TeamPCP, indicating an attacker performing enumeration of cloud resources from a suspicious network origin.
date: "2026-07-15T14:02:20Z"
lastmod: "2026-07-17T08:49:50Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - aws-cloudtrail
  - iam
  - discovery
  - cloud
  - identity
  - threat-detection
vendors:
  - Amazon
  - Amazon Web Services
  - Mullvad VPN AB
  - Tefincom S.A.
  - Nord Security
  - ProtonVPN
  - Proton AG
  - Surfshark Ltd.
  - ExpressVPN
  - Datacamp Limited
  - M247 Ltd
  - The Constant Company
  - Linode LLC
  - Akamai
  - 31173 Services AB
  - Oy Crea Nova Hosting Solution Ltd
  - RETN Limited
  - WorldStream B.V.
products:
  - AWS CloudTrail
  - AWS Identity and Access Management (IAM)
  - Amazon S3
  - Amazon EC2
  - AWS Lambda
  - Amazon RDS
  - Amazon DynamoDB
  - AWS Key Management Service (KMS)
  - AWS Security Token Service (STS)
  - AWS STS
  - AWS IAM
  - AWS KMS
  - Amazon Bedrock
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Flags the first time a given IAM principal invokes a narrow set of high-signal discovery APIs (credential check, account and IAM enumeration, bucket and compute inventory, logging introspection).
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Flags the first time a given IAM principal invokes a narrow set of high-signal discovery APIs (credential check, account and IAM enumeration, bucket and compute inventory, logging introspection).
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://attack.mitre.org/techniques/T1526/
  - https://github.com/bountyyfi/bad-asn-list/blob/main/all.txt
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_new_terms_vpn_asn_discovery_api_calls.toml
iocs:
  - type: asn
    value: "216025"
  - type: asn
    value: "57138"
  - type: asn
    value: "207137"
  - type: asn
    value: "212238"
  - type: asn
    value: "199218"
  - type: asn
    value: "209103"
  - type: asn
    value: "209854"
  - type: asn
    value: "141039"
  - type: asn
    value: "147049"
  - type: asn
    value: "53314"
  - type: asn
    value: "60068"
  - type: asn
    value: "9009"
  - type: asn
    value: "20473"
  - type: asn
    value: "63949"
  - type: asn
    value: "39351"
  - type: asn
    value: "51765"
  - type: asn
    value: "204187"
  - type: asn
    value: "29066"
  - type: asn
    value: "206092"
  - type: asn
    value: "208172"
  - type: asn
    value: "9002"
  - type: asn
    value: "49981"
ioc_counts:
  asn: 22
rules:
  - title: AWS Discovery API Calls from Suspected VPN/Hosting ASN
    description: Detects high-signal AWS discovery API calls (e.g., GetCallerIdentity, ListUsers) from ASNs associated with consumer VPNs, dual-use hosting providers, or networks linked to known threat actors like TeamPCP. This rule flags the combination of suspicious origin and reconnaissance activity.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1526
      - T1580
    data_sources:
      - aws.cloudtrail
rules_count: 1
updates:
  - at: "2026-07-17T08:49:50Z"
    level: L1
    summary: new IOCs
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_new_terms_vpn_asn_discovery_api_calls.toml
---

This brief details detection of suspicious AWS discovery API calls originating from Autonomous System Numbers (ASNs) commonly associated with consumer VPN services, VPN-heavy hosting providers, or networks previously linked to groups such as TeamPCP. The detection flags the *first time* a specific AWS Identity and Access Management (IAM) principal is observed invoking a curated list of high-signal discovery APIs (e.g., `GetCallerIdentity`, `ListUsers`, `ListBuckets`, `DescribeInstances`) from an IP address mapped to one of the identified suspicious ASNs. This activity is indicative of an adversary conducting reconnaissance in an AWS environment, attempting to gather information about account configurations, IAM users, roles, and deployed resources. While some of these ASNs are dual-use (legitimate hosting providers), their association with sensitive API calls from a previously unseen principal, as detected by this rule, suggests potential unauthorized access and enumeration attempts.

## Impact

Successful execution of these discovery activities allows attackers to gain critical insights into the target AWS environment. This reconnaissance can reveal the structure of an organization's cloud infrastructure, identify potential misconfigurations, map out IAM users and their permissions, and locate valuable data stored in S3 buckets or other services. This information is crucial for an attacker to plan subsequent stages of an attack, such as privilege escalation, lateral movement, or data exfiltration. The financial impact can include unauthorized resource usage, data breaches, and regulatory fines. Operational impact can manifest as service disruptions, loss of data integrity, and reputational damage.

## Recommendation

* **Deploy the Sigma rule** in this brief to your SIEM, noting that the "first time" detection is an Elastic-specific feature and the Sigma rule will detect *any* matching event.
* **Monitor AWS CloudTrail logs** for `event.action` values such as `GetCallerIdentity`, `ListUsers`, `ListBuckets`, `DescribeInstances` originating from `source.as.number` values identified in the rule.
* **Review `aws.cloudtrail.user_identity.arn`, `event.action`, and `source.as.number`** for any alerts generated by the rule, comparing against your organization's approved remote access patterns.
* **Implement GeoIP and ASN enrichment** for `source.ip` to ensure `source.as.number` is populated in your AWS CloudTrail logs, enabling this detection.
* **Rotate keys and revoke sessions** for any `aws.cloudtrail.user_identity.access_key_id` found to be associated with suspicious activity.
* **Regularly review and update the list of suspicious ASNs** using resources like BGP.tools, RIPE, or peeringdb, as referenced in the rule's `note`.
