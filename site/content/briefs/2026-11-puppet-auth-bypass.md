---
brief_id: brief-2026-11-04-puppet-auth-bypass
event_id: brief-2026-11-04-puppet-auth-bypass
revision: 1
activity_at: "2026-11-04T00:47:08Z"
title: 'Perforce Puppet Server: Authorization bypass in trapperkeeper-authorization (CVE-2026-115732)'
slug: 2026-11-puppet-auth-bypass
description: An authorization bypass vulnerability in the trapperkeeper-authorization component of Puppet Server allows node impersonation and remote command execution via specifically crafted CA-signed certificates. A public exploit is available.
date: "2026-11-04T00:47:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
  source_url: https://sploitus.com/exploit?id=CVE-2026-115732
  confidence: high
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
vendors:
  - Perforce
products:
  - Puppet Server
  - Puppet Enterprise
cves:
  - id: CVE-2026-115732
    kev_status: "false"
references:
  - https://portal.perforce.com/s/cve/a91Qi000003IaJRIA0/certificate-name-authorization-bypass
  - https://sploitus.com/exploit?id=CVE-2026-115732
  - https://sploitus.com/exploit?id=CVE-2026-115732&utm_source=rss&utm_medium=rss
---

CVE-2026-115732 is an authorization bypass vulnerability affecting the trapperkeeper-authorization component used by Puppet Server. A client presenting a CA-signed certificate with a name that extends or shortens an authorized hostname can be incorrectly authorized as that host. 

Successful exploitation enables node impersonation. In Puppet Enterprise, this facilitates unauthorized access to certificate-authority administration and remote command execution on managed nodes. Exploitation requires a certificate with a colliding name, issued by the certificate authority via approval or autosign. A public Proof of Concept (PoC) is available on Sploitus.
