---
brief_id: brief-2026-10-26-vmware-tanzu-vulnerabilities
event_id: brief-2026-10-26-vmware-tanzu-vulnerabilities
revision: 1
activity_at: "2026-10-26T22:20:43Z"
title: 'VMware Tanzu Platform and Associated Components: Multiple Vulnerabilities'
slug: 2026-10-vmware-tanzu-vulnerabilities
description: Multiple vulnerabilities discovered in various VMware Tanzu Platform components, including API Gateway, Tanzu Hub, and associated buildpacks, require urgent review of Broadcom security advisories for remediation.
date: "2026-10-26T22:20:43Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - cloud
  - infrastructure
vendors:
  - VMware
products:
  - API Gateway for VMware Tanzu Platform (< 2.4.10)
  - Platform Services for VMware Tanzu Platform (10.x < 10.4.6)
  - Platform Services for VMware Tanzu Platform (< 11.0.0)
  - Ruby Buildpack (< 1.10.95)
  - Service Publisher for VMware Tanzu Platform (< 10.4.6)
  - Staticfile Buildpack (< 1.6.103)
  - Stemcells for Ubuntu Jammy Azure Light (< 1.9041.x)
  - Stemcells for Ubuntu Jammy FIPS (< 1.9041.x)
  - Stemcells for Ubuntu Resolute (< 1.0.x)
  - Stemcells for Windows (2019.x < 2019.104.x)
  - Stemcells for Windows (2022.x < 2022.8.x)
  - Tanzu GemFire on Tanzu Platform (< 11.0.0)
  - Tanzu Hub (< 10.4.6)
  - Tanzu Hub (< 11.0.0)
  - Tanzu Kubernetes Grid Integrated Edition - Mgmt Console (< 1.26.3)
  - Tanzu for Postgres on Tanzu Platform (< 11.0.0)
affected_os:
  - Ubuntu
  - Windows Server 2019
  - Windows Server 2022
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1385/
  - https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39354
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Perform an inventory of all VMware Tanzu and Stemcell deployments against the affected version list provided in the ANSSI and Broadcom advisories.
      owner: IT Operations
      due: 24h
      evidence: Source provides a comprehensive list of affected products and version ranges.
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected components to the versions specified in the respective Broadcom Security Advisories.
      owner: IT Operations
      addresses: All affected VMware Tanzu products listed in the brief.
      evidence: Source instructs to refer to the editor's security bulletins for patches.
---

The French CERT (ANSSI) has published an advisory regarding numerous security vulnerabilities identified across multiple VMware Tanzu Platform products and related components, including buildpacks and stemcells. The vulnerabilities affect a wide range of versions, and the vendor has provided specific security advisories for each component. As of the time of reporting, the specific security impact remains undisclosed by the vendor. Organizations are directed to the official Broadcom security advisory portal to identify the specific risk levels and remediation paths for their environments.

## Recommendation

- Inventory all deployed VMware Tanzu Platform components, including buildpacks and stemcells, to determine if they fall within the affected version ranges identified by the Broadcom advisories.
- Apply the vendor-provided security patches referenced in the official Broadcom documentation for each affected component immediately.
- Monitor the Broadcom Support portal for any additional updates or clarifications regarding the nature of these vulnerabilities as more technical details become available.
