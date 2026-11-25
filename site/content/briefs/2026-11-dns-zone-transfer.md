---
brief_id: brief-2026-11-25-dns-zone-transfer
event_id: brief-2026-11-25-dns-zone-transfer
revision: 1
activity_at: "2026-11-25T16:21:36Z"
title: DNS Server Zone Transfer Failure
slug: 2026-11-dns-zone-transfer
description: The Windows DNS Server service generates Event ID 6004 when it receives a zone transfer request for a zone it does not host or for which it is not authoritative.
date: "2026-11-25T16:21:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - reconnaissance
  - dns
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: Gather Victim Network Information
    subtechnique_id: T1590.002
    subtechnique_name: DNS
    evidence: The DNS server received a zone transfer request from %1 for a non-existent or non-authoritative zone %2.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_server/win_dns_server_failed_dns_zone_transfer.yml
  - https://web.archive.org/web/20231017043746/https://kb.eventtracker.com/evtpass/evtpages/EventId_6004_Microsoft-Windows-DNS-Server-Service_65410.asp
rules:
  - title: Failed DNS Zone Transfer
    description: Detects when the DNS server receives a zone transfer request for a non-existent or non-authoritative zone.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1590.002
    data_sources:
      - windows
      - dns-server
rules_count: 1
---

## Overview

The Windows DNS Server service records Event ID 6004 when a request for a zone transfer is received by the server for a zone that is either non-existent or for which the server is not authoritative.

## Attack Chain

This event indicates an attempt to initiate a zone transfer (AXFR) against a DNS server.

## Impact

Unauthorized zone transfer requests may be logged by the DNS Server service.

## Recommendation

Monitor DNS Server logs for the occurrence of Event ID 6004.
