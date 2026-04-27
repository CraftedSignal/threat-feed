---
title: SaaS Notification Pipeline Abuse for Phishing and Spam Campaigns
slug: 2026-04-saas-notification-abuse
description: Attackers are abusing notification pipelines in SaaS platforms like GitHub and Jira to deliver phishing and spam emails by exploiting legitimate platform features and bypassing traditional email security measures.
date: "2026-04-07T10:00:35Z"
severities:
  - high
tags:
  - saas-abuse
  - phishing
  - credential-harvesting
  - github
  - jira
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://blog.talosintelligence.com/weaponizing-saas-notification-pipelines/
ioc_counts:
  domain: 3
  email: 1
  ip: 1
rules:
  - title: GitHub Commit Message Phishing Lure
    description: Detects phishing lures in GitHub commit messages used to trigger malicious email notifications.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - mailserver
  - title: Jira Service Desk Invite Abuse
    description: Detects abuse of Jira Service Desk invitation features for phishing by monitoring for specific project names or welcome messages with suspicious URLs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - mailserver
  - title: GitHub SMTP Server Usage
    description: Detects emails originating from GitHub's SMTP server that contain suspicious content or links.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - mailserver
rules_count: 3
---

Cisco Talos has observed a surge in malicious activity that abuses notification pipelines within popular collaboration platforms, such as GitHub and Jira, to distribute spam and phishing emails. This technique, known as Platform-as-a-Proxy (PaaP), enables threat actors to bypass conventional email security filters by leveraging the trusted infrastructure of legitimate SaaS providers. Attackers embed malicious content within system-generated notifications, exploiting the implicit trust…
