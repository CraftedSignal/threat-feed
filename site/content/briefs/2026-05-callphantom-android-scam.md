---
title: CallPhantom Android Apps Falsely Promise Call History for Payment
slug: 2026-05-callphantom-android-scam
description: ESET researchers discovered 28 fraudulent Android apps, named CallPhantom, on Google Play that falsely claim to provide call logs for any phone number in exchange for payment, generating random data or requesting email addresses and amassing over 7.3 million downloads before being removed.
date: "2026-05-07T08:51:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - android
  - scam
  - callphantom
  - fraud
vendors:
  - Google
products:
  - Google Play
affected_os:
  - Android
references:
  - https://www.welivesecurity.com/en/eset-research/fake-call-logs-real-payments-how-callphantom-tricks-android-users/
rules:
  - title: Detect CallPhantom Fake Call History App
    description: Detects CallPhantom applications generating random contact names and numbers
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - process_creation
      - android
  - title: Detect CallPhantom Deceptive Email Notification
    description: Detects CallPhantom apps displaying notifications styled as emails to persuade users to subscribe.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - process_creation
      - android
rules_count: 2
---

ESET researchers uncovered 28 fraudulent Android apps on Google Play, collectively named CallPhantom, that falsely claim to provide call logs, SMS records, and WhatsApp call history for any phone number. These apps, promising access to private information, garnered over 7.3 million downloads before being removed from the Google Play store on December 16, 2025. CallPhantom apps primarily targeted Android users in India and the broader Asia-Pacific region, often preselecting India’s +91 country code and supporting UPI payment systems. The apps aimed to exploit users' curiosity by offering insight into private information.

## Attack Chain

1.  Users search for call history apps on the Google Play store.
2.  Users download a CallPhantom app, enticed by seemingly functional screenshots and descriptions.
3.  The app requests payment or subscription to unlock access to call history data.
4.  Users pay via Google Play's billing system, third-party UPI apps, or directly via payment card forms within the app.
5.  The app generates random phone numbers, names, call times, and durations or requests an email address.
6.  The app presents fake call history data or promises to send call history data to the provided email address.
7.  Users discover that the data is fabricated and that they have been scammed.
8.  Victims leave negative reviews on the Google Play store.

## Impact

The CallPhantom apps, downloaded over 7.3 million times, scammed Android users by charging them for fabricated call history data. Victims paid for subscriptions ranging up to US$80, receiving randomly generated data or nothing in return. The fraudulent apps bypassed Google Play’s official billing system in some instances, complicating refund efforts for affected users. The apps have been removed from the Google Play Store but the financial impact on affected users remains.

## Recommendation

*   Monitor for installation of apps matching the CallPhantom naming scheme using a YARA rule (reference the file SHA-1 hashes listed in the original report).
*   Implement network monitoring to detect connections to Firebase Realtime Database, from which some CallPhantom apps fetched third-party payment URLs.
*   Deploy the Sigma rule below to detect suspicious applications that generate and display random contact data after payment.
