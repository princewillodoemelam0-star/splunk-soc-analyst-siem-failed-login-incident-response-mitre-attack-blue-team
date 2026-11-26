# splunk-soc-analyst-siem-failed-login-incident-response-mitre-attack-blue-team
Hands-on SOC Level 1 investigation of failed Windows login activity using Splunk Enterprise, covering log analysis, authentication correlation, source IP investigation, MITRE ATT&amp;CK mapping, and incident response.

Failed Login Investigation Using Splunk Enterprise

Project: SOC Analyst Level 1 Practical Investigation

Tool: Splunk Enterprise

Operating System: Windows 10

Investigation Type: Authentication Failure Investigation

1. Introduction

I carried out a hands-on investigation of failed login activity using Splunk Enterprise.

My objective was to investigate the authentication events, identify the affected account, examine the source of the login attempts, and determine whether the activity could indicate a possible brute-force attack or unauthorized access.

Rather than immediately classifying the alert as malicious, I approached it by examining the available evidence and identifying what additional information was required.

2. Initial Alert Investigation

I opened Splunk Enterprise and navigated to Search & Reporting.

I started with this SPL query:

index=main "status=failed"

Initial findings

My search returned 3 matching events.

From the visible event details, I identified:

Field| Evidence
Index| main
Username| jane
Action| login
Status| failed
Hostname| DESKTOP-AUR2MKK
Timestamp| 2026-04-13 10:06:30 AM

Initial assessment:

The logs showed failed authentication activity involving the account "jane".

I treated this as suspicious activity requiring further investigation, rather than immediately declaring it a brute-force attack.

3. Investigation Steps

Step 1: Review the authentication logs

I reviewed the available failed-login events to understand the activity.

I focused on:

- The affected username.
- The number of failed attempts.
- The timestamps.
- The affected endpoint.
- Whether the attempts occurred within a short period.

Step 2: Identify the source IP address

I would inspect the raw authentication events to identify the originating IP address.

I would check fields such as "src_ip", "Source_Network_Address", or equivalent fields available in the logs.

My objective would be to determine whether the attempts originated from one IP address or multiple locations.

I would also examine relevant network logs to establish whether the source was internal or external.

Step 3: Investigate repeated failed attempts

I would use the following search to identify accounts experiencing repeated failures:

index=main "status=failed"
| stats count by user, host
| sort - count

This would help me identify the affected accounts and endpoints.

Step 4: Check for successful authentication

I would investigate whether the failed login attempts were followed by a successful login.

index=main "status=success"

I would correlate the results using:

- Username.
- Source IP.
- Hostname.
- Timestamp.

A successful login following multiple failures would require additional investigation, especially if it originated from the same suspicious source.

Step 5: Establish the event timeline

I would arrange the authentication events chronologically.

index=main action=login
| sort 0 _time
| table _time user action status host

This would help me understand the sequence of authentication activity.

Step 6: Determine the potential threat

I would assess whether the activity was consistent with:

- User password-entry mistakes.
- Repeated password guessing.
- Brute-force attempts.
- Possible unauthorized account access.

I would use the evidence to determine the appropriate severity and whether escalation was necessary.

4. MITRE ATT&CK Mapping

Potential Technique: T1110 – Brute Force

I considered MITRE ATT&CK T1110 because repeated failed authentication attempts can be associated with password-guessing activity.

However, the three matching events alone are insufficient to confirm a brute-force attack.

Further correlation and supporting evidence would be required.

5. Recommended Remediation

If the investigation confirmed unauthorized access or malicious authentication activity, I would recommend:

1. Escalating the incident to SOC Level 2 or the incident response team.
2. Temporarily restricting the affected account where appropriate.
3. Resetting the affected user's credentials.
4. Revoking suspicious active sessions.
5. Investigating the source IP across available security logs.
6. Checking for suspicious activities after successful authentication.
7. Enforcing MFA and appropriate account lockout policies.
8. Continuing to monitor the affected endpoint and account.

6. Investigation Status

Initial status: Further Investigation Required

The initial Splunk search returned three failed-login events.

I identified the visible username, hostname, action, and timestamp.

The source IP, successful-login correlation, and final attack classification still require verification.

I would not close this investigation as a confirmed security incident without sufficient evidence.

7. Skills Demonstrated

- Splunk Enterprise.
- SIEM log investigation.
- SPL queries.
- Windows authentication monitoring.
- Failed-login analysis.
- Source IP investigation.
- Event correlation.
- MITRE ATT&CK.
- Incident response.
- Security documentation.

8. Conclusion

This practical investigation demonstrates how I approach authentication-related alerts as a SOC Analyst Level 1.

I started with the available logs, identified the failed authentication activity, and established the additional evidence required to understand the incident.

My approach is simple:

Investigate the alert. Examine the evidence. Correlate the events. Determine the risk. Recommend remediation.

An alert is an indication of something that needs attention, not automatic proof of an attack.
