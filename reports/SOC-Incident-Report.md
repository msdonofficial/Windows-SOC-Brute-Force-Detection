\# SOC Incident Report

\## Windows Endpoint – Simulated Brute-Force Detection



\### 1. Incident Overview



| Field | Details |

|---|---|

| Incident Type | Simulated Brute-Force Attack |

| Target Account | SOC\_LabTest |

| Target System | DON |

| Source Address | ::1 (Localhost) |

| Severity | Medium |

| Status | Detected – Lab Investigation |

| Detection Method | PowerShell log analysis |



\### 2. Objective



To configure Windows Security auditing, simulate failed authentication attempts, identify suspicious login activity, and develop a PowerShell-based detection mechanism.



\### 3. Evidence Collected



\*\*Windows Security Event ID 4625\*\*

\- Description: An account failed to log on.

\- Target account: SOC\_LabTest

\- Logon type: 2

\- Failure reason: Unknown user name or bad password

\- Status: 0xC000006D

\- Substatus: 0xC000006A



\*\*Windows Security Event ID 4776\*\*

\- Description: Credential validation attempt.

\- Authentication package: MICROSOFT\_AUTHENTICATION\_PACKAGE\_V1\_0

\- Logon account: SOC\_LabTest

\- Error code: 0xC000006A



\### 4. Detection Logic



A custom PowerShell script was developed to:



1\. Collect Windows Security Event ID 4625.

2\. Analyze events from the previous 10 minutes.

3\. Group failed attempts by account and source IP.

4\. Trigger an alert when an account and source IP combination reaches five failures.

5\. Classify alerts by severity.

6\. Export alert information to a CSV file.



\### 5. Detection Thresholds



| Parameter | Configuration |

|---|---|

| Failed login threshold | 5 |

| Monitoring window | 10 minutes |

| Medium severity | 5–7 failures |

| High severity | 8 or more failures |

| Windows account lockout threshold | 10 failures |



\### 6. Response and Investigation



\- Identified the affected test account.

\- Confirmed the failed authentication status.

\- Correlated Event IDs 4625 and 4776.

\- Generated a PowerShell detection alert.

\- Saved alert evidence in SOC-Alerts.csv.



\### 7. Recommendations



\- Monitor repeated failed authentication attempts.

\- Investigate unusual source addresses.

\- Review account lockout events.

\- Correlate failed logons with successful authentication events.

\- Escalate suspicious activity for further investigation.



\### 8. Conclusion



The lab successfully demonstrated Windows endpoint security monitoring and detection of repeated failed authentication attempts using native Windows Security logs and PowerShell.



The activity was performed in a controlled local environment for cybersecurity training purposes.



\### 9. Failed-to-Successful Login Correlation



A second PowerShell detection script was developed

to identify successful authentication following

repeated failed login attempts.



Test results:

\- Account: SOC\_LabTest

\- Source IP: ::1

\- Failed attempts: 5

\- Successful login: 12:08:49

\- Generated alert: High



Result: Detection successful.



The script identified five failed authentication

attempts followed by a successful login within

the configured correlation window.

