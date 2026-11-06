\# Windows SOC – Endpoint Security Monitoring \& Brute-Force Detection



A hands-on Security Operations Center (SOC) lab built using Windows Security Event Logs and PowerShell to detect repeated failed authentication attempts and suspicious login patterns.



\## Project Overview



This project demonstrates how a SOC analyst can monitor Windows endpoint authentication activity, investigate failed login attempts, detect possible brute-force behavior, and generate alerts for further investigation.



The lab uses native Windows security auditing and custom PowerShell detection scripts without requiring a third-party SIEM.



\## Objectives



\- Enable and investigate Windows Security auditing.

\- Analyze failed and successful authentication events.

\- Detect repeated failed login attempts.

\- Correlate failed logins with subsequent successful logins.

\- Generate and export security alerts to CSV.

\- Document findings in a SOC incident report.



\## Lab Environment



| Component | Configuration |

|---|---|

| Operating System | Windows 11 Home |

| Monitoring Platform | Windows Security Event Logs |

| Scripting Language | PowerShell |

| Test Account | SOC\_LabTest |

| Test Workstation | LAB-WIN11 (anonymized) |

| Event Viewer | Windows Event Viewer |



\## Architecture



```mermaid

flowchart TD

&#x20;   A\[Windows 11 Endpoint] --> B\[Windows Security Auditing]

&#x20;   B --> C\[Security Event Log]

&#x20;   C --> D\[Event ID 4625 - Failed Login]

&#x20;   C --> E\[Event ID 4624 - Successful Login]

&#x20;   C --> F\[Event ID 4776 - Credential Validation]

&#x20;   D --> G\[PowerShell Brute-Force Detection]

&#x20;   D --> H\[Login Correlation Script]

&#x20;   E --> H

&#x20;   G --> I\[Security Alerts]

&#x20;   H --> I

&#x20;   I --> J\[Console Output]

&#x20;   I --> K\[CSV Reports]

&#x20;   J --> L\[SOC Investigation]

&#x20;   K --> L

```



\## Windows Security Events Investigated



| Event ID | Description |

|---|---|

| 4624 | An account successfully logged on |

| 4625 | An account failed to log on |

| 4776 | Credential validation attempt |



\## Detection Features



\### 1. Brute-Force Detection



The PowerShell detection script:



\- Collects Event ID 4625.

\- Analyzes failed logins within a 10-minute window.

\- Groups events by account and source IP.

\- Generates an alert when five or more failures are detected.

\- Assigns severity levels.

\- Exports alerts to CSV.



\### 2. Failed-to-Successful Login Correlation



A second PowerShell script identifies:



\- Repeated failed authentication attempts.

\- A subsequent successful login.

\- Matching account and source IP.

\- Five or more failures within the configured 10-minute period before a successful login.



The correlation script generates a High severity alert when its conditions are met.



\## Detection Configuration



| Parameter | Value |

|---|---|

| Failed login threshold | 5 |

| Monitoring window | 10 minutes |

| Brute-force alert severity | Medium |

| High severity threshold | 8 or more failures |

| Correlation alert severity | High |



\## Project Structure



```text

Windows-SOC-Brute-Force-Detection/

│

├── scripts/

│   ├── SOC-BruteForce-Detection.ps1

│   └── SOC-Login-Correlation.ps1

│

├── evidence/

│   ├── SOC-Alerts.csv

│   └── SOC-Correlation-Alerts.csv

│

├── reports/

│   └── SOC-Incident-Report.md

│

├── screenshots/

│   ├── 01-Windows-Security-Events.png

│   ├── 02-Brute-Force-Detection-Alert.png

│   └── 03-Login-Correlation-Alert.png

│

└── README.md

```



\## How to Run



1\. Open PowerShell as Administrator.

2\. Navigate to the project root directory.

3\. Enable script execution for the current PowerShell session only:



```powershell

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

```



4\. Execute the brute-force detection script:



```powershell

.\\scripts\\SOC-BruteForce-Detection.ps1

```



5\. Execute the login correlation script:



```powershell

.\\scripts\\SOC-Login-Correlation.ps1

```



The scripts analyze existing Windows Security events and generate alerts based on their configured detection conditions.



\## Lab Results



The lab successfully demonstrated:



\- Detection of repeated failed authentication attempts.

\- Identification of Event ID 4625 and Event ID 4776.

\- Detection of five failed login attempts within the configured window.

\- CSV-based security alert logging.

\- Detection of five failed attempts followed by a successful login.

\- Generation of a High severity correlation alert.



\## Skills Demonstrated



\- SOC Operations

\- Windows Security Monitoring

\- Security Event Log Analysis

\- PowerShell Scripting

\- Brute-Force Detection

\- Authentication Monitoring

\- Incident Investigation

\- Alert Generation

\- Security Incident Documentation



\## Limitations



\- Testing was performed in a controlled local Windows environment.

\- The source address `::1` represents localhost, not an external attacker.

\- The correlation script currently targets the `SOC\_LabTest` account.

\- Detection thresholds are configurable lab values, not universal production security standards.

\- Alerts indicate suspicious patterns and require analyst investigation.



\## Disclaimer



This project was developed for educational and cybersecurity training purposes. All authentication tests were performed using a controlled local test account. No unauthorized systems or accounts were targeted.



\## Author



Cybersecurity Enthusiast | SOC Analyst \& Security Monitoring Projects

