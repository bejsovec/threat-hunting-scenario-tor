# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/bejsovec/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered that it looks like the user downloaded and installed Tor . Did something that resulted in many Tor-related files being copied to the desktop and creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: May 26, 2026 1:02:09 PM 

KQL statement used:
```
DeviceFileEvents
| where FileName contains "tor"
| where InitiatingProcessAccountName == "brandonlab"
| where DeviceName == "brando-edr"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “"tor-browser-windows". Based on the logs returned, at May 26, 2026 1:34:36 PM the employee ran “tor-browser-windows-x86_64-portable-15.0.14 /s” from the downloads folder. This triggered a silent installation of the Tor application.

KQL statement used:
```
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256, Account = InitiatingProcessAccountName
| where DeviceName == "brando-edr"
```
---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “brandonlab” actually opened the Tor browser. There was evidence they opened the Tor application on May 26, 2026 1:35:31 PM. There were several other instances of firefox.exe (tor) as well as tor.exe spawned afterwards.

KQL statement used:
```
DeviceProcessEvents
| where DeviceName == "brando-edr"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the Tor browser was used to establish a connection using any of the known ports used by Tor. An employee on “brando-edr” device on May 26, 2026 1:36:17 PM successfully established a connection to report IP address 159.69.138.31 on port 9001. The connection was initiated by the process tor.exe located in c:\users\brandonlab\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a few other connections.

KQL statement used:
```
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| where DeviceName == "brando-edr"
| order by Timestamp desc
```
---

## Chronological Event Timeline 

### 1. File Download – Tor Browser Installer
Timestamp: Prior to May 26, 2026 1:33:47 PM PDT
Event: User downloaded the Tor Browser installer to the local device.
Device: brando-edr
User: brandonlab
File Path: C:\Users\brandonlab\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe
File Name: tor-browser-windows-x86_64-portable-15.0.14.exe

### 2. Process Execution – Silent Tor Installation
Timestamp: May 26, 2026 1:34:51 PM PDT
Event: User executed the Tor Browser installer using silent installation arguments.
Device: brando-edr
User: brandonlab
Process: tor-browser-windows-x86_64-portable-15.0.14.exe
Process Command:
 tor-browser-windows-x86_64-portable-15.0.14.exe /s
Execution Path: C:\Users\brandonlab\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe

### 3. Application Execution – Tor Browser Launch
Timestamp: May 26, 2026 1:35:31 PM PDT
Event: Tor Browser application and supporting Tor processes were launched on the endpoint.
Device: brando-edr
User: brandonlab
Process: tor.exe
Executable Path:
 C:\Users\brandonlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
Observed Command Line:
 "tor.exe" -f "C:\Users\brandonlab\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc"
Additional Activity: Multiple instances of tor.exe, firefox.exe, and tor-browser.exe were observed following execution.

### 4. Network Connection – Tor Relay Communication
Timestamp: May 26, 2026 1:36:17 PM PDT
Event: Tor process established outbound network communication to a known Tor relay node.
Device: brando-edr
User: brandonlab
Initiating Process: tor.exe
Process Path:
 C:\Users\brandonlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
Remote IP Address: 159.69.138.31
Remote Port: 9001
Protocol Purpose: Known Tor relay communication port.
Additional Activity: Multiple additional Tor-related outbound connections were observed afterward.

### 5. File Creation – “tor-shopping-list.txt”
Timestamp: May 26, 2026 1:38:21 PM PDT
Event: A text file named tor-shopping-list.txt was created on the endpoint following Tor Browser activity.
Device: brando-edr
User: brandonlab
File Name: tor-shopping-list.txt
Associated Activity: File creation occurred after Tor installation, execution, and outbound Tor communications were established.


---

## Summary

On May 26, 2026, suspicious activity was identified on device “brando-edr” involving employee account “brandonlab.” Investigation of DeviceFileEvents revealed the user downloaded and installed the Tor Browser, resulting in multiple Tor-related files being copied to the desktop, including a file named “tor-shopping-list.txt.” Initial file activity began at approximately 1:02 PM PDT.

Further analysis of DeviceProcessEvents confirmed the user executed “tor-browser-windows-x86_64-portable-15.0.14 /s” from the Downloads folder at 1:34 PM PDT, indicating a silent installation of the Tor Browser. Additional process events showed the Tor Browser was launched shortly afterward at 1:35 PM PDT, with multiple instances of tor.exe and firefox.exe observed.

Network analysis using DeviceNetworkEvents confirmed outbound Tor-related traffic from the device. At approximately 1:36 PM PDT, tor.exe established a successful connection to remote IP address 159.69.138.31 over port 9001, a known Tor communication port. Multiple additional Tor-related network connections were also identified, confirming active Tor usage on the endpoint.


---

## Response Taken
TOR usage was confirmed on endpoint brando-edr. The device was isolated and the user's direct manager was notified.
---
