# RedTeam-SysInfo-v1.ps1
This script is intended to be used for basic information gathering/recon on a target Windows machine by a network defender or a penetration tester.

# General Details
* Script Name: redteam-sysinfo-v1.ps1
* Author: Robert Riskin
* Date: 2020/05/24
* Tested On: Windows 10 1809, 1903, domain joined and non-domain joined

* Notes: This script is a first run at a redteam script to scrape information for potential post-exploitation purposes. It is designed to be run under any user context as it will only run elevated commands if the current user is an administrator.
This script will pull basic information such as current logged-in user, computer name, IP address and MAC Address.
This script will determine if the computer is joined to a domain.
This script will verify if the current user is a member of the local administrators group or any domain joined groups that are placed in the local Windows Administrators Group.
This script will check to see if there are any Bitlocker drives mounted and display their status and encryption schema.
This script will check to see if any version of Office 2010-365 is installed and if macros are enabled.
This script will check to see if the Internet is working by testing an TLS connection to the Microsoft Updates Catalog.
This script will check to see if RDP is enabled on the local computer.
This script will check to see if any of the Windows Firewall Profiles are disabled.

# Requirements
* Windows 10 Operating System - at least version 1809
* Powershell 5 - this should be included with the Windows 10 release

# Installation
1. Copy the redteam-sysinfo-v1.ps1 file or raw code to the target machine.
2. Run the script:
```Powershell
>.\redteam-sysinfo-v1.ps1
```

