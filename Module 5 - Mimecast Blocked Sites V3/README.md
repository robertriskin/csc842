# mimecast-blocked-sites-v3.cs
This application is intended to be used as a graphical user interface tool to help Mimecast administrators quickly add malicious domains and/or e-mail addresses to their Blocked Senders group for instant usage.

# General Details
* C# File Name: mimecast-blocked-sites-v3.cs
* Authoer: Robert Riskin
* Date: 2020/07/18
* Description: A Visual C# Winform application that takes an e-mail or domain, checks that the e-mail is in valid format and/or a domain is not in the restricted list and then add the domain/e-mail to a specific group inside of Mimecast, for the purposes of this application it should be the blocked senders profile group. Additionally it can decode Mimecast protected URLs and also put URLs on a managed block via explicit or domain links.
* Tested on Windows 10 1809

# Features
* Add an e-mail address to a specific group inside of Mimecast
* Add a domain to a specific group inside of Mimecast
* Add an explicit or domain to managed URL list to block
* Decode Mimecast protected URL

# Build Requirments: 
* Visual Studio 2019
* A valid Mimecast API account created with the basic admin role 
* Mimecast API Keys, including: access key, secret key, application ID, application key and a profile group ID to which you want the e-mails/domains to be added to - typically this is the Blocked Senders Group - for that you will need to know the ID of the profile group

# Resources Used:
* https://www.mimecast.com/tech-connect/documentation/endpoint-reference/directory/add-group-member 
* https://www.mimecast.com/tech-connect/documentation/endpoint-reference/directory/find-groups/
* https://www.mimecast.com/tech-connect/documentation/endpoint-reference/targeted-threat-protection-url-protect/decode-url/
* https://www.mimecast.com/tech-connect/documentation/endpoint-reference/targeted-threat-protection-url-protect/create-managed-url/

# Installation/Usage
1. Download the mimecast-blocked-sites-v3.cs file.
2. Open the file inside of Visual Studio 2019.
3. Modify the base_url, access_key, secret_key, app_id, app_key, and blockedsendersid variables with those according to your Mimecast instance.
4. Build the form to your liking from a visual perspective.
5. Build the solution -> Build -> Build Solution.
6. Locate the binary executable and DLL file in the bin\debug\netcoreapp3.1 folder
7. Execute the binary executable:
```CMD or Powershell Prompt
>mimecast-blocked-sites-v3.exe
```
