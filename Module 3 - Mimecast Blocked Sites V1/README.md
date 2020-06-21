# mimecast-blocked-sites-v1.py
This script is intended to be used as a graphical user interface tool to help Mimecast administrators quickly add malicious domains and/or e-mail addresses to their Blocked Senders group for instant usage.

#General Details
* Filename: mimecast-blocked-sites-v1.py
* Authoer: Robert Riskin
* Date: 2020/06/19
* Description: A python gui application that takes an e-mail or domain, checks that the e-mail is in valid format and/or a domain is not in the restricted list and then add the domain/e-mail to a specific group inside of Mimecast, for the purposes of this application it should be the blocked senders profile group.
* Tested on Windows 7/10 with python3.7
* Notes: I ported part of this code from the Mimecast python API documentation from Python2 to Python3

# Features
* Add an e-mail address to a specific group inside of Mimecast
* Add a domain to a specific group inside of Mimecast

# Requirments: 
* Python3.7
* A valid Mimecast API account created with the basic admin role, 
* Mimecast API Keys, including: access key, secret key, application ID, application key and a profile group ID to which you want the e-mails/domains to be added to - typically this is the Blocked Senders Group - for that you will need to know the ID of the profile group

# Resources Used:
* https://www.mimecast.com/tech-connect/documentation/endpoint-reference/directory/add-group-member 
* https://www.mimecast.com/tech-connect/documentation/endpoint-reference/directory/find-groups/

#Installation/Usage
1. Copy the mimecast-blocked-sites-v1.py file or raw code to the target machine
2. Modify the base_url, access_key, secret_key, app_id, app_key, and blockedsendersid variables with those according to your Mimecast instance
3. Run the script:
```Python3.7
>mimecast-blocked-sites-v1.py
```
