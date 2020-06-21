#!/python3
#Filename: mimecast-blocked-sites-v1.py
#Author: Robert Riskin
#Date: 2020/06/19
#Description: A python gui application that takes an e-mail or domain, checks that the e-mail is in valid format and/or a domain is not in the restricted list and then add the domain/e-mail to a specific group inside of Mimecast, for the purposes of this application it should be the blocked senders profile group.
#Requirments: A valid Mimecast API account created with the basic admin role, Mimecast API Keys, including: access key, secret key, application ID, application key and a profile group ID
#Notes: I ported part of this code from the Mimecast python API documentation from Python2 to Python3
#Mimecast API Resources Used: https://www.mimecast.com/tech-connect/documentation/endpoint-reference/directory/add-group-member/ | https://www.mimecast.com/tech-connect/documentation/endpoint-reference/directory/find-groups/

#imported libraries
import base64
import json
import hashlib
import hmac
import uuid
import datetime
import requests
import re
import tkinter as tk
from tkinter import RAISED, BOTH, RIGHT, CENTER
from tkinter.ttk import Frame

#setting tkinter gui object and title 
root = tk.Tk()
root.title("Mimecast Block Application")

#setting mimecast variables - you will need to fill these in with your custom values that are unique to your environment
base_url = "https://xx-api.mimecast.com"
uri = "/api/directory/add-group-member"
url = base_url + uri
access_key = "ENTER_YOUR_ACCESS_KEY_HERE"
secret_key = "ENTER_YOUR_SECRET_KEY_HERE"
app_id = "ENTER_YOUR_APP_ID_HERE"
app_key = "ENTER_YOUR_APP_KEY_HERE"
blockedsendersid = "ENTER_YOUR_PROFILE_GROUP_ID_HERE"

# Generate request header values - borrowed from Mimecast documentation
request_id = str(uuid.uuid4())
hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

# Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header - borrowed from Mimecast documentation - updated for python3
hmac_sha1 = hmac.new(base64.b64decode(secret_key), ":".join([hdr_date, request_id, uri, app_key]).encode(), digestmod=hashlib.sha1).digest() 
bytesig = base64.b64encode(hmac_sha1).decode() 

# Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey - borrowed from Mimecast documentation - updated for python3
sig = str(bytesig)

# Create request headers - borrowed from Mimecast documentation
headers = {'Authorization': 'MC ' + access_key + ':' + sig,'x-mc-app-id': app_id,'x-mc-date': hdr_date,'x-mc-req-id': request_id,'Content-Type': 'application/json'}

#setting gui variables for tkinter application 
userentry = tk.StringVar() #variable for user entered domain/email 
consolelog = tk.StringVar() #variable for the console status text
consolelog.set("Waiting for user action...")
v = tk.IntVar() #variable for determining if entered data is a domain or email
v.set(0) # set initial variable to domain
blocktypes = [("Domain",1),("E-mail",2)] #list that holds the desired entered data type

#functions

#this function will check to make sure the inputted domain is not a major e-mail service
def checkdomain(entereddomain):
	#print("Entering checkdomain function")
	#list of free domains that we do NOT want to block globally
	freeemaildomains = ["aol.com", "articmail.com", "gmail.com", "outlook.com", "live.com", "hotmail.com", "protonmail.com", "yahoo.com", "zoho.com"]
	
	#checks to see if entered domain is in the free list, if it is, return false and fail the domain check as we do not want to block these entirely, else return true and continue blocking the domain in Mimecast
	if entereddomain in freeemaildomains:
		return False
	else:
		return True

#function that receives an e-mail and runs a regex to validate that it has a valid e-mail format, returns boolean object - used email regex check from https://stackoverflow.com/questions/8022530/how-to-check-for-valid-email-address
def validate_email(enteredemail):
	return bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", enteredemail))

#function that is used when a domain or email is entered and goes through the checks and adds the domain or email to the blocked senders group in mimecast
def addblockedsite():
	#checks if entered data is an e-mail and proceeds to do checks
	if v.get() == 1:
		#print("E-mail")
		#checks to see if e-mail is valid, if so it continues
		if validate_email(userentry.get()):
			#updates console gui 
			consolelog.set("Email entered.")
			#sets the payload to send to mimecast with the entered e-mail address
			payload = {'data': [{'id': blockedsendersid,'emailAddress': userentry.get()}]}
			#sends the request with the necessary mimecast information for the post request to add the email to the blocked sites profile
			r = requests.post(url=url, headers=headers, data=str(payload))
			#received api data determining if the post was successful
			data = r.json()
			#parses return in json format and retrieves the status and failure messages
			status = data['meta']
			fail = data['fail']
			#error handling and updating gui if status was 200 and no failures, if this was not the case then it logs to console and the gui that failures were present
			if str(status) == "{'status': 200}":
				print("status OK")
				if str(fail) == "[]":
					print("no failures")
					consolelog.set("E-mail successfully blocked!")
				else:
					print("failures present")
					consolelog.set("Status OK but failures present!")
			else:
				print("Domain not blocked, status failed.")
				consolelog.set("Domain not blocked, status failed.")
		else:
			print("E-mail check failed!")
			consolelog.set("E-mail check failed!")
	#checks if entered data is a domain and if so it continues	
	if v.get() == 0:
		#print("Domain")
		#checks to see if domain is on the free domain lists
		if checkdomain(userentry.get()):
			#updates console gui
			consolelog.set("Domain entered.")
			#sets the payload to send to mimecast with the entered domain
			payload = {'data': [{'id': blockedsendersid,'domain': userentry.get()}]}
			#sends the request with the necessary mimecast information for the post request to add the domain to the blocked sites profile
			r = requests.post(url=url, headers=headers, data=str(payload))
			#returns object of type dict with lists of information
			data = r.json()
			#parses return in json format and retrieves the status and failure messages
			status = data['meta']
			fail = data['fail']
			#error handling and updating gui if status was 200 and no failures, if this was not the case then it logs to console and the gui that failures were present
			if str(status) == "{'status': 200}":
				print("status OK")
				if str(fail) == "[]":
					print("no failures")
					consolelog.set("Domain successfully blocked!")
				else:
					print("failures present")
					consolelog.set("Status OK but failures present!")
			else:
				print("Domain not blocked, status failed.")
				consolelog.set("Domain not blocked, status failed.")
		else:
			print("Domain check failed.")
			consolelog.set("Domain check failed!")
			
	#testing console output	
	#print(userentry.get())

#layout items - text, entries, buttons
tk.Label(root,text="""What are you blocking?""",justify = tk.LEFT,padx = 20).pack()
#displaying radio button
for val, blocktype in enumerate(blocktypes):
	tk.Radiobutton(root,text=blocktype,padx = 20,variable=v,value=val).pack(anchor=tk.W)
tk.Label(root, text="Enter Site to Block:").pack()	
tk.Entry(root, textvariable=userentry).pack()
tk.Label(root, textvariable=consolelog).pack()
tk.Button(root, text="Exit", command=root.quit).pack(side=RIGHT)
tk.Button(root, text="Block Entry", command=addblockedsite).pack(side=RIGHT)

#tkinter main object loop
root.mainloop()
