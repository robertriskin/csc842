<#
Script Name: redteam-sysinfo-v1.ps1
Author: Robert Riskin
Date: 2020/05/24
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
#>

#Funcion that gets current username, computername, ip address, & mac address
Function getbasicsysteminfo
{
	#gets logged-in user's username, computer, ip and MAC address
	$currentuser = $env:username
	$currentcomputer = $env:computername
	$ipaddress = get-netipaddress -addressfamily ipv4 | where {$_.IPAddress -ne "127.0.0.1"} | select IPaddress -expandproperty IPAddress
	$macaddress = (gwmi win32_networkadapterconfiguration).macaddress

	#Outputs info to commandline
	echo "*************************************************"
	echo "*****Basic System Information********************"
	echo("Current User: "+$currentuser)
	echo("Current Computer Name: "+$currentcomputer)
	echo("IP Address: "+$ipaddress)
	echo("MAC Address: "+$macaddress)
	echo "*************************************************"
}

#Function that verifies if computer is part of a domain, global because it is called from other functions
Function global:verifydomain
{
	
	$domainjoined = (gwmi win32_computersystem).partofdomain
	return $domainjoined
}

#Function that verifies if the current logged in user is a local admin, depending if computer is domain joined
Function verifyadmin
{
	#sets array variable to track if local admin or a domain group that is a member of local admin group
	$adminArray= @()

	#checks to see if the computer is on domain, as the user/admin checks are slightly different
	if (verifydomain)
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
			$principal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
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
Function global:bitlocker
{
	#retrieves bitlocker status via manage-bde command
	$bitlockerstatus = manage-bde -status
	
	$bitlockerprotectionstatus = $bitlockerstatus | select -Index 13
	#if bitlocker protection is on, proceed to display information
	if($bitlockerprotectionstatus.Substring(26,13) -eq "Protection On")
		{
			#Bitlocker Volume
			$bitlockervolume = $bitlockerstatus | select -Index 5
			echo ("Bitlocked Volume: "+$bitlockervolume.Substring(7,2))

			$bitlockerconversion = $bitlockerstatus | select -Index 10
			echo ("Bitlocked Volume Encryption Status: "+$bitlockerconversion.Substring(26,15))

			$bitlockermethod = $bitlockerstatus | select -Index 12
			echo ("Bitlocked Volume Encryption Schema: "+$bitlockermethod.Substring(26,11))

		}	
	else
		{
			echo "OS Drive is not Bitlocked."
		}


}

#Function that determines the version(s) of Microsoft Office installed, uses registry settings
Function officeversion 
{
	#sets an array to keep track of office versions in case there are multiple installations
	$officeVersion= @()
	
	#sets variables for paths to registry locations of Office install locations
	$officeversion1 = "hklm:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
	$version1 = get-itemproperty -path $officeversion1 -name VersionToReport
	$officeversion2 = "hklm:\SOFTWARE\Microsoft\Office\14.0\Common\FilesPaths"
	if([bool](get-itemproperty -path $officeversion1 -name VersionToReport))
		{
			if($version1.VersionToReport -ge "16")
				{
					echo "Office 2016+ is installed."
					$officeVersion += "2016"
				}
			if($version1.VersionToReport -lt "16")
				{
					echo "Office 2013 is installed"
					$officeVersion += "2013"
				}
			
		}
	else 
		{
			if([bool](get-itemproperty -path $officeversion2))
				{
					echo "Office 2010 is installed."
					$officeVersion += "2010"
				}
		}
#Returns the office array of versions
return $officeVersion
}

#Function that checks for internet connectivity via TLS to the Microsoft Update Catalog to avoid suspicioun in network logs
Function checkinternet
{
	$webrequest = invoke-webrequest "https://catalog.update.microsoft.com"
	if($webrequest.statuscode -eq "200")
		{
			echo "Computer can reach the internet."
		}
	else
		{
			echo "Computer cannot reach the internet."
		}
}

#Function that checks if RDP is enabled via a registry setting
Function checkrdpaccess
{
	$rdppath = "hklm:\system\currentcontrolset\control\terminal server"
	$rdpenabled = get-itemproperty -path $rdppath -name fDenyTSConnections
	if($rdpenabled.fDenyTSConnections -eq "0")
		{
			echo "RDP is enabled!"
		}
}

#Function that checks to see if the three different Windows Firewall Profiles are enabled
Function checkwindowsfirewall
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
			echo "Windows Firewall is enabled on all profiles."
		}
	else
		{
			echo "At least one of the Windows Firewall profiles is disabled."
		}
	
}

#executes the getinfo function
getbasicsysteminfo

#executes the verifyadmin function
if((verifyadmin) -contains "isAdmin")
	{
		echo "Current user is a member of the local administrator group."

		#executes functions that require admin access
		#executes bitlocker discovery function
		bitlocker

		#executes office version discovery and macro check, macro checks are based off Office version from previous function and other hardcoded registry settings
		if((officeversion) -contains "2010")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\14.0\msproject\security"
				$macroenabled = get-itemproperty -path $macropath -name VBAWarnings
				if([bool](get-itemproperty -path $macropath -name VBAWarnings))
					{
						if($macroenabled.VBAWarnings -eq "1")
							{
								echo "Macros are enabled!"
							}

					}
				echo "Microsoft Office 2010 is installed."
			}	
		if((officeversion) -contains "2013")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\15.0\excel\security"
				$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
				if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
					{
						if($macroenabled.blockcontentexecutionfrominternet -ne "1")
							{
								echo "Macros are enabled!"
							}

					}

				echo "Microsoft Office 2013 is installed."
			}
		if((officeversion) -contains "2016")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\16.0\excel\security"
				$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
				if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
					{
						if($macroenabled.blockcontentexecutionfrominternet -ne "1")
							{
								echo "Macros are enabled!"
							}

					}


				echo "Microsoft Office 2016+ is installed, this can include Office 2016, 2019, 365."
			}

		#executes internet access check function
		checkinternet

		#executes RDP check function
		checkrdpaccess

		#executes Windows Firewall check function
		checkwindowsfirewall
		
	}
#assumes user is NOT an admin and runs non-admin functions
else
	{
		echo "Current user is not a local administrator."

		#executes functions that do not require admin access

		#executes office version discovery and macro check, macro checks are based off Office version from previous function and other hardcoded registry settings
		if((officeversion) -contains "2010")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\14.0\msproject\security"
				$macroenabled = get-itemproperty -path $macropath -name VBAWarnings
				if([bool](get-itemproperty -path $macropath -name VBAWarnings))
					{
						if($macroenabled.VBAWarnings -eq "1")
							{
								echo "Macros are enabled!"
							}

					}
				echo "Microsoft Office 2010 is installed."
			}	
		if((officeversion) -contains "2013")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\15.0\excel\security"
				$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
				if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
					{
						if($macroenabled.blockcontentexecutionfrominternet -ne "1")
							{
								echo "Macros are enabled!"
							}

					}

				echo "Microsoft Office 2013 is installed."
			}
		if((officeversion) -contains "2016")
			{
				$macropath = "hkcu:\software\policies\microsoft\office\16.0\excel\security"
				$macroenabled = get-itemproperty -path $macropath -name blockcontentexecutionfrominternet
				if([bool](get-itemproperty -path $macropath -name blockcontentexecutionfrominternet))
					{
						if($macroenabled.blockcontentexecutionfrominternet -ne "1")
							{
								echo "Macros are enabled!"
							}

					}


				echo "Microsoft Office 2016+ is installed, this can include Office 2016, 2019, 365."
			}

		#executes internet access check function
		checkinternet

		#executes RDP check function
		checkrdpaccess

		#executes Windows Firewall check function
		checkwindowsfirewall
	}

#end of script