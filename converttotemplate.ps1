<#
.NOTES
    Author: Joseh de Clerck
    Created: 06/05/2017
        
.SYNOPSIS
    This script converts a VirtualMachine to a template
.DESCRIPTION 
	Loads the VMware PowerCLI core snapin and opens a VMware PowerCLI connection to the specified vCenter, using the specified credentials.
	
	Start a VM so vCenter will detect the guest agent
    Shutdown the guest
    Convert to template
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$vmName,
    [Parameter(Mandatory=$True,Position=2)]
    [string]$user,
    [Parameter(Mandatory=$True,Position=3)]
    [string]$password,
    [Parameter(Mandatory=$True,Position=4)]
    [string]$vcenter
)

Write-Output "Converting $vmName to template"

$ErrorActionPreference = "Stop"

Get-Module -ListAvailable PowerCLI* | Import-Module
Set-PowerCLIConfiguration -InvalidCertificateAction ignore -confirm:$false
#Connect to vCenter
Connect-VIServer -server $vcenter -user $user -password $password

#Start the VM and wait for the agent to be running (how to exit if agent is not installed???)
Start-VM $vmName | Out-Null
While ((get-vm $vmName).Guest.State -eq "NotRunning") { sleep 30 }
Write-Output "Shutdown guest"
#Shutdown the VM guest and wait till the state is poweredoff
Shutdown-VMGuest $vmName -Confirm:$false | Out-Null
While ((get-vm $vmName).PowerState -ne "PoweredOff") { sleep 30 }
Write-Output "Convert to template"
#Convert to Template
Set-VM $vmName -ToTemplate -Confirm:$false | Out-Null
Write-Output "Conversion complete"
#Disconnect from VIServer
Disconnect-VIServer -Confirm:$false
