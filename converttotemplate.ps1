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
<#
    This part will rotate the templates
    1. Remove -old template
    2. Rename template -> template-old
    3. Set vmname -> template
#>
$ISOTIME = Get-Date -Format "yyyy-MM"
$TemplateName = $vmName.Replace("-$ISOTIME","")

$OldTemplate = Get-Template -Name "$TemplateName-OLD" -ErrorAction SilentlyContinue
if ($OldTemplate) { Remove-Template -Template $OldTemplate -DeletePermanently -Confirm:$false }
$Template = Get-Template -Name "$TemplateName" -ErrorAction SilentlyContinue
if($Template) { Set-Template -Template $Template -Name "$TemplateName-OLD" }
#Rename template to template-old
Set-VM $vmName -ToTemplate -Confirm:$false | Out-Null
$NewTemplate = Get-Template -Name $VMName 
if ($NewTemplate) { Set-Template -Template $NewTemplate -Name $TemplateName -}
Write-Output "Conversion complete"
#Disconnect from VIServer
Disconnect-VIServer -Confirm:$false