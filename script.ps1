# Perform the integration of the computer in the Sandbox-ass Active Directory
# and log the result in file "Provisionning_status.log" in "C:\Program Files\SGBUILD\Logs\".
# This log can be then checked by the automation server to ensure that JumpHost has been successfully deployed before sending email to Owner and users.
# Complete operation log is located in "join_sandbox-aas_domain_"

$folder = "C:\Program Files\SGBUILD\Logs\"
$file = "join_sandbox-aas_domain_"
$Resultfile =  Join-Path -Path $folder -ChildPath "Provisionning_status.log"
if (Test-Path -Path $Resultfile) { Remove-Item -Path $Resultfile -Force }

#region Init & Loading Functions
    function Init-LogFile{
	    [CmdletBinding()]
         param( [Parameter(Mandatory=$true)]
                [string]$folder,
                [Parameter(Mandatory=$true)]
                [string]$file
              )
        $global:LogFolder = $folder
        $file = $file + $(Get-Date -Format "yyyyMMdd" -Date (Get-Date).ToUniversalTime()) + ".log"
        $global:Logfile = Join-Path -path $folder -ChildPath $file
        $logdata = "-------------------------------------------------------------------------------------------"
        "$(Get-Date -Format "yyyy/MM/dd HH:mm:ss" -Date (Get-Date)) - $logdata" | Out-File $logfile -Append
    }

    Init-LogFile -folder $folder -file $file

    function Write-ToLogFile{
        <#
        .SYNOPSIS
        Append data to the log file and write to host
        .DESCRIPTION
          Write logdata to host and append to the log file you have previously inited with Init-LogFile with date and timestamp 
         .PARAMETER logdata
          This is the content you want to append to the log file and write to host
        .EXAMPLE
          Write-ToLogFile "############ $Scriptname #####################  STARTING ###############"
          Write-ToLogFile "############ $Scriptname #####################  FINISHED ###############"
        .EXAMPLE
          Write-ToLogFile "ERROR $($send) $($Element.servername) $($Element.InstanceID)"
        .EXAMPLE
          Write-ToLogFile "$($_.exception.message)"
        .NOTES

        #>
	    [CmdletBinding()]
         param( [Parameter(Mandatory=$true)]
                [string]$logdata,
                [Parameter(Mandatory=$false)]
                [string]$ForeGroundColor
         )
          "$(Get-Date -Format "yyyy/MM/dd HH:mm:ss" -Date (Get-Date)) - $logdata" | Out-File $global:Logfile -Append
          Write-Host "$(Get-Date -Format "yyyy/MM/dd HH:mm:ss" -Date (Get-Date)) - $logdata"
    }

    Write-ToLogFile "Importing AWS Module"
    Import-Module AWSPowershell
    $awsversion = (Get-Module -Name AWSPowershell).Version.ToString()
    Write-ToLogFile "AWS Module Version : $awsversion"

    Function Write-OperationFailed {
        Write-ToLogFile "Integration in AD failed"
        "JUMPHOST Provisionning failed"| Out-File $Resultfile
    }
#endregion

#region proxy
    Write-ToLogFile "Setting Proxy by invoking C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\set_proxy.cmd"
    C:\Users\Default\AppData\Roaming\Microsoft\Windows\"Start Menu"\Programs\Startup\set_proxy.cmd

    #Verifier le proxy
    $pattern = '[^a-zA-Z0-9.\-]'


    Write-ToLogFile "-------------------------------------------------------------------------------------------"
    $regPolicyKey = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
    $value =  Get-ItemProperty -path $regPolicyKey -Name ProxySettingsPerUser -ErrorAction SilentlyContinue
    if ($value) {
        Write-ToLogFile "$regPolicyKey ProxySettingsPerUser => $($value.ProxySettingsPerUser)"
    } else {
        Write-ToLogFile "$regPolicyKey ProxySettingsPerUser => NOTSET)"
    } 
    Write-ToLogFile "-------------------------------------------------------------------------------------------"
    foreach ($key in @("HKCU:\Software","HKLM:\Software","HKLM:\Software\Wow6432Node")) {
        foreach ($property in @("AutoDetect", "ProxyEnable", "ProxyServer", "ProxyOverride")) {
            $fullKey = $key + "\Microsoft\Windows\CurrentVersion\Internet Settings"
            $value = Get-ItemProperty -Path $fullKey -Name $property -ErrorAction SilentlyContinue
            if ($value) {
                Write-ToLogFile "$key $property => $($value.$property)"
            } else {
                Write-ToLogFile "$key $property => NOTSET)"
            }   
        }
        $fullKey = $key + "\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
        $value = (Get-ItemProperty $fullKey -Name DefaultConnectionSettings -ErrorAction SilentlyContinue)
        if ($value) {
            $msg = "$key DefaultConnectionSettings => " + (-join ($value.DefaultConnectionSettings[1..100] |%{ [char]$_ }))
            Write-ToLogFile "$($msg-replace $pattern, ' ')"
        } else {
            Write-ToLogFile "$key DefaultConnectionSettings => NOT SET"
        }
        Write-ToLogFile "-------------------------------------------------------------------------------------------"
    }
#endregion


#region test reseau
    $browser = New-Object System.Net.WebClient     
    $browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials  
    $proxyset = (Get-ItemProperty  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").Proxyserver
    $proxy = ($proxyset -split ":")[0]
    $port = ($proxyset -split ":")[1]
    $ProxyTest = Test-NetConnection -Port $port -computername $proxy
    if ($ProxyTest.TcpTestSucceeded) {
        Write-ToLogFile "Connection test on $ProxyTest.computername on port $ProxyTest.remoteport Succeded"
    }
    else {
        Write-ToLogFile "Connection test on $ProxyTest.computername on port $ProxyTest.remoteport Failed"
        Write-OperationFailed
        Exit 1
    }

#endregion


# Verifie qu'on est bien dans WORKGROUP AU DEPART
# Getting Info From The Local Computer
$localComputerSystem = Get-WMIObject Win32_ComputerSystem
$computerName = $localComputerSystem.Name
$actualDomain = $localComputerSystem.Domain
Write-ToLogFile "Computer $Computername is in domain $($actualDomain)"
$TCPIPDomain = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters').Domain
Write-ToLogFile "TCPIPDomain : $TCPIPDomain"
if (!($actualDomain -eq "WORKGROUP")) {
    # TODO Verifier qu'on est dans le bon domaine
    Write-ToLogFile "Computer is not in Workgroup : Script Exiting"
    Write-OperationFailed
    Exit 1
}




<#
#POULE ET OEUF : On peut pas vérifier que le compte existe dans le domain si on est pas dans le domain. On  peut pas rejoindre le domain, si le compte existe déjà
# Verifier que le computername n'existe pas dans le domaine. 
# Si c'est le cas et qu'on est pas dans le domaine, le supprimer au préalable
# Besoin d'installer le module ActiveDirectory pour vérifier sur le computerName n'est pas déjà dans l'AD
if (!(Get-WindowsFeature -Name "RSAT-AD-PowerShell").Installed) { 
    Install-WindowsFeature -Name "RSAT-AD-PowerShell" 
    if (!(Get-WindowsFeature -Name "RSAT-AD-PowerShell").Installed) { 
        Write-ToLogFile "Error installing RSAT-AD-PowerShell : $_"
        Write-OperationFailed
        exit 1
    }
}
# Get-ADComputer $computerName
#>


#region Interrogation AD
    Try {
        $try = 0
        while ($try -lt 10) {
            Write-ToLogFile "Querying Get-DSDirectory and waiting response"
            $Directory = Get-DSDirectory -region eu-west-1 -verbose # | ? {$_.Shortname -match "sandbox-aas"}
            if ($Directory) {break} else { $try++ }
        }
    }
    Catch {
        Write-ToLogFile "Fatal Error : $_"
        Write-OperationFailed
        Exit 1
    }


    Write-ToLogFile "Directory ID : $($Directory.DirectoryId)"
    Write-ToLogFile "Directory Name : $($Directory.Name)"
#endregion

#region Recupération du FQDN du 1er Domain Controlleur - nécessaire ensuite pour Join-SGAWSDOmain
    Write-ToLogFile "Resolving AD Host"
    Try {
        $fqdnRODC = (Resolve-DnsName  $Directory.DnsIpAddrs[0]).NameHost
    }
    Catch {
        Write-ToLogFile "Error Resolving AD Host : $_"
        Write-OperationFailed
        exit 1
    }
    Write-ToLogFile "FQDN AD 1 is : $($fqdnRODC)"
#endregion


#region Creation du compte ordi dans le domaine
    Write-ToLogFile "ComputerName is : $env:ComputerName"
    $NewDSComp = $null
    $computerAccountPWD = "COE-$(Get-Random)"
    Write-ToLogFile "Performing New-DSComputer"
    Try {
        $NewDSComp= New-DSComputer -DirectoryId $Directory.DirectoryId -ComputerName $env:ComputerName -Password $computerAccountPWD  #-ErrorVariable NewDSComp
    }
    Catch {
        Write-ToLogFile "Error Integration New-DSComputer : $_"
        Write-ToLogFile "Error Integration New-DSComputer : $($_.FullyQualifiedErrorId)"
        Write-OperationFailed
        exit 1
    }
    Write-ToLogFile "Computer account creation result : "
    ForEach ($key in $NewDSComp.ComputerAttributes.GetEnumerator()) {
        Write-ToLogFile "$($key.Name) : $($key.value)"
    }
#endregion

#region Join Domain

    $fqdnADdomain = $Directory.Name


    # Defining Required Constants
    Set-Variable JOIN_DOMAIN -option Constant -value 1                    # Joins a computer to a domain. If this value is not specified, the join is a computer to a workgroup
    Set-Variable MACHINE_PASSWORD_PASSED -option Constant -value 128    # The machine, not the user, password passed. This option is only valid for unsecure joins
    Set-Variable NETSETUP_JOIN_READONLY -option Constant -value 2048    # Use an RODC to perform the domain join against

    # Cumulative Value To Use 
    $readOnlyDomainJoinOption = $JOIN_DOMAIN + $MACHINE_PASSWORD_PASSED + $NETSETUP_JOIN_READONLY



    # Present The Gathered Information

    Write-ToLogFile "Trying To Perform A Read-Only Domain Join Using The Following Information..."
    Write-ToLogFile "FQDN AD Domain............: $fqdnADdomain"
    Write-ToLogFile "FQDN RODC.................: $fqdnRODC"
    Write-ToLogFile "Computer Name.............: $computerName"
    Write-ToLogFile "Computer Account Password.: $computerAccountPWD"

    # Performing The Read-Only Domain Join
    $errorCode = $localComputerSystem.JoinDomainOrWorkGroup($fqdnADdomain+"\"+$fqdnRODC,$computerAccountPWD,$null,$null,$readOnlyDomainJoinOption)
    # Error Handling
    # List of 'system error codes' (http://msdn.microsoft.com/en-us/library/ms681381.aspx) and 
    # List of 'network management error codes' (http://msdn.microsoft.com/en-us/library/aa370674(VS.85).aspx)
    $errorDescription = switch ($($errorCode.ReturnValue)) {
        0 {"SUCCESS: The Operation Completed Successfully."} 
        5 {"FAILURE: Access Is Denied."} 
        53 {"FAILURE: The Network Path Was Not Found."}
        64 {"FAILURE: The Specified Network Name Is No Longer Available."}
        87 {"FAILURE: The Parameter Is Incorrect."} 
        1326 {"FAILURE: Logon failure: Unknown Username Or Bad Password."} 
        1355 {"FAILURE: The Specified Domain Either Does Not Exist Or Could Not Be Contacted."} 
        2691 {"FAILURE: The Machine Is Already Joined To The Domain."} 
        default {"FAILURE: Unknown Error!"}
    }
    Write-ToLogFile "Domain Join Result Code...: $($errorCode.ReturnValue)"
    Write-ToLogFile "Domain Join Result Text...: $errorDescription"
    Write-ToLogFile "The Computer Account Password Will Be Reset Shortly After The Domain Join!"

    # Finishing Up

    If ($($errorCode.ReturnValue) -ne "0") {
        Write-ToLogFile "Domain integration failed"
        Write-OperationFailed
        exit 1
    }


#endregion


#region ADD Domain Users to group Remote Desktop Users
    #Get Local Group object 
    [adsi]$Localgroup="WinNT://$env:COMPUTERNAME/Remote Desktop Users"
    Write-ToLogFile "Local Group : $($Localgroup.Path)"
    #Get Domain Group object 
    #$DomainGroup = [ADSI]"WinNT://sandbox-aas.local/Domain Users" 
    #Write-ToLogFile "Domain Group : $($DomainGroup.Path)"
    #Assign DomainGroup to LocalGroup 
    #$LocalGroup.Add($DomainGroup.Path) 

    #En force avec le nom en dur, au moins comme ca ca passe meême si on est pas encore dans le domaine
    $DomainGroup = "WinNT://sandbox-aas.local/Domain Users" 
    Try {
        $LocalGroup.Add($DomainGroup) 
    }
    Catch {
        Write-ToLogFile "Error adding $DomainGroup to $($Localgroup.Path) : $_"
        Write-OperationFailed
        exit 1
    }
    Write-ToLogFile "Successfully add Domain group $DomainGroup to Local group $($Localgroup.Path)"
#endregion

<#
#region Removing EC2 Instance Role
    $instanceID = (Invoke-webrequest http://169.254.169.254/latest/meta-data/instance-id).content
    $asso = (Get-EC2IamInstanceProfileAssociation | where instanceID -eq $instanceID).AssociationId
    Write-ToLogFile "Unregister-EC2IamInstanceProfile"
    Unregister-EC2IamInstanceProfile -AssociationId $asso
    Write-ToLogFile "End of join_sandbox-aas_domain"
#endregion
#>

"JUMPHOST Provisionning Success"| Out-File $Resultfile

Write-ToLogFile "###### FINISHED ######"
Write-ToLogFile "-----------------------------------------------------"
#Write-ToLogFile "!!! THE COMPUTER WILL REBOOT AUTOMATICALLY IN 40 SECONDS !!!"
#Write-ToLogFile "!!! TO STOP THE REBOOT USE THE COMMAND: SHUTDOWN /A !!!"

# ShutDown will be performed by User-Data
#SHUTDOWN /R /T 40
