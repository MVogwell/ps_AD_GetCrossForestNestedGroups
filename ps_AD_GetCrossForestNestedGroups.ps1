#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
    .SYNOPSIS
    This PowerShell v5.1 script will create a report of Active Directory nested group members including trusted cross-forest/domains

    .DESCRIPTION
    The script works by first obtaining any required credentials to authenticate to foriegn trusted domains

    .OUTPUTS
    This function will return a csv file in the temp folder (unless an alternative path is specified in the startup parameter OutputFile) containing the results

    .PARAMETER GroupName
    Required. Specify the name of AD group in the local domain you want to report on.

    .PARAMETER OutputFile
    Optional. Use this parameter to specify an alternative location for the output csv file.

    .PARAMETER SkipDomainAuthentication
    Optional - String Array. If you want to skip discovery for a specific domain (for example if you don't have credentials for that domain) then you can specify an array of domains that should be skipped. The report file will show an error as it was unable to enumerate user objects for this domain(s).

    .EXAMPLE
    .\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "Group-Test"

    This would enumerate the members of the AD group "Group-Test" including any nested users/groups from trusted domains. The results file will be saved to the %TEMP% folder.

    .EXAMPLE
    .\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "Group-Test" -OutputFile c:\temp\results.csv

    This would enumerate the members of the AD group "Group-Test" including any nested users/groups from trusted domains. The results file would be saved to c:\temp\results.csv

    .EXAMPLE
    .\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "Group-Test" -SkipDomainAuthentication "domain1.com"

    This would enumerate the members of the AD group including any nested users/groups from trusted domains - except domain1.com which would be skipped.

	.EXAMPLE
    .\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "Group-Test" -SkipDomainAuthentication @("domain1.com","domain2.com")

    This would enumerate the members of the AD group including any nested users/groups from trusted domains - except domain1.com AND domain2.com which would be skipped.

    .NOTES
    Version history:
        1.0 - Initial tested release
        1.1 - Update to move functions into separate files
        1.2 - Implemented string-array group name inputs (was string)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string[]]$GroupName,
    [Parameter(Mandatory=$false)][string]$OutputFile,
    [Parameter(Mandatory=$false)][string[]]$SkipDomainAuthentication
)

# Preference set to stop on discovering an error
$ErrorActionPreference = "Stop"

# Initialise variables
$arrGroupsToProcess = New-Object System.Collections.ArrayList($null)
if ([string]::IsNullOrEmpty($OutputFile)) { $OutputFile = ($Env:Temp + "\GroupEnumerator_" + $GroupName + ".csv") }
$arrUserAttributes = @("ObjectClass","DistinguishedName","UserPrincipalName","samAccountName","Name","EmployeeId","mail","ObjectSid")
$arrGroupAttributes = @("ObjectClass","DistinguishedName","Name","ObjectSid")
[System.Collections.ArrayList]$arrGroupsToProcess = @()

$objInfoPref = $InformationPreference
$InformationPreference = "Continue"

Write-Information "`n`n=== ps_AD_GetCrossForestNestedGroups - Martin Vogwell - v1.2 === `n"

#@# Import Functions
try {
    Write-Verbose "*** Importing functions"

    . $PSScriptRoot\Functions\Get-ADTrustedDomain.ps1
    . $PSScriptRoot\Functions\Test-DomainAccess.ps1
    . $PSScriptRoot\Functions\Get-ADDomainCredential.ps1
    . $PSScriptRoot\Functions\Get-ADAccess.ps1
    . $PSScriptRoot\Functions\Get-ADLocalObject.ps1
    . $PSScriptRoot\Functions\Get-ADObjectDetail.ps1
    . $PSScriptRoot\Functions\Get-ADGroupMembersCrossForest.ps1
    . $PSScriptRoot\Functions\Get-MemberData.ps1

    Write-Verbose "`t+++ Success `n"
}
catch {
    $sErrMsg = $sErrMsg = ("Failed to import function(s): " + (($Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
    throw $sErrMsg
}

#@# Import the ActiveDirectory module
try {
    Write-Information "*** Importing ActiveDirectory for PowerShell module"

    Import-Module ActiveDirectory -Verbose:$false

    Write-Information "`t+++ Success `n"
}
catch {
    Write-Information "`t--- Failed - make sure the module is available on this machine. See https://learn.microsoft.com/en-us/powershell/module/activedirectory/ for more information. `n`n"

    Exit
}

#@# Check the specified group exists in AD and add the DistinguishedName to the arraylist containing the groups to invetigate
try {
    Write-Information "*** Confirming group availability in AD"

    foreach ($sGroupName in $GroupName) {
        Write-Information "`t=== Group: $sGroupName"

        $sRootGroupDN = Get-ADGroup -Identity $sGroupName | Select-Object -ExpandProperty DistinguishedName

        [void]$arrGroupsToProcess.Add($sRootGroupDN)

        Write-Information "`t`t+++ Successfully added"
    }

    if ($GroupName.GetType().Name -eq 'Object[]') {
        Write-Information "`t+++ Successfully added all requested groups to the queue`n"
    }
}
catch {
    Write-Information "`t--- Failed to find the specified group in the local Active Directory `n`n"

    # No point in carrying on - exit the script
    Exit
}


#@# Get a list of the trusted domains
try {
    Write-Information "*** Enumerating trusted domains"

    # Add the current "local" domain then any trusted domains
    $arrTrustedDomains = @((Get-ADDomain).DnsRoot)
    $arrTrustedDomains += Get-ADTrustedDomain

    Write-Information "`t+++ Success `n"
}
catch {
    Write-Information "`t--- Failed to discover trusted domains. `n`n"

    Exit
}

#@# Get the name of the current Domain name and LDAP root DN
try {
    Write-Information "*** Enumerating local domain information"

    $sLocalDomainRoot = (Get-ADDomain).DistinguishedName
    $sLocalDomainName = (Get-ADDomain).DNSRoot

    Write-Information "`t+++ Success `n"
}
catch {
    Write-Information "`t--- Failed to run the cmdlet Get-ADDomain `n`n"

    Exit
}

#@# List the known trusted domains
Write-Information "*** List of trusted domains"
$arrTrustedDomains | ForEach-Object { Write-Information "`t+++ $($_)" }

#@# Get the credentials for each domain (if required)
Write-Information "`n*** Evaluating domain access (credentials may be requested)"

#@# Validate SkipDomainAuthentication
# If no domains were specified to *** SKIP *** then add a "dumb" entry so calling the function doesn't error
# If the value passed for SkipDomainAuthentication is a string not an array then convert it into an array
if ([String]::IsNullOrEmpty($SkipDomainAuthentication)) {
    $SkipDomainAuthentication = @("NoDomainsToSkip")
}
elseif ($SkipDomainAuthentication.GetType().Name -eq "string") {
    $SkipDomainAuthentication = @($SkipDomainAuthentication)
}

#@# Call the function Get-ADAccess - this will request credentials for a domain unless authentication is not required
try {
    $arrDomainInfo = Get-ADAccess -arrTrustedDomains $arrTrustedDomains -arrSkipDomainAuthentication $SkipDomainAuthentication
}
catch {
    $sErrMsg = ("Failed to obtain required authentication: " + (($Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))

    Write-Information "`t--- $sErrMsg `n`n"

    Remove-Variable sErrMsg -ErrorAction "SilentlyContinue"

    Exit
}

#@# Show the results of the trusted domain list
$arrDomainInfo | ForEach-Object {
    Write-Verbose "`t=== Domain: $($_.DomainName) :: Domain SID: $($_.DomainSid)"
}

Write-Information "`t+++ Successfully authenticated against trusted domains `n"

#@# PROCESS

try {
    Write-Information "*** Processing group membership... please wait"

    $param_GetMemberData = @{
        arrGroupsToProcess = $arrGroupsToProcess
        arrDomainInfo = $arrDomainInfo
        arrUserAttributes = $arrUserAttributes
        arrGroupAttributes = $arrGroupAttributes
        sLocalDomainRoot = $sLocalDomainRoot
        sLocalDomainName = $sLocalDomainName
    }

    $arrGroupMemberResults = Get-MemberData @param_GetMemberData

    Write-Information "`t+++ Success `n"
}
catch {
    $sErrMsg = ("Failed to process group membership: " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
    Write-Information "`t--- $sErrMsg `n"

    throw $sErrMsg
}

#@# END

# Export to file
if (!($null -eq $arrGroupMemberResults)) {
    try {
        Write-Information "`n*** Writing results to file"

        $arrGroupMemberResults | ConvertTo-CSV -NoTypeInformation | Out-File $OutputFile -Encoding utf8 -Force

        Write-Information "`t+++ Success"
        Write-Information "`t+++ File: $OutputFile `n`n"
    }
    catch {
        $sErrMsg = ("Failed to write results to output file $($OutputFile): " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
        Write-Information "`t--- $sErrMsg `n`n"
    }
}

# Tidy up
Remove-Variable arrGroupMemberResults,arrDomainInfo,arrGroupMembers,arrTrustedDomains,sLocalDomainName,SkipDomainAuthentication,sLocalDomainRoot,sRootGroupDN,arrGroupAttributes,arrGroupsToProcess,arrUserAttributes,GroupName,OutputFile,OutputFile,param_GetMemberData -ErrorAction "SilentlyContinue"

Write-Information "*** FINISHED *** `n`n"

# Reset information preference back to the original value
$InformationPreference = $objInfoPref