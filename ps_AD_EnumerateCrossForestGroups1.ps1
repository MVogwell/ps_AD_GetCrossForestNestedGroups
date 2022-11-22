#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
    .SYNOPSIS
    This PowerShell v5.1 script will create a report of Active Directory nested group members including trusted cross-forest/domains

    .DESCRIPTION
    The script works by first obtaining any required credentials to authenticate to foriegn domains

    .OUTPUTS
    This function will return a csv file in the temp folder (unless an alternative path is specified in the startup parameter OutputFile) containing the results

    .PARAMETER GroupName
    Required. Specify the name of AD group in the local domain you want to report on.

    .PARAMETER OutputFile
    Optional. Use this parameter to specify an alternative location for the output csv file.

    .PARAMETER SkipDomainAuthentication
    Optional - String Array. If you want to skip discovery for a specific domain (for example if you don't have credentials for that domain) then you can specify an array of domains that should be skipped. The report file will show an error as it was unable to enumerate user objects for this domain(s).

    .EXAMPLE
    ps_AD_EnumerateCrossForestGroups.ps1 -GroupName "Group-Test"

    This would enumerate the members of the AD group "Group-Test" including any nested users/groups from trusted domains. The results file will be saved to the %TEMP% folder.

    .EXAMPLE
    ps_AD_EnumerateCrossForestGroups.ps1 -GroupName "Group-Test" -OutputFile c:\temp\results.csv

    This would enumerate the members of the AD group "Group-Test" including any nested users/groups from trusted domains. The results file would be saved to c:\temp\results.csv

    .EXAMPLE
    ps_AD_EnumerateCrossForestGroups.ps1 -GroupName "Group-Test" -SkipDomainAuthentication "domain1.com"

    This would enumerate the members of the AD group including any nested users/groups from trusted domains - except domain1.com which would be skipped.    

    .NOTES
    MVogwell - November 2022 - Version 1.0

    Version history:
        1.0 - Initial tested release
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$false)][string]$OutputFile,
    [Parameter(Mandatory=$false)][string[]]$SkipDomainAuthentication

)

# Preference set to stop on discovering an error
$ErrorActionPreference = "Stop"

Function Get-ADTrustedDomain() {
    <#
        .SYNOPSIS
        Function to return FQDNs of trusted Active Directory domains. Requires the "Active Directory for PowerShell module"

        .PARAMETER Server
        Optional. Set the server (or domain name) to request the information from

        .PARAMETER objCredential
        Optional. Set the credential to use

        .NOTES
        Version 1.0 - Initial release
    #>
    
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param (
        [Parameter(Mandatory=$false)][string]$Server,
        [Parameter(Mandatory=$false)][PSCredential]$Credential
    )

    # Set the default parameter to call Get-ADTrust
    $param_ADTrust = @{
        Filter = "*"
    }

    # Add the server name if provided
    if ([string]::IsNullOrEmpty($Server) -eq $false) {
        $param_ADTrust.Server = $Server
    }

    # Add the credential if provided
    if (!($null -eq $Credential)) {
        $param_ADTrust.Credential = $Credential
    }

    $arrTrustedDomains = (Get-ADTrust @param_ADTrust).Target

    return $arrTrustedDomains
}

Function Test-DomainAccess() {
    param (
        [Parameter(Mandatory=$true)][string]$sDomainName,
        [Parameter(Mandatory=$false)][pscredential]$objCredential
    )

    try {
        if ($null -eq $objCredential) {
            Write-Verbose "`t`t+++ Testing $sDomainName WITHOUT credentials"

            $sDomainSid = (Get-ADDomain $sDomainName -Server $sDomainName | Select-Object -ExpandProperty DomainSID).toString().SubString(0,19)
        }
        else {
            Write-Verbose "`t`t+++ Testing $sDomainName with credentials"

            $sDomainSid = (Get-ADDomain $sDomainName -Credential $objCredential -Server $sDomainName | Select-Object -ExpandProperty DomainSID).toString().SubString(0,19)
        }

        Write-Verbose "`t`t`t+++ Test-DomainAccess returned domainSid $sDomainSid"

        return $sDomainSid
    }
    catch {
        Write-Verbose "`t+++ Test-DomainAccess returned domainSid: FAILED"

        $sErrMsg = (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," ")

        return $sErrMsg
    }
}

Function Get-ADDomainCredential() {
    param (
        [Parameter(Mandatory=$true)][string]$sDomainName
    )

    # Request the credential from the user
    try {
        Write-Verbose "`t`t=== Requesting Credentials"

        $objCredential = Get-Credential -Message "Enter the credentials for domain $($sDomainName). If credentials are not required for this group hit escape."

        if ($null -eq $objCredential) {
            throw "Failed to obtain credential from user"
        }
    }
    catch {
        Write-Verbose "`t`t`t--- FAILED TO GET CREDENTIAL FROM USER"

        $sErrMsg = ("Domain: " + $sDomainName + " (no credential provided)")

        throw $sErrMsg
    }

    # Only test if the credentials were successfully captured
    if (!($null -eq $objCredential)) {
        $sDomainSid = Test-DomainAccess -sDomainName $sDomainName -objCredential $objCredential
    }

    if ($sDomainSid -match "^S\-") {
        Write-Output "`t`t+++ Successfully tested"

        $objReturn = [PSCustomObject] @{
            Credential = $objCredential
            DomainSid = $sDomainSid
        }
        return $objReturn
    }
    else {
        Write-Verbose "`t`t--- Failed to discover DomainSid"

        $sErrMsg = "Domain: " + $sDomainName + " (" + $sDomainSid + ")"

        throw $sErrMsg
    }
}

Function Get-ADAccess() {
    param (
        [string[]]$arrTrustedDomains,
        [string[]]$arrSkipDomainAuthentication
    )

    Write-Verbose "*** Function: Get-ADAccess -- Getting domain info and credentials"

    # Initialise variable
    [System.Collections.ArrayList]$arrDomainData = @()

    # Loop through each trusted domain specified in the parameters
    foreach ($sTrustedDomain in $arrTrustedDomains) {
        Write-Verbose "*** Testing $($sTrustedDomain)"

        if ($arrSkipDomainAuthentication -contains $sTrustedDomain) {
            Write-Verbose "`t--- Skipping domain $sTrustedDomain"

            $objDomainData = [PSCustomObject] @{
                DomainName = $sTrustedDomain
                Credential = "SKIPPED"
                DomainSid = "SKIPPED"
            }
        }
        else {
            $sDomainSid = Test-DomainAccess -sDomainName $sTrustedDomain

            if ($sDomainSid -match "^S\-") {
                # No credential required
                Write-Verbose "`t+++ No credential required. DomainSid = $sDomainSid"

                # return null because no credential is required
                $objDomainData = [PSCustomObject] @{
                    DomainName = $sTrustedDomain
                    Credential = $null
                    DomainSid = $sDomainSid
                }

                Write-Verbose "`t+++ Domain: $sTrustedDomain - no credentials required"
            }
            else {
                Write-Verbose "`t+++ Credential required to access domain $sTrustedDomain"

                $objDomainInfo = Get-ADDomainCredential -sDomainName $sTrustedDomain

                Write-Verbose "`t`t+++ DomainSid = $($objDomainInfo.DomainSid)"

                $objDomainData = [PSCustomObject] @{
                    DomainName = $sTrustedDomain
                    Credential = $objDomainInfo.Credential
                    DomainSid = $objDomainInfo.DomainSid
                }

                Write-Verbose "`t+++ Domain: $sTrustedDomain - credentials required - tested credentials successfully"
            }
        }

        [void]$arrDomainData.Add($objDomainData)

        Remove-Variable objDomainData,objDomainInfo -ErrorAction "SilentlyContinue"
    }

    return $arrDomainData
}

Function Get-ADLocalObject() {
    param (
        [Parameter(Mandatory=$true)][string]$sObjectName,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes,
        [Parameter(Mandatory=$true)][string]$sTargetDomain
    )

    Write-Verbose "*** Function: Get-ADLocalObject :: $sObjectName"

    # A prefix of RG= is used to identify the 'owning' group for an object. This is used in the report to report on which
    # group the object is a member of.
    if ($sObjectName -match "^RG=") {
        $sOwningGroup = ($sObjectName.Split(",")[0].Replace("RG=",""))
        $sObjectName = $sObjectname.Substring($sObjectName.IndexOf(",") + 1)
    }

    try {
        Write-Verbose "`t=== Searching local AD for $sObjectName"

        $arrADObject = Get-ADObject -Identity $sObjectName -Properties member,CanonicalName | Select-Object Name,ObjectClass,DistinguishedName,member,CanonicalName

        if ($null -eq $arrADObject) {
            $sErrMsg = "Failed to find " + $sObjectName + " in local AD"
            throw $sErrMsg
        }
        else {
            Write-Verbose "`t+++ Object discovered in AD. ObjectType = $($arrADObject.ObjectClass)"

            # The function Get-ADObjectDetail required an array object of DistinguishedNames to target
            $arrMembers = @([PSCustomObject] @{DistinguishedName=$arrADObject.DistinguishedName;ObjectClass='user'})

            if ($arrADObject.ObjectClass -eq 'user') {
                $param_MemberDetails = @{
                    sTargetDomain = $sTargetDomain
                    sOwningGroup = $sOwningGroup
                    arrTargetDN = $arrMembers
                    arrUserAttributes = $arrUserAttributes
                    arrGroupAttributes = $arrGroupAttributes
                }

                $arrMemberDetails = Get-ADObjectDetail @param_MemberDetails

                return $arrMemberDetails
            }
            else {
                [string[]]$arrReturnObjectDn = @()

                $sOwningGroup = ($arrADObject.CanonicalName).Replace(",","_")

                foreach ($sMember in $arrADObject.member) {
                    # This adds RG= to the start of the distinguishedName. This is used to identify the group
                    # that the object belongs to.

                    $arrReturnObjectDn += "RG=" + $sOwningGroup + "," + $sMember
                }

                Write-Verbose "`t+++ Returning $($arrReturnObjectDn.Count) objects for analysis"

                return [string[]]$arrReturnObjectDn
            }
        }
    }
    catch {
        $sErrMsg = ("Failed to enumerate AD Group $($sObjectName): " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))

        throw $sErrMsg
    }
}

Function Get-ADObjectDetail() {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory=$false)][PSCredential]$objCredential,
        [Parameter(Mandatory=$true)][string]$sTargetDomain,
        [Parameter(Mandatory=$true)][string]$sOwningGroup,
        [Parameter(Mandatory=$true)][Object[]]$arrTargetDN,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes
    )

    Write-Verbose "*** Function: Get-ADObjectDetail - Retrieving AD Object Details"

    [System.Collections.ArrayList]$arrADObjResults = @()

    # Add the TargetDomain and Owning Group detail
    $arrADUserAttributes = $arrUserAttributes | Where-Object {$_ -ne "ObjectSid"}
    $arrADUserAttributes += @{n='ObjectSid';e={($_.ObjectSid).toString()}}
    $arrADUserAttributes += @{n='SourceDomain';e={$sTargetDomain}}
    $arrADUserAttributes += @{n='OwningGroup';e={$sOwningGroup}}

    # Add the TargetDomain and Owning Group detail
    $arrADGroupAttributes = $arrGroupAttributes | Where-Object {$_ -ne "ObjectSid"}
    $arrADGroupAttributes += @{n='ObjectSid';e={($_.ObjectSid).toString()}}
    $arrADGroupAttributes += @{n='SourceDomain';e={$sTargetDomain}}
    $arrADGroupAttributes += @{n='OwningGroup';e={$sOwningGroup}}

    foreach ($objTargetDN in $arrTargetDN) {
        try {
            if ($objTargetDN.ObjectClass -eq 'user') {
                Write-Verbose "`t=== Retrieving user details: $($objTargetDN.DistinguishedName)"

                if ($null -eq $objCredential) {
                    $objADEntity = Get-ADUser -Identity $objTargetDN.DistinguishedName -Properties $arrUserAttributes -Server $sTargetDomain | Select-Object $arrADUserAttributes
                }
                else {
                    $objADEntity = Get-ADUser -Identity $objTargetDN.DistinguishedName -Properties $arrUserAttributes -Server $sTargetDomain -Credential $objCredential | Select-Object $arrADUserAttributes
                }
            }
            else {
                Write-Verbose "`t=== Retrieving group details: $($objTargetDN.DistinguishedName)"

                if ($null -eq $objCredential) {
                    $objADEntity = Get-ADGroup -Identity $objTargetDN.DistinguishedName -Properties $arrGroupAttributes -Server $sTargetDomain | Select-Object $arrADGroupAttributes
                }
                else {
                    $objADEntity = Get-ADGroup -Identity $objTargetDN.DistinguishedName -Properties $arrGroupAttributes -Server $sTargetDomain -Credential $objCredential | Select-Object $arrADGroupAttributes
                }
            }
        }
        catch {
            Write-Verbose "`t`t--- Failed to discover user/group details. Creating empty return object"

            # Create a result object containing the known info about the object but without the full AD returned data
            $objADEntity = new-object PSCustomObject

            # Add the empty attributes according to the value of the object's ObjectClass attribute
            if ($objTargetDN.ObjectClass -eq 'user') {
                foreach ($sAttribute in $arrUserAttributes) {
                   $objADEntity | Add-Member -MemberType NoteProperty -Name $sAttribute -Value ""
                }
            }
            else {
                foreach ($sAttribute in $arrGroupAttributes) {
                    $objADEntity | Add-Member -MemberType NoteProperty -Name $sAttribute -Value ""
                }
            }

            # Add compulsory properties
            $sErrMsg = ("Failed to discover AD Object details. Error: " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
            $objADEntity | Add-Member -MemberType NoteProperty -Name "Error" -Value $sErrMsg -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value $objTargetDN.ObjectClass -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $objTargetDN.DistinguishedName -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "TargetDomain" -Value $sTargetDomain -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "OwningGroup" -Value $sOwningGroup -Force
        }

        # Add the result to the array
        [void]$arrADObjResults.Add($objADEntity)

        # Tidy up
        Remove-Variable objADEntity -ErrorAction "SilentlyContinue"
    }

    return $arrADObjResults
}

Function Get-ADGroupMembersCrossForest() {
    param (
        [Parameter(Mandatory=$true)][PSCustomObject[]]$arrDomainInfo,
        [Parameter(Mandatory=$true)][string]$sTargetMember,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes
    )

    <# What it does
        Extracts the SID from the DN provided in sTargetMember
        Finds the matching domain info (name and credential) based on the first 19 characters of the SID
        Gets the DistinguishedName, Name and ObjectClass information of the cross forest object
        If the returned object is a group - get the members of the cross forest group
        Call function Get-ADObjectDetail to get user and group details
        Return the details returned by Get-ADObjectDetail
    #>

    # Initialise
    $sOwningGroup = ""      # This is required to prevent the string from being null

    # A prefix of RG= is used to identify the 'owning' group for an object. This is used in the report to report on which
    # group the object is a member of.
    if ($sTargetMember -match "^RG=") {
        $sOwningGroup = ($sTargetMember.Split(",")[0].Replace("RG=",""))
        $sTargetMember = $sTargetMember.Substring($sTargetMember.IndexOf(",") + 1)
    }

    Write-Verbose "*** Function Get-ADGroupMembersCrossForest :: Processing object $sTargetMember"

    # Extract the SID of the member object
    $sTargetADObjectSid = $sTargetMember.Split(",")[0].Replace("CN=","")

    # Escape from the function if the SID could not be extrapolated
    if (([string]::IsNullOrEmpty($sTargetADObjectSid)) -or ($sTargetADObjectSid.Length -eq 0)) {
        throw "Failed to extract ObjectSid for group member (where the source is a foreign domain)"
    }

    Write-Verbose "`t+++ Target Object SID: $sTargetADObjectSid"

    # Find the source domain from arrDomainInfo based on the first 19 characters of the ObjectSid
    $objTargetDomain = $arrDomainInfo | Where-Object {$_.DomainSid -eq $sTargetADObjectSid.Substring(0,19)}

    # Escape from the function if the target domain could not be found
    if ($null -eq $objTargetDomain) {
        $sErrMsg = "Failed to discover target domain for SID " + $sTargetADObjectSid

        throw $sErrMsg
    }
    elseif ($objTargetDomain.DomainSid -match "FAILED|SKIPPED") {
        $sErrMsg = ("Unable to perform lookup against target domain " + $objTargetDomain.DomainName + " there are no credentials available for this domain")
        throw $sErrMsg
    }

    Write-Verbose "`t+++ Object source domain: $($objTargetDomain.DomainName)"

    # Find the object in the source domain by searching for the SID. This is required to get the non-SID identity of the object
    try {
        if ($null -eq $objTargetDomain.Credential) {
            Write-Verbose "`t+++ Searching target domain (without credential)"

            $objADTargetObject = Get-ADObject -Filter "ObjectSid -eq '$sTargetADObjectSid'" -Server $objTargetDomain.DomainName -Properties CanonicalName | Select-Object ObjectGuid,Name,ObjectClass,DistinguishedName,CanonicalName
        }
        else {
            Write-Verbose "`t=== Searching target domain using credential"

            $objADTargetObject = Get-ADObject -Filter "ObjectSid -eq '$sTargetADObjectSid'" -Server $objTargetDomain.DomainName -Credential $objTargetDomain.Credential -Properties CanonicalName | Select-Object ObjectGuid,Name,ObjectClass,DistinguishedName,CanonicalName
        }
    }
    catch {
        $sErrMsg = ("Failed to request ObjectSid " + $sTargetADObjectSid + " from domain " + $objTargetDomain.DomainName + ". Error: " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
        throw $sErrMsg
    }

    # Check that something was found then enumerate the group members from the source domain
    if ($null -eq $objADTargetObject) {
        $sErrMsg = "Object with SID " + $sTargetADObjectSid + " not found in target domain " + $objTargetDomain.DomainName
        throw $sErrMsg
    }
    else {
        if ($objADTargetObject.ObjectClass -eq 'group') {
            Write-Verbose "`t=== Target objectClass: group"
            $arrMembers = Get-ADGroupMember -Identity ($objADTargetObject.ObjectGuid).toString() -Server $objTargetDomain.DomainName -Credential $objTargetDomain.Credential | Select-Object DistinguishedName, ObjectClass
        }
        else {
            Write-Verbose "`t=== Target objectClass: $($objADTargetObject.ObjectClass)"

            [object[]]$arrMembers = ($objADTargetObject | Select-Object DistinguishedName, ObjectClass)
        }

        # Retrieve the user details
        try {
            $param_MemberDetails = @{
                sTargetDomain = $objTargetDomain.DomainName
                arrTargetDN = $arrMembers
                arrUserAttributes = $arrUserAttributes
                arrGroupAttributes = $arrGroupAttributes
            }

            # If the owning group has been specified in the original sTargetMember using the RG= prefix
            # then use the sOwningGroup value otherwise use the group name derived from Get-ADGroupMember in
            # this function.
            if ([string]::IsNullOrEmpty($objADTargetObject.Name)) {
                $param_MemberDetails.sOwningGroup = $sOwningGroup
            }
            else {
                $param_MemberDetails.sOwningGroup = $objADTargetObject.CanonicalName
            }

            # If a credential is available for the trusted domain add the credential object
            if (!($null -eq $objTargetDomain.Credential)) {
                $param_MemberDetails.objCredential = $objTargetDomain.Credential
            }

            # If the discovered cross forest object is a user (not a group) then remove the sOwningGroup detail
            if ($objADTargetObject.ObjectClass -eq "user") {
                if ([string]::IsNullOrEmpty($sOwningGroup) -eq $false) {
                    $param_MemberDetails.sOwningGroup = $sOwningGroup
                }
                else {
                    $param_MemberDetails.sOwningGroup = "None-UserAddedDirectly"
                }
            }

            $arrMemberDetails = Get-ADObjectDetail @param_MemberDetails
        }
        catch {
            $sErrMsg = ("Failed to discover user details. Error: " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
            throw $sErrMsg
        }
    }

    Write-Verbose "`t+++ Completed extracting AD object information `n"

    return $arrMemberDetails
}

#@# Main

#@# BEGIN

# Initialise variables
[System.Collections.ArrayList]$arrGroupMemberResults = @()        # Contains results data
$arrGroupsToProcess = New-Object System.Collections.ArrayList($null)
if ([string]::IsNullOrEmpty($OutputFile)) { $OutputFile = ($Env:Temp + "\GroupEnumerator_" + $GroupName + ".csv") }
$arrUserAttributes = @("ObjectClass","DistinguishedName","UserPrincipalName","samAccountName","Name","EmployeeId","mail","ObjectSid")
$arrGroupAttributes = @("ObjectClass","DistinguishedName","Name","ObjectSid")
[System.Collections.ArrayList]$arrGroupsToProcess = @()

try {
    Write-Output "*** Importing ActiveDirectory for PowerShell module"

    Import-Module ActiveDirectory -Verbose:$false

    Write-Output "`t+++ Success `n"
}
catch {
    Write-Output "`t--- Failed - make sure the module is available on this machine. See https://learn.microsoft.com/en-us/powershell/module/activedirectory/ for more information. `n`n"

    Exit
}


# Check the group exists
# Check the group exists in AD and add the DistinguishedName to the arraylist containing the groups to invetigate
try {
    Write-Output "*** Confirming group availability in AD"

    $sRootGroupDN = Get-ADGroup -Identity $GroupName | Select-Object -ExpandProperty DistinguishedName

    [void]$arrGroupsToProcess.Add($sRootGroupDN)

    Write-Output "`t+++ Success `n"
}
catch {
    Write-Output "`t--- Failed to find the specified group in the local Active Directory `n`n"

    # No point in carrying on - exit the script
    Exit
}


# Get a list of the trusted domains
try {
    Write-Output "*** Enumerating trusted domains"

    # Add the current "local" domain then any trusted domains
    $arrTrustedDomains = @((Get-ADDomain).DnsRoot)
    $arrTrustedDomains += Get-ADTrustedDomain

    Write-Output "`t+++ Success `n"
}
catch {
    Write-Output "`t--- Failed to discover trusted domains. `n`n"

    Exit
}

# Get the name of the current Domain name and LDAP root DN
try {
    Write-Output "*** Enumerating local domain information"

    $sLocalDomainRoot = (Get-ADDomain).DistinguishedName
    $sLocalDomainName = (Get-ADDomain).DNSRoot

    Write-Output "`t+++ Success `n"
}
catch {
    Write-Output "`t--- Failed to run the cmdlet Get-ADDomain `n`n"

    Exit
}

# List the known trusted domains
Write-Output "*** List of known domains"
$arrTrustedDomains | ForEach-Object { Write-Output "`t+++ $($_)" }

# Get the credentials for each domain (if required)
Write-Output "`n*** Evaluating domain access (credentials may be requested)"

# If no domains were specified to *** SKIP *** then add a "dumb" entry so calling the function doesn't error
# If the value passed for SkipDomainAuthentication is a string not an array then convert it into an array
if ([String]::IsNullOrEmpty($SkipDomainAuthentication)) {
    $SkipDomainAuthentication = @("NoDomainsToSkip")
}
elseif ($SkipDomainAuthentication.GetType().Name -eq "string") {
    $SkipDomainAuthentication = @($SkipDomainAuthentication)
}

# Call the function Get-ADAccess - this will request credentials for a domain unless authentication is not required
try {
    $arrDomainInfo = Get-ADAccess -arrTrustedDomains $arrTrustedDomains -arrSkipDomainAuthentication $SkipDomainAuthentication
}
catch {
    $sErrMsg = ("Failed to obtain required authentication: " + (($Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))

    Write-Output "`t--- $sErrMsg `n`n"

    Exit
}

# Show the results of the trusted domain list
$arrDomainInfo | ForEach-Object {
    Write-Verbose "`t=== Domain: $($_.DomainName) :: Domain SID: $($_.DomainSid)"
}

Write-Output "`t+++ Successfully authenticated against trusted domains `n"

#@# PROCESS

# Recursively enumerate group members and extract the details
Do {
    Write-Output "*** Processing group member $($arrGroupsToProcess[0])"

    # Check if the group is local or in a trusted domain
    try {
        if ($arrGroupsToProcess[0] -match "CN=ForeignSecurityPrincipals") { # Group/User is in a trusted domain
            $arrReturnedMembers = Get-ADGroupMembersCrossForest -arrDomainInfo $arrDomainInfo -sTargetMember $arrGroupsToProcess[0] -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes
        }
        else {
            $arrReturnedData = Get-ADLocalObject -sObjectName $arrGroupsToProcess[0] -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes -sTargetDomain $sLocalDomainName

            if ($arrReturnedData.GetType().Name -eq 'PSCustomObject') {
                $arrReturnedMembers = @($arrReturnedData)
            }
            else {
                if ($arrReturnedData.Count -eq 1) {
                    [void]$arrGroupsToProcess.Add($arrReturnedData)
                }
                else {
                    [void]$arrGroupsToProcess.AddRange($arrReturnedData)
                }

                # Create an empty arrReturnedMembers as no user data has been returned
                $arrReturnedMembers = @()
            }
        }

        Write-Output "`t+++ Success `n"
    }
    catch {
        if ($arrGroupsToProcess[0] -match "^RG=") {
            $sFailedUserDn = $arrGroupsToProcess[0].Substring($arrGroupsToProcess[0].indexof(",") +1)
            $sOwningGroup = $arrGroupsToProcess[0].Split(",")[0].Replace("RG=","")
        }
        else {
            $sFailedUserDn = $arrGroupsToProcess[0]
            $sOwningGroup = "Unknown"
        }

        $objFailedUser = [PSCustomObject]@{
            ObjectClass = "Error"
            DistinguishedName = $sFailedUserDn
            UserPrincipalName = (($Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," ")
            SourceDomain = "Unknown"
            OwningGroup = $sOwningGroup
        }

        $arrReturnedMembers = @($objFailedUser)

        Write-Output "`t--- $sErrMsg `n"
    }

    Write-Verbose "*** MAIN :: Processing returned users"

    # Loop through each result - only add the AD object if it isn't already in the list
    foreach ($objReturnedMember in $arrReturnedMembers) {
        if (!($arrGroupMemberResults.DistinguishedName -contains $objReturnedMember.DistinguishedName)) {
            Write-Verbose "`t+++ Accepted user $($objReturnedMember.DistinguishedName)"

            [void]$arrGroupMemberResults.Add($objReturnedMember)

            # Check if the result member is a group - if it is then add it to the array of groups to process
            # add the DN only and convert groups from "foreign" domains as SIDs with the DN containing CN=ForeignSecurityPrincipals
            if ($objReturnedMember.ObjectClass -eq 'group') {
                if ($objReturnedMember.DomainName -ne $sLocalDomainName) {
                    $sDistinguishedNameToProcess = ("CN=" + $objReturnedMember.ObjectSid + ",CN=ForeignSecurityPrincipals," + $sLocalDomainRoot)
                }
                else {
                    $sDistinguishedNameToProcess = $objReturnedMember.DistinguishedName
                }

                Write-Verbose "`t=== Adding group to process to stack: $sDistinguishedNameToProcess"

                [void]$arrGroupsToProcess.Add($sDistinguishedNameToProcess)

                Remove-Variable sDistinguishedNameToProcess -ErrorAction "SilentlyContinue"
            }
        }
        else {
            Write-Verbose "`t+++ DUPLICATE User not added $($objReturnedMember.DistinguishedName)"
        }
    }

    Remove-Variable arrReturnedMembers -ErrorAction "SilentlyContinue"

    # Remove the first element of the array - this reduces the stack of groups to process after processing the current 0 element
    # Once all groups have been processed it will be removed
    [void]$arrGroupsToProcess.RemoveAt(0)

} While ($arrGroupsToProcess.Count -gt 0)

#@# END

# Export to file
try {
    Write-Output "`n*** Writing results to file"

    $arrGroupMemberResults | ConvertTo-CSV -NoTypeInformation | Out-File $OutputFile -Encoding utf8 -Force

    Write-Output "`t+++ Success"
    Write-Output "`t+++ File: $OutputFile `n`n"
}
catch {
    $sErrMsg = ("Failed to write results to output file $($OutputFile): " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
    Write-Output "`t--- $sErrMsg `n`n"
}


# Tidy up
Remove-Variable arrGroupMemberResults,arrDomainInfo,arrGroupMembers,arrTrustedDomains -ErrorAction "SilentlyContinue"

Write-Output "*** FINISHED ***"