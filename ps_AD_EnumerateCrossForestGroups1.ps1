[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$false)][string]$OutputFile,
    [Parameter(Mandatory=$false)][string[]]$SkipDomainAuthentication

)

$ErrorActionPreference = "Stop"


Function Get-ADTrustedDomains() {
    $arrTrustedDomains = (Get-ADTrust -Filter *).Target

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

        return "FAILED"
    }
}

Function Get-ADDomainCredential() {
    param (
        [Parameter(Mandatory=$true)][string]$sDomainName
    )

    # Write-Output "Please enter the user credentials for domain $($sDomainName). If you don't have them hit escape"

    # Request the credential from the user
    try {
        Write-Verbose "`t`t=== Requesting Credentials"

        $objCredential = Get-Credential -Message "Enter the credentials for domain $($sDomainName). If credentials are not required for this group hit escape."
    }
    catch {
        Write-Verbose "`t`t`t--- FAILED TO GET CREDENTIAL FROM USER"

        # xxxxx change to an empty pscredential object
        $objCredential = $null
        $sDomainSid = "FailedToGetCredentials"
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
        Write-Output "`t`t--- Failed to discover DomainSid"

        throw "Failed to test provided credentials"
    }
}

Function Get-ADAccess() {
    param (
        [string[]]$arrTrustedDomains,
        [string[]]$arrSkipDomainAuthentication
    )

    Write-Verbose "*** Getting domain info and credentials"

    [System.Collections.ArrayList]$arrDomainData = @()

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

                try {
                    $objDomainInfo = Get-ADDomainCredential -sDomainName $sTrustedDomain

                    Write-Verbose "`t`t+++ DomainSid = $($objDomainInfo.DomainSid)"

                    $objDomainData = [PSCustomObject] @{
                        DomainName = $sTrustedDomain
                        Credential = $objDomainInfo.Credential
                        DomainSid = $objDomainInfo.DomainSid
                    }

                    Write-Verbose "`t+++ Domain: $sTrustedDomain - credentials required - tested credentials successfully"
                }
                catch {
                    Write-Verbose "`t+++ Failed to authenticate to domain $($_)"

                    $objDomainData = [PSCustomObject] @{
                        DomainName = $sTrustedDomain
                        Credential = "FAILED"
                        DomainSid = "FAILED"
                    }

                    Write-Verbose "`t+++ Domain: $sTrustedDomain - credentials required - tested credentials FAILED"
                }
            }
        }

        [void]$arrDomainData.Add($objDomainData)

        Remove-Variable objDomainData,objDomainInfo -ErrorAction "SilentlyContinue"
    }

    return $arrDomainData
}

Function Get-ADLocalGroupMembership() {
    param (
        [Parameter(Mandatory=$true)][string]$sGroupName
    )    

    try {
        $arrGroupMembers = Get-ADGroup -Identity $sGroupName -Properties member | Select-Object -ExpandProperty member

        return $arrGroupMembers
    }
    catch {
        $sErrMsg = ("Failed to enumerate AD Group $($sGroupName): " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))

        throw $sErrMsg
    }
}

Function Get-ADLocalObject() {
    param (
        [Parameter(Mandatory=$true)][string]$sObjectName,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes,
        [Parameter(Mandatory=$true)][string]$sTargetDomain
    )    

    Write-Verbose "Function: Get-ADLocalObject :: $sObjectName"

    # A prefix of RG= is used to identify the 'owning' group for an object. This is used in the report to report on which
    # group the object is a member of.
    if ($sObjectName -match "^RG=") {
        $sOwningGroup = ($sObjectName.Split(",")[0].Replace("RG=",""))
        $sObjectName = $sObjectname.Substring($sObjectName.IndexOf(",") + 1)
    }

    try {
        Write-Verbose "`t=== Searching local AD for $sObjectName"

        $arrADObject = Get-ADObject -Identity $sObjectName -Properties member | Select-Object Name,ObjectClass,DistinguishedName,member

        if ($null -eq $arrADObject) {
            $sErrMsg = "Failed to find " + $sObjectName + " in local AD"
            throw $sErrMsg
        }
        else {
            Write-Verbose "`t+++ Object discovered in AD. ObjectType = $($arrADObject.ObjectClass)"

            # The function Get-ADObjectDetails required an array object of DistinguishedNames to target
            $arrMembers = @([PSCustomObject] @{DistinguishedName=$arrADObject.DistinguishedName;ObjectClass='user'})

            if ($arrADObject.ObjectClass -eq 'user') {
                $param_MemberDetails = @{
                    sTargetDomain = $sTargetDomain
                    sOwningGroup = $sOwningGroup
                    arrTargetDN = $arrMembers
                    arrUserAttributes = $arrUserAttributes
                    arrGroupAttributes = $arrGroupAttributes
                }
        
                $arrMemberDetails = Get-ADObjectDetails @param_MemberDetails

                return $arrMemberDetails
            }
            else {
                [string[]]$arrReturnObjectDn = @()

                $sOwningGroup = $arrADObject.Name

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

<#
Function Get-ADGroupMembersLocal() {
    param (
        [Parameter(Mandatory=$true)][string]$sGroupName,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes,
        [Parameter(Mandatory=$true)][string]$sTargetDomain
    )

    Write-Verbose "*** Function: Get-ADGroupMembersLocal :: LocalObject: $sGroupName"

    $arrADObject = Get-ADObject -Identity $sGroupName -Properties member | Select-Object ObjectClass,DistinguishedName,member

    # If the object is a group return the members, if not return the DN of the user object
    if ($arrADObject.ObjectClass -eq 'group') {
        $arrMembers = $arrADObject.member

        Write-Verbose "`t+++ Returned ObjectClass group"
    }
    elseif ($arrADObject.ObjectClass -eq 'user') {
        $arrMembers = $arrADObject.DistinguishedName

        Write-Verbose "`t+++ Returned ObjectClass user"
    }

    # Check users to retrieve objects for have been discovered
    if ($null -eq $arrMembers) {
        $sErrMsg = "Unable to find object " + $sGroupName + " in local domain"
        throw $sErrMsg
    }

    # Retrieve the user details
    try {
        $param_MemberDetails = @{
            sTargetDomain = $sTargetDomain
            sOwningGroup = $sGroupName
            arrTargetDN = $arrMembers
            arrUserAttributes = $arrUserAttributes
            arrGroupAttributes = $arrGroupAttributes
        }

        # If the discovered cross forest object is a user (not a group) then remove the sOwningGroup detail
        if ($objADTargetObject.ObjectClass -eq "user") {
            $param_MemberDetails.sOwningGroup = "None-UserAddedDirectly"
        }

        $arrMemberDetails = Get-ADObjectDetails @param_MemberDetails
    }
    catch {
        $sErrMsg = ("Failed to discover user details. Error: " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
        throw $sErrMsg
    }

    return $arrMemberDetails
}
#>
Function Get-ADObjectDetails() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][PSCredential]$objCredential,
        [Parameter(Mandatory=$true)][string]$sTargetDomain,
        [Parameter(Mandatory=$true)][string]$sOwningGroup,
        [Parameter(Mandatory=$true)][Object[]]$arrTargetDN,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes
    )

    Write-Verbose "*** Function: Get-ADObjectDetails - Retrieving AD Object Details"

    [System.Collections.ArrayList]$arrADObjResults = @()

    # Add the TargetDomain and Owning Group detail
    $arrADUserAttributes = $arrUserAttributes | Where-Object {$_ -ne "ObjectSid"}
    $arrADUserAttributes += @{n='ObjectSid';e={($_.ObjectSid).toString()}}
    $arrADUserAttributes += @{n='TargetDomain';e={$sTargetDomain}}
    $arrADUserAttributes += @{n='OwningGroup';e={$sOwningGroup}}
    
    # Add the TargetDomain and Owning Group detail
    $arrADGroupAttributes = $arrGroupAttributes | Where-Object {$_ -ne "ObjectSid"}
    $arrADGroupAttributes += @{n='ObjectSid';e={($_.ObjectSid).toString()}}    
    $arrADGroupAttributes += @{n='TargetDomain';e={$sTargetDomain}}
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
        Call function Get-ADObjectDetails to get user and group details
        Return the details returned by Get-ADObjectDetails
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
    }
    elseif ($objTargetDomain.DomainSid -match "FAILED|SKIPPED") {
        $sErrMsg = ("Unable to perform lookup against target domain " + $objTargetDomain.DomainName + " there are no credentials available for this domain")
        throw $sErrMsg
    }

    Write-Verbose "`t+++ Found matching domain $($objTargeDomain.DomainName)"

    # Find the object in the source domain by searching for the SID. This is required to get the non-SID identity of the object
    try {
        if ($null -eq $objTargetDomain.Credential) {
            $objADTargetObject = Get-ADObject -Filter "ObjectSid -eq '$sTargetADObjectSid'" -Server $objTargetDomain.DomainName | Select-Object ObjectGuid,Name,ObjectClass
        }
        else {
            $objADTargetObject = Get-ADObject -Filter "ObjectSid -eq '$sTargetADObjectSid'" -Server $objTargetDomain.DomainName -Credential $objTargetDomain.Credential | Select-Object ObjectGuid,Name,ObjectClass
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
            $arrMembers = Get-ADGroupMember -Identity ($objADTargetObject.ObjectGuid).toString() -Server $objTargetDomain.DomainName -Credential $objTargetDomain.Credential | Select-Object DistinguishedName, ObjectClass
        }
        else {
            $arrMembers = @()
            $arrMembers += $objADTargetObject | Select-Object DistinguishedName, ObjectClass
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
                $param_MemberDetails.sOwningGroup = $objADTargetObject.Name
            }

            # If a credential is available for the trusted domain add the credential object
            if (!($null -eq $objTargetDomain.Credential)) {
                $param_MemberDetails.objCredential = $objTargetDomain.Credential
            }

            # If the discovered cross forest object is a user (not a group) then remove the sOwningGroup detail
            if ($objADTargetObject.ObjectClass -eq "user") {
                $param_MemberDetails.sOwningGroup = "None-UserAddedDirectly"
            }

            $arrMemberDetails = Get-ADObjectDetails @param_MemberDetails
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

# Get the DN of the requested group
#### TESTING
#[void]$arrGroupsToProcess.Add($GroupName)

<#
try {
    Write-Output "*** Enumerating root group members"
    
    $arrGroupMembers = Get-ADLocalGroupMembership -sGroupName $GroupName

    # Convert the returned group members to an ArrayList
    if ($arrGroupMembers.GetType().BaseType.Name -eq 'Array') {
        [void]$arrGroupsToProcess.AddRange($arrGroupMembers)
    }
    else {
        [void]$arrGroupsToProcess.Add($arrGroupMembers)
    }

    Write-Output "`t+++ Success `n"
}
catch {
    Write-Output "`t--- Failed"

    $Error[0].Exception.Message
    
    Exit
}
#>

# TEST
[System.Collections.ArrayList]$arrGroupsToProcess = @()

# Only the DN can be added to arrGroupsToProcess. If the DN was not provided in the parameter GroupName then look up it
# xxxxxxxxxxxxx requires error handling
if ($GroupName -match "^CN=") {
    [void]$arrGroupsToProcess.Add($GroupName)
}
else {
    $sRootGroupDN = Get-ADGroup -Identity $GroupName | Select-Object -ExpandProperty DistinguishedName
    [void]$arrGroupsToProcess.Add($sRootGroupDN)
}


# Get a list of the trusted domains
$arrTrustedDomains = @((Get-ADDomain).DnsRoot)
$arrTrustedDomains += Get-ADTrustedDomains

# Get the name of the current Domain name and LDAP root DN
$sLocalDomainRoot = (Get-ADDomain).DistinguishedName
$sLocalDomainName = (Get-ADDomain).DNSRoot

Write-Output "*** List of known domains"
$arrTrustedDomains | ForEach-Object { Write-Output "`t+++ $($_)" }

# Get the credentials for each domain (if required)
Write-Output "`n*** Evaluating domain access (credentials may be requested)"

# If no domains were specified to skip then add a "dumb" entry so calling the function doesn't error
# If the value passed for SkipDomainAuthentication is a string not an array then convert it into an array
if ([String]::IsNullOrEmpty($SkipDomainAuthentication)) {
    $SkipDomainAuthentication = @("NoDomainsToSkip")
}
elseif ($SkipDomainAuthentication.GetType().Name -eq "string") {
    $SkipDomainAuthentication = @($SkipDomainAuthentication)
}

$arrDomainInfo = Get-ADAccess -arrTrustedDomains $arrTrustedDomains -arrSkipDomainAuthentication $SkipDomainAuthentication

# Show the results of the trsted domain list
$arrDomainInfo | ForEach-Object {
    Write-Output "`t=== Domain: $($_.DomainName) :: Domain SID: $($_.DomainSid)"
}

#@# PROCESS
Write-Output "`n***Enumerating group membership"


# Recursively enumerate group members and extract the details
#foreach ($sMemberDN in $arrGroupMembers) {
Do {
    Write-Output "*** Processing group member $($arrGroupsToProcess[0])"

    # Check if the group is local or in a trusted domain
    if ($arrGroupsToProcess[0] -match "CN=ForeignSecurityPrincipals") {
        $arrReturnedMembers = Get-ADGroupMembersCrossForest -arrDomainInfo $arrDomainInfo -sTargetMember $arrGroupsToProcess[0] -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes
    }
    else {
        $arrReturnedData = Get-ADLocalObject -sObjectName $arrGroupsToProcess[0] -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes -sTargetDomain $sLocalDomainName

        Write-Output "DEBUG: $($arrReturnedData.GetType().Name)"

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
Write-Output "`n*** Writing results to file"

try {
    $arrGroupMemberResults | ConvertTo-CSV -NoTypeInformation | Out-File $OutputFile -Encoding utf8 -Force

    Write-Output "`t+++ Success `n"
}
catch {
    $sErrMsg = ("Failed to write results to output file $($OutputFile): " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
    Write-Output "`t--- $sErrMsg"
}


# Tidy up
Remove-Variable arrGroupMemberResults,arrDomainInfo,arrGroupMembers,arrTrustedDomains -ErrorAction "SilentlyContinue"