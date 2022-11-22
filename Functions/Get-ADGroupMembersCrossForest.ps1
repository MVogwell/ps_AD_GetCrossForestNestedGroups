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