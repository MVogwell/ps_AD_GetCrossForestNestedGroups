Function Get-MemberData() {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param (
        [Parameter(Mandatory=$true)][System.Collections.ArrayList]$arrGroupsToProcess,
        [Parameter(Mandatory=$true)][Object[]]$arrDomainInfo,
        [Parameter(Mandatory=$true)][String[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][String[]]$arrGroupAttributes,
        [Parameter(Mandatory=$true)][String]$sLocalDomainRoot,
        [Parameter(Mandatory=$true)][String]$sLocalDomainName
    )

    [System.Collections.ArrayList]$arrGroupMemberResults = @()

    # Recursively enumerate group members and extract the details
    Do {
        Write-Progress -Activity "Processing group member" -Status "$($arrGroupsToProcess[0])"

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

            Write-Verbose "`t--- $sErrMsg `n"
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

    return Write-Output $arrGroupMemberResults -NoEnumerate
}