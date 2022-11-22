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