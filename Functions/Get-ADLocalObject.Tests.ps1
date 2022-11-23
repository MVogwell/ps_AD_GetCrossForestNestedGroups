[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
param()

BeforeAll {
    . $PSScriptRoot\Get-ADLocalObject.ps1

    # Initialise variables
    $arrUserAttributes = @("ObjectClass","DistinguishedName","UserPrincipalName","samAccountName","Name","EmployeeId","mail","ObjectSid")
    $arrGroupAttributes = @("ObjectClass","DistinguishedName","Name","ObjectSid")

    Function Get-ADObject() {
        [CmdletBinding()]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
        param (
            [Parameter(Mandatory=$true)][string]$Identity,
            [Parameter(Mandatory=$true)][string[]]$Properties
        )

        # This function fakes the results from various requests for the cmdlet Get-ADObject which is available in the
        # ActiveDirectory module. This was used instead of mock as multiple responses were required.

        if ($Identity -match "CN=GoodUser") {
            $objReturn = [PSCustomObject] @{
                Name = "GoodUser"
                Distinguishedname = "CN=GoodUser,CN=Users,DC=domain1,DC=com"
                ObjectClass = "user"
                CanonicalName = "domain1.com\Users\GoodUser"
            }
        }
        elseif ($Identity -match "CN=BadUser") {
            throw "User not found in AD"
        }
        elseif ($Identity -match "CN=GoodGroup") {
            $arrMembers = @("CN=GoodUser,CN=Users,DC=domain1,DC=com","CN=AnotherUser,CN=Users,DC=domain1,DC=com")

            $objReturn = [PSCustomObject] @{
                Name = "GoodGroup"
                Distinguishedname = "CN=GoodGroup,CN=Users,DC=domain1,DC=com"
                ObjectClass = "group"
                CanonicalName = "domain1.com\Users\GoodGroup"
                Member = $arrMembers
            }
        }

        return Write-Output $objReturn -NoEnumerate
    }

    Function Get-ADObjectDetail() {
        [System.Collections.ArrayList]$arrMemberDetails = @()
        $objMember = [PSCustomObject] @{
            ObjectClass = "user"
            DistinguishedName = $sUserDN
            UserPrincipalName = "gooduser@domain1.com"
            samAccountName = "gooduser"
            Name = "Good User"
            EmployeeId = 1234
            mail = "good.user@domain1.com"
            ObjectSid = "S-1-5-21-1111111111-1111111111-1111111111-111"
        }
        [void]$arrMemberDetails.Add($objMember)

        return Write-Output $arrMemberDetails -NoEnumerate
    }
}

Describe "Get-ADLocalObject" {
    Context "Requesting local user" {
        BeforeAll {
            $sUserDN = "CN=GoodUser,CN=Users,DC=domain1,DC=com"

            $arrResult = Get-ADLocalObject -sObjectName $sUserDN -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes -sTargetDomain "domain1.com"
        }

        It "Should match expected data type" {
            $arrResult.GetType().Name | Should -be "PSCustomObject"
            $arrResult[0].GetType().Name | Should -be "PSCustomObject"
        }

        It "Should return user data" {
            $arrResult[0].ObjectClass | Should -be "user"
            $arrResult[0].Name | Should -be "Good User"
        }
    }
    Context "Request user unknown to AD" {
        BeforeAll {
            $sUserDN = "CN=BadUser,CN=Users,DC=domain1,DC=com"
        }

        It "Should fail with unknown user error" {
            try {
                $arrResult = Get-ADLocalObject -sObjectName $sUserDN -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes -sTargetDomain "domain1.com"
            }
            catch {
                $Error[0].Exception.Message | Should -be "Failed to discover $($sUserDN): User not found in AD"
            }
        }
    }
    Context "Requesting local group" {
        BeforeAll {
            $sGroupDN = "CN=GoodGroup,CN=Users,DC=domain1,DC=com"

            $arrResult = Get-ADLocalObject -sObjectName $sGroupDN -arrUserAttributes $arrUserAttributes -arrGroupAttributes $arrGroupAttributes -sTargetDomain "domain1.com"
        }

        It "Should match expected data type" {
            $arrResult.GetType().Name | Should -be "Object[]"
            $arrResult[0].GetType().Name | Should -be "String"
        }

        It "Should return user data containing the origin group prefix" {
            $arrResult[0] -match '^RG=domain1.com\\Users\\GoodGroup,CN=GoodUser,CN=Users,DC=domain1,DC=com' | Should -be $true
        }

        It "Should return two test elements" {
            $arrResult.Count | Should -be 2
        }
    }
}

AfterAll {
    Remove-Item function:\Get-ADObject
    Remove-Item function:\Get-ADObjectDetail
}