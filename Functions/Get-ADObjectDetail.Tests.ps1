[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
param()

BeforeAll {
    # Import function
    . $PSScriptRoot\Get-ADObjectDetail.ps1

    # Declare groups for mocking
    Function Get-ADUser() {}
    Function Get-ADGroup() {}


    $arrUserAttributes = @("ObjectClass","DistinguishedName","UserPrincipalName","samAccountName","Name","EmployeeId","mail","ObjectSid")
    $arrGroupAttributes = @("ObjectClass","DistinguishedName","Name","ObjectSid")
}

Describe "Get-ADObjectDetail" {
    Context "Request user and expect response using credentials" {
        BeforeAll {
            $objSid = new-object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-1-11-1111111111-1111111111-111111111-1111"

            $objUserResponse = [PSCustomObject] @{
                ObjectClass = "user"
                DistinguishedName = "CN=GoodUser,CN=Users,DC=domain1,DC=com"
                UserPrincipalName = "gooduser@domain1.com"
                samAccountName = "GoodUser"
                Name = "Good User"
                EmployeeId = 1234
                mail = "good.user@domain1.com"
                ObjectSid = $objSid
                SourceDomain = "domain1.com"
                OwningGroup = "domain1.com\Users\Test Group"
            }

            mock Get-ADUser { return Write-Output $objUserResponse -NoEnumerate}

            $param_ADObjectDetail = @{
                objCredential = New-Object PSCredential -ArgumentList "abc",("abc" | ConvertTo-SecureString -AsPlainText -Force)
                sTargetDomain = "domain1.com"
                sOwningGroup = "domain1.com\Users\Test Group"
                arrTargetDN = @(@{DistinguishedName="CN=GoodUser,CN=Users,DC=domain1,DC=com";ObjectClass='user'})
                arrUserAttributes = $arrUserAttributes
                arrGroupAttributes = $arrGroupAttributes
            }

            $objResult = Get-ADObjectDetail @param_ADObjectDetail
        }

        It "Should return correct data types" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return 1 element" {
            $objResult.Count | Should -be 1
        }

        It "Should contain the correct user data" {
            $objResult[0].Name | Should -be "Good User"
            $objResult[0].DistinguishedName | Should -be "CN=GoodUser,CN=Users,DC=domain1,DC=com"
            $objResult[0].UserPrincipalName | Should -be "gooduser@domain1.com"
            $objResult[0].samAccountName | Should -be "GoodUser"
            $objResult[0].OwningGroup | Should -be "domain1.com\Users\Test Group"
            $objResult[0].SourceDomain | Should -be "domain1.com"
        }
    }
    Context "Request user and expect response without using credentials" {
        BeforeAll {
            $objSid = new-object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-1-11-1111111111-1111111111-111111111-1111"

            $objUserResponse = [PSCustomObject] @{
                ObjectClass = "user"
                DistinguishedName = "CN=GoodUser,CN=Users,DC=domain1,DC=com"
                UserPrincipalName = "gooduser@domain1.com"
                samAccountName = "GoodUser"
                Name = "Good User"
                EmployeeId = 1234
                mail = "good.user@domain1.com"
                ObjectSid = $objSid
                SourceDomain = "domain1.com"
                OwningGroup = "domain1.com\Users\Test Group"
            }

            mock Get-ADUser { return Write-Output $objUserResponse -NoEnumerate}

            $param_ADObjectDetail = @{
                sTargetDomain = "domain1.com"
                sOwningGroup = "domain1.com\Users\Test Group"
                arrTargetDN = @(@{DistinguishedName="CN=GoodUser,CN=Users,DC=domain1,DC=com";ObjectClass='user'})
                arrUserAttributes = $arrUserAttributes
                arrGroupAttributes = $arrGroupAttributes
            }

            $objResult = Get-ADObjectDetail @param_ADObjectDetail
        }

        It "Should return correct data types" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return 1 element" {
            $objResult.Count | Should -be 1
        }

        It "Should contain the correct user data" {
            $objResult[0].Name | Should -be "Good User"
            $objResult[0].DistinguishedName | Should -be "CN=GoodUser,CN=Users,DC=domain1,DC=com"
            $objResult[0].UserPrincipalName | Should -be "gooduser@domain1.com"
            $objResult[0].samAccountName | Should -be "GoodUser"
            $objResult[0].OwningGroup | Should -be "domain1.com\Users\Test Group"
            $objResult[0].SourceDomain | Should -be "domain1.com"
        }
    }

    Context "Request multiple users simultaneously" {
        BeforeAll {
            $objSid = new-object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-1-11-1111111111-1111111111-111111111-1111"

            $objUserResponse = [PSCustomObject] @{
                ObjectClass = "user"
                DistinguishedName = "CN=GoodUser,CN=Users,DC=domain1,DC=com"
                UserPrincipalName = "gooduser@domain1.com"
                samAccountName = "GoodUser"
                Name = "Good User"
                EmployeeId = 1234
                mail = "good.user@domain1.com"
                ObjectSid = $objSid
                SourceDomain = "domain1.com"
                OwningGroup = "domain1.com\Users\Test Group"
            }

            mock Get-ADUser { return Write-Output $objUserResponse -NoEnumerate}

            $param_ADObjectDetail = @{
                sTargetDomain = "domain1.com"
                sOwningGroup = "domain1.com\Users\Test Group"
                arrTargetDN = @(@{DistinguishedName="CN=GoodUser,CN=Users,DC=domain1,DC=com";ObjectClass='user'},@{DistinguishedName="CN=GoodUser,CN=Users,DC=domain1,DC=com";ObjectClass='user'})
                arrUserAttributes = $arrUserAttributes
                arrGroupAttributes = $arrGroupAttributes
            }

            $objResult = Get-ADObjectDetail @param_ADObjectDetail
        }

        It "Should return correct data types" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return 2 elements" {
            $objResult.Count | Should -be 2
        }

        It "Should contain the correct user data in element 2" {
            $objResult[1].Name | Should -be "Good User"
            $objResult[1].DistinguishedName | Should -be "CN=GoodUser,CN=Users,DC=domain1,DC=com"
            $objResult[1].UserPrincipalName | Should -be "gooduser@domain1.com"
            $objResult[1].samAccountName | Should -be "GoodUser"
            $objResult[1].OwningGroup | Should -be "domain1.com\Users\Test Group"
            $objResult[1].SourceDomain | Should -be "domain1.com"
        }
    }

    Context "User doesn't exist in target domain" {
        BeforeAll {
            mock Get-ADUser { throw "User not found in AD"}

            $param_ADObjectDetail = @{
                objCredential = New-Object PSCredential -ArgumentList "abc",("abc" | ConvertTo-SecureString -AsPlainText -Force)
                sTargetDomain = "domain1.com"
                sOwningGroup = "domain1.com\Users\Test Group"
                arrTargetDN = @(@{DistinguishedName="CN=GoodUser,CN=Users,DC=domain1,DC=com";ObjectClass='user'})
                arrUserAttributes = $arrUserAttributes
                arrGroupAttributes = $arrGroupAttributes
            }

            $objResult = Get-ADObjectDetail @param_ADObjectDetail
        }

        It "Should return correct data types" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return 1 element" {
            $objResult.Count | Should -be 1
        }

        It "Should contain empty data structure apart from provided elements" {
            $objResult[0].DistinguishedName | Should -be "CN=GoodUser,CN=Users,DC=domain1,DC=com"
            [string]::IsNullOrEmpty($objResult[0].Name) | Should -be $true
            [string]::IsNullOrEmpty($objResult[0].UserPrincipalName) | Should -be $true
            [string]::IsNullOrEmpty($objResult[0].samAccountName) | Should -be $true
            $objResult[0].ObjectClass | Should -be "user"
            $objResult[0].OwningGroup | Should -be "domain1.com\Users\Test Group"
            $objResult[0].SourceDomain | Should -be "domain1.com"
        }
    }

    Context "Request GROUP and expect response using credentials" {
        BeforeAll {
            $objSid = new-object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-2-22-2222222222-2222222222-222222222-2222"

            $objUserResponse = [PSCustomObject] @{
                ObjectClass = "group"
                DistinguishedName = "CN=GoodGroup,CN=Users,DC=domain1,DC=com"
                Name = "Good Group"
                ObjectSid = $objSid
                SourceDomain = "domain1.com"
                OwningGroup = "domain1.com\Users\Test Group"
            }

            mock Get-ADGroup { return Write-Output $objUserResponse -NoEnumerate}

            $param_ADObjectDetail = @{
                objCredential = New-Object PSCredential -ArgumentList "abc",("abc" | ConvertTo-SecureString -AsPlainText -Force)
                sTargetDomain = "domain1.com"
                sOwningGroup = "domain1.com\Users\Test Group"
                arrTargetDN = @(@{DistinguishedName="CN=GoodGroup,CN=Users,DC=domain1,DC=com";ObjectClass='group'})
                arrUserAttributes = $arrUserAttributes
                arrGroupAttributes = $arrGroupAttributes
            }

            $objResult = Get-ADObjectDetail @param_ADObjectDetail
        }

        It "Should return correct data types" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return 1 element" {
            $objResult.Count | Should -be 1
        }

        It "Should contain the correct user data" {
            $objResult[0].DistinguishedName | Should -be "CN=GoodGroup,CN=Users,DC=domain1,DC=com"
            $objResult[0].Name | Should -be "Good Group"
            $objResult[0].OwningGroup | Should -be "domain1.com\Users\Test Group"
            $objResult[0].SourceDomain | Should -be "domain1.com"
            $objResult[0].ObjectSid | Should -be "S-1-2-22-2222222222-2222222222-222222222-2222"
            $objResult[0].ObjectSid.GetType().Name | Should -be "string"
        }
    }
}

AfterAll {
    Remove-Item function:\Get-ADUser
    Remove-Item function:\Get-ADGroup
}