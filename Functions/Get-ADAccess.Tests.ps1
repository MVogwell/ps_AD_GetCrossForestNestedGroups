[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
param()


BeforeAll {
    # Load functions
    . $PSScriptRoot\Get-ADAccess.ps1
    . $PSScriptRoot\Get-ADDomainCredential.ps1
    . $PSScriptRoot\Test-DomainAccess.ps1

    $arrTrustedDomains = @("domain1.com","domain2.com")

    Function Get-ADDomain() {
        param (
            [Parameter(Mandatory=$true)][string]$Server,
            [Parameter(Mandatory=$false)][PSCredential]$Credential
        )

        Write-Verbose "Get-ADDomain starting"

        if ($Server -eq "domain1.com") {
            $objReturn = [PSCustomObject] @{
                DomainSID = "S-1-5-21-1111111111-111111111-111111111-111"
            }
        }
        elseif ($Server -eq "domain2.com") {
            if ($null -eq $Credential) {
                throw "No access"
            }
            else {
                $objReturn = [PSCustomObject] @{
                    DomainSID = "S-2-5-22-2222222222-222222222-222222222-222"
                }
            }
        }

        return $objReturn
    }
}

Describe "Get-ADAccess" {
    Context "NoSkippedDomains" {
        BeforeAll {
            $arrSkipDomainAuthentication = @("NoSuchDomain")

            # Prevent GUI call for Get-Credential
            $psCred = New-Object PSCredential -ArgumentList "testing",("testing" | ConvertTo-SecureString -AsPlainText -Force)
            Mock Get-Credential { return $psCred}

            $objResult = Get-ADAccess -arrTrustedDomains $arrTrustedDomains -arrSkipDomainAuthentication $arrSkipDomainAuthentication
        }

        It "Returns Object Array" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return first domain name" {
            $objResult[0].DomainName | Should -be "domain1.com"
        }

        It "Should return first domain DomainSID" {
            $objResult[0].DomainSid | Should -be "S-1-5-21-1111111111"
        }

        It "Should return second domain name" {
            $objResult[1].DomainName | Should -be "domain2.com"
        }

        It "Should return second domain DomainSID" {
            $objResult[1].DomainSid | Should -be "S-2-5-22-2222222222"
        }
    }
    Context "WithSkippedDomains" {
        BeforeAll {
            $arrSkipDomainAuthentication = @("domain2.com")

            $objResult = Get-ADAccess -arrTrustedDomains $arrTrustedDomains -arrSkipDomainAuthentication $arrSkipDomainAuthentication -Verbose:$VerbosePreference
        }

        It "Returns ArrayList" {
            $objResult.GetType().Name | Should -be "ArrayList"
        }

        It "Should return first domain name" {
            $objResult[0].DomainName | Should -be "domain1.com"
        }

        It "Should return first domain DomainSID" {
            $objResult[0].DomainSid | Should -be "S-1-5-21-1111111111"
        }

        It "Show domain 2 as skipped" {
            ($objResult | Where-Object DomainName -eq "domain2.com").DomainSID | Should -be "SKIPPED"
        }
    }
}

AfterAll {
    Remove-Item function:\Get-ADDomain
}