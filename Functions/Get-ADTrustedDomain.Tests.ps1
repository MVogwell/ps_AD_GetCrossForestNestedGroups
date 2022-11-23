[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
param()

BeforeAll {
    . $PSScriptRoot\Get-ADTrustedDomain.ps1

    Function Get-ADTrust {
        [CmdletBinding()]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
        param (
            [Parameter(Mandatory=$true)][string]$Filter,
            [Parameter(Mandatory=$false)][string]$Server,
            [Parameter(Mandatory=$false)][PSCredential]$Credential
        )

        Write-Verbose "Running fake Get-ADTrust"

        if ([string]::IsNullOrEmpty($Server)) {
            $sData = @("Domain1","Domain2")
            $sReturn  = [PSObject] @{Target=$sData}
        }
        else {
            $sData = @("Domain1-$Server","Domain2-$Server")
            $sReturn  = [PSObject] @{Target=$sData}
        }

        if (!($null -eq $Credential)) {
            if ($Credential.Username -match "\s") {
                throw "Badly formatted credential"
            }
        }

        return $sReturn
    }
}

Describe "Get-ADTrustedDomain" {
    Context "No params" {
        It "Returns array object" {
            (Get-ADTrustedDomain).GetType().Name | Should -be "Object[]"
        }

        It "Returns expected trusted domains" {
            Get-ADTrustedDomain | Should -be @("Domain1","Domain2")
        }
    }
    Context "With server params" {
        BeforeAll {
            $sServer = "abc"
        }

        It "Returns array object" {
            (Get-ADTrustedDomain -Server $sServer).GetType().Name | Should -be "Object[]"
        }

        It "Returns expected trusted domains" {
            Get-ADTrustedDomain -Server $sServer | Should -be @("Domain1-$sServer","Domain2-$sServer")
        }

        AfterAll {
            Remove-Variable sServer
        }
    }
    Context "With credential params" {
        BeforeAll {
            $objCredentialGood = New-Object PSCredential -ArgumentList "abc",("abc" | ConvertTo-SecureString -AsPlainText -Force)
            $objCredentialBad = New-Object PSCredential -ArgumentList " ",("abc" | ConvertTo-SecureString -AsPlainText -Force)
        }

        It "Returns array object" {
            (Get-ADTrustedDomain -Credential $objCredentialGood).GetType().Name | Should -be ("Object[]" -or "String")
        }

        It "Fails with error on credential" {
            try {
                Get-ADTrustedDomain -Credential $objCredentialBad
            }
            catch {
                $Error[0].Exception.Message | Should -Be "Badly formatted credential"
            }
        }

        AfterAll {
            Remove-Variable objCredential -ErrorAction "SilentlyContinue"
        }
    }
}

AfterAll {
    Remove-Item function:\Get-ADTrust -ErrorAction "SilentlyContinue"
}
