Function Get-ADAccess() {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param (
        [Parameter(Mandatory=$true)][string[]]$arrTrustedDomains,
        [Parameter(Mandatory=$true)][string[]]$arrSkipDomainAuthentication
    )

    Write-Verbose "*** Function: Get-ADAccess -- Getting domain info and credentials"

    # Initialise variable
    [System.Collections.ArrayList]$arrDomainData = @()

    # Loop through each trusted domain specified in the parameters
    foreach ($sTrustedDomain in $arrTrustedDomains) {
        Write-Verbose "*** Testing $($sTrustedDomain)"

        Write-Progress -Activity "Testing access to domain" -Status "$sTrustedDomain - Testing access without additional credentials"

        if ($arrSkipDomainAuthentication -contains $sTrustedDomain) {
            Write-Verbose "`t--- Skipping domain $sTrustedDomain"

            Write-Progress -Activity "Testing access to domain" -Status "$sTrustedDomain - SKIPPED"

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

                Write-Progress -Activity "Testing access to domain" -Status "$sTrustedDomain - No credential required"

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

                Write-Progress -Activity "Testing access to domain" -Status "$sTrustedDomain - Requesting/Validating Credential"

                $objDomainInfo = Get-ADDomainCredential -sDomainName $sTrustedDomain

                Write-Verbose "`t`t+++ DomainSid = $($objDomainInfo.DomainSid)"

                $objDomainData = [PSCustomObject] @{
                    DomainName = $sTrustedDomain
                    Credential = $objDomainInfo.Credential
                    DomainSid = $objDomainInfo.DomainSid
                }

                Write-Verbose "`t+++ Domain: $sTrustedDomain - credentials tested successfully"
            }
        }

        [void]$arrDomainData.Add($objDomainData)

        Remove-Variable objDomainData,objDomainInfo -ErrorAction "SilentlyContinue"
    }

    return Write-Output $arrDomainData -NoEnumerate
}