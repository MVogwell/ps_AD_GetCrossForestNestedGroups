Function Test-DomainAccess() {
    param (
        [Parameter(Mandatory=$true)][string]$sDomainName,
        [Parameter(Mandatory=$false)][pscredential]$objCredential
    )

    Write-Verbose "*** Function: Test-DomainAccess -- Domain: $sDomainName"

    try {
        if ($null -eq $objCredential) {
            Write-Verbose "`t`t=== Testing $sDomainName WITHOUT credentials"

            $sDomainSid = (Get-ADDomain -Server $sDomainName | Select-Object -ExpandProperty DomainSID).toString().SubString(0,19)
        }
        else {
            Write-Verbose "`t`t+++ Testing $sDomainName with credentials"

            $sDomainSid = (Get-ADDomain -Server $sDomainName -Credential $objCredential | Select-Object -ExpandProperty DomainSID).toString().SubString(0,19)
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