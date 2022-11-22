Function Get-ADDomainCredential() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$sDomainName
    )

    Write-Verbose "*** Function: Get-ADDomainCredential - Domain: $sDomainName"

    # Request the credential from the user
    try {
        Write-Verbose "`t=== Requesting Credentials"

        $objCredential = Get-Credential -Message "Enter the credentials for domain $($sDomainName). If credentials are not required for this group hit escape."

        if ($null -eq $objCredential) {
            throw "Failed to obtain credential from user"
        }

        Write-Verbose "`t`t+++ Credentials retrieved"
    }
    catch {
        Write-Verbose "`t`t`t--- FAILED TO GET CREDENTIAL FROM USER"

        $sErrMsg = ("Domain: " + $sDomainName + " (no credential provided)")

        throw $sErrMsg
    }

    # Only test if the credentials were successfully captured
    if (!($null -eq $objCredential)) {
        $sDomainSid = Test-DomainAccess -sDomainName $sDomainName -objCredential $objCredential -Verbose:$VerbosePreference
    }

    if ($sDomainSid -match "^S\-") {
        $objReturn = [PSCustomObject] @{
            Credential = $objCredential
            DomainSid = $sDomainSid
        }

        return $objReturn
    }
    else {
        Write-Verbose "`t`t--- Failed to discover DomainSid"

        $sErrMsg = "Domain: " + $sDomainName + " (" + $sDomainSid + ")"

        throw $sErrMsg
    }
}