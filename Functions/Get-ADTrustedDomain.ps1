Function Get-ADTrustedDomain() {
    <#
        .SYNOPSIS
        Function to return FQDNs of trusted Active Directory domains. Requires the "Active Directory for PowerShell module"

        .PARAMETER Server
        Optional. Set the server (or domain name) to request the information from

        .PARAMETER objCredential
        Optional. Set the credential to use

        .NOTES
        Version 1.0 - Initial release
    #>
    
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param (
        [Parameter(Mandatory=$false)][string]$Server,
        [Parameter(Mandatory=$false)][PSCredential]$Credential
    )

    # Set the default parameter to call Get-ADTrust
    $param_ADTrust = @{
        Filter = "*"
        Verbose = $VerbosePreference
    }

    # Add the server name if provided
    if ([string]::IsNullOrEmpty($Server) -eq $false) {
        Write-Verbose "Using Server name $Server"
        $param_ADTrust.Server = $Server
    }

    # Add the credential if provided
    if (!($null -eq $Credential)) {
        Write-Verbose "Using credential $($Credential.UserName)"
        $param_ADTrust.Credential = $Credential
    }

    $arrTrustedDomains = (Get-ADTrust @param_ADTrust).Target

    return $arrTrustedDomains
}