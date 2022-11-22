Function Get-ADObjectDetail() {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory=$false)][PSCredential]$objCredential,
        [Parameter(Mandatory=$true)][string]$sTargetDomain,
        [Parameter(Mandatory=$true)][string]$sOwningGroup,
        [Parameter(Mandatory=$true)][Object[]]$arrTargetDN,
        [Parameter(Mandatory=$true)][string[]]$arrUserAttributes,
        [Parameter(Mandatory=$true)][string[]]$arrGroupAttributes
    )

    Write-Verbose "*** Function: Get-ADObjectDetail - Retrieving AD Object Details"

    [System.Collections.ArrayList]$arrADObjResults = @()

    # Add the TargetDomain and Owning Group detail
    $arrADUserAttributes = $arrUserAttributes | Where-Object {$_ -ne "ObjectSid"}
    $arrADUserAttributes += @{n='ObjectSid';e={($_.ObjectSid).toString()}}
    $arrADUserAttributes += @{n='SourceDomain';e={$sTargetDomain}}
    $arrADUserAttributes += @{n='OwningGroup';e={$sOwningGroup}}

    # Add the TargetDomain and Owning Group detail
    $arrADGroupAttributes = $arrGroupAttributes | Where-Object {$_ -ne "ObjectSid"}
    $arrADGroupAttributes += @{n='ObjectSid';e={($_.ObjectSid).toString()}}
    $arrADGroupAttributes += @{n='SourceDomain';e={$sTargetDomain}}
    $arrADGroupAttributes += @{n='OwningGroup';e={$sOwningGroup}}

    foreach ($objTargetDN in $arrTargetDN) {
        try {
            if ($objTargetDN.ObjectClass -eq 'user') {
                Write-Verbose "`t=== Retrieving user details: $($objTargetDN.DistinguishedName)"

                if ($null -eq $objCredential) {
                    $objADEntity = Get-ADUser -Identity $objTargetDN.DistinguishedName -Properties $arrUserAttributes -Server $sTargetDomain | Select-Object $arrADUserAttributes
                }
                else {
                    $objADEntity = Get-ADUser -Identity $objTargetDN.DistinguishedName -Properties $arrUserAttributes -Server $sTargetDomain -Credential $objCredential | Select-Object $arrADUserAttributes
                }
            }
            else {
                Write-Verbose "`t=== Retrieving group details: $($objTargetDN.DistinguishedName)"

                if ($null -eq $objCredential) {
                    $objADEntity = Get-ADGroup -Identity $objTargetDN.DistinguishedName -Properties $arrGroupAttributes -Server $sTargetDomain | Select-Object $arrADGroupAttributes
                }
                else {
                    $objADEntity = Get-ADGroup -Identity $objTargetDN.DistinguishedName -Properties $arrGroupAttributes -Server $sTargetDomain -Credential $objCredential | Select-Object $arrADGroupAttributes
                }
            }
        }
        catch {
            Write-Verbose "`t`t--- Failed to discover user/group details. Creating empty return object"

            # Create a result object containing the known info about the object but without the full AD returned data
            $objADEntity = new-object PSCustomObject

            # Add the empty attributes according to the value of the object's ObjectClass attribute
            if ($objTargetDN.ObjectClass -eq 'user') {
                foreach ($sAttribute in $arrUserAttributes) {
                   $objADEntity | Add-Member -MemberType NoteProperty -Name $sAttribute -Value ""
                }
            }
            else {
                foreach ($sAttribute in $arrGroupAttributes) {
                    $objADEntity | Add-Member -MemberType NoteProperty -Name $sAttribute -Value ""
                }
            }

            # Add compulsory properties
            $sErrMsg = ("Failed to discover AD Object details. Error: " + (($Global:Error[0].Exception.Message).toString()).replace("`r"," ").replace("`n"," "))
            $objADEntity | Add-Member -MemberType NoteProperty -Name "Error" -Value $sErrMsg -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value $objTargetDN.ObjectClass -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $objTargetDN.DistinguishedName -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "TargetDomain" -Value $sTargetDomain -Force
            $objADEntity | Add-Member -MemberType NoteProperty -Name "OwningGroup" -Value $sOwningGroup -Force
        }

        # Add the result to the array
        [void]$arrADObjResults.Add($objADEntity)

        # Tidy up
        Remove-Variable objADEntity -ErrorAction "SilentlyContinue"
    }

    return $arrADObjResults
}