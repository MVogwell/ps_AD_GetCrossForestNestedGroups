# ![logo][] ps_AD_GetCrossForestNestedGroups

ps_AD_GetCrossForestNestedGroups is a PowerShell script that can be used to enumerate Active Directory security groups that contain members from one or more trusted domains.

The script generates a csv file output that contains details about the user along with details of which domain they are from and what nested group they are a member of.

[logo]:https://raw.githubusercontent.com/MVogwell/ps_AD_GetCrossForestNestedGroups/master/Assets/Icon.png

## Important stuff
* The script makes no changes to Active Directory.
* This script comes with no guarantees, warranties, or any other -ies! No responsibility is taken for you running this script.


## Operation example

* You have a domain "LocalDomain.com" which has a valid domain trust to "ExternalDomain.com"
* You have an AD Security Group called "GRP_LOCAL_MyNestedGroup" in the domain "LocalDomain.com"
* This group contains:
  * Users from the domain "LocalDomain.com".
  * A group from the domain "LocalDomain.com" called "GRP_GLOBAL_LocalUsers" that contains users from that domain only.
  * A group from the domain "ExternalDomain.com" called "GRP_GLOBAL_ExternalUsers" that contains users from the trusted domain.
* The script will:
  * Get the details of the users native to LocalDomain.com in the group "GRP_LOCAL_MyNestedGroup"
  * Get the details of the group "GRP_GLOBAL_LocalUsers" from LocalDomain.com
  * Get the details of the users in the group "GRP_GLOBAL_LocalUsers" from LocalDomain.com
  * Get the details of the group "GRP_GLOBAL_UserGroup" from ExternalDomain.com
  * Get the details of the users in the group "GRP_GLOBAL_UserGroup" from the domain "ExternalDomain.com"

Additionally if the group "GRP_GLOBAL_UserGroup" contains nested group from the domain "ExternalDomain.com" then those groups and users will be discovered and reported on.


## Permissions

Where a two way trust exists between the domain the script will enumerate the group membership without requesting credentials. However, if there is only a one-way trust between domains then the script will ask for credentials to access Active Directory information from the trusted domain.

If you don't have credentials for every domain that is trusted by the domain being reported from - don't panic - see the FAQ section below for how to skip domains.




## Requirements

The script requires the following:

* The "ActiveDirectory module for PowerShell" must be installed on the machine running the script - information on installing this can be found [here][].
* PowerShell v5.1 or above
* Network access to Domain Controllers in the source domain as well as all other trusted domains.

[here]:https://www.varonis.com/blog/powershell-active-directory-module


## How to run the script
* Download the script from https://github.com/MVogwell/ps_AD_GetCrossForestNestedGroups and extract all the files
* You must keep the Functions folder in the same location as the main script ps_AD_GetCrossForestNestedGroups.ps1
* Open PowerShell and navigate to the folder you have extracted the script to.
* Run the script with the following command - change "MY-GROUP" to the name of the Active Directory group you want to report on:

`.\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "MY-GROUP"`

The script will run and, once complete, will generate a csv file in the %Temp% folder - the full path of the output file will be listed at the end of the script.

## FAQs

### What if I want the report to be saved somewhere else?

* To do this run the script with the optional parameter OutputFile as seen in the example below:

`.\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "MY-GROUP" -OutputFile c:\temp\MyFolder\Results.csv`

<br>

### What if I don't have credentials for one or more of the trusted Active Directory domains?

* If you don't have credentials for a trusted domain, or just want to skip it because there are no groups from that domain nested in the main group, you can start the script with the '-SkipDomainAuthentication' as seen in the example below:

`.\ps_AD_GetCrossForestNestedGroups.ps1 -GroupName "MY-GROUP" -SkipDomainAuthentication "ExternalDomain2.com"`

Note: If a user/group object is discovered that comes from a domain that the script doesn't have access to it the report will show the user object as Error - all domains that could be reached will return as normal.

<br>

### What if I only want to enumerate a nested group from one domain?

Not a problem - run the script on the domain you want to report on and add -SkipDomainAuthentication for the other domains (just so you don't have to wait around for authentication to finish).

<br>

### But what if I don't have any trusted domains but still want to use this to enumerate nested groups in AD?

Not a problem - just run the script as per the first example and you'll get the results!

<br>

### Where can I find out more about the problems of enumerating groups containing cross forest/domain AD objects?

I'm glad you asked - pop over to https://martinvogwell.medium.com/cross-forest-nested-ad-groups-discovery-with-powershell-a3e43cb08128 for more information!
