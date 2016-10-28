Add-Type -AssemblyName System.Web

<# Add exception for self-signed certificates
    Added from https://www.ibm.com/developerworks/community/blogs/edgeCity/entry/still_restless_with_powershell?lang=en
#>

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$restName = "RESTAPI"
$restPassword = "T3mpP@ss!"

Function Get-BFConnectHeaders {

    $EncodedAuthorization = [System.Text.Encoding]::UTF8.GetBytes($restName + ':' + $restPassword)
    $EncodedPassword = [System.Convert]::ToBase64String($EncodedAuthorization)
    $Headers = @{"Authorization"="Basic $($EncodedPassword)"}

    return $Headers


    }



Function Get-BFServer {
    return [uri]"https://bigfix.ad.jhickok.com:52311"
}


    #Arbitrary Query
Function Invoke-BFSessionQuery {
    <#
    .SYNOPSIS
    Submit a session relevance query to the BigFix Server
    
    .DESCRIPTION
    This is a helper function to facilitate asking the BigFix server for an answer to a session relevance question
    
    .PARAMETER Query
    The session relevance query that you wish to run

    .EXAMPLE
    Get all computers in the BigFix build environment
    get-gueryanswer -query "names of bes computers"

    .EXAMPLE
    PowerShell will number them for you when it displays your help text to a user.

    .Notes
    Author: William Easton - williamseaston@gmail.com
    #>
    param (
        $Query
    )

    #Prep BF Server Connection
    $Headers = Get-BFConnectHeaders

    $APIEntry = "$(Get-BFServer)" + "api/query?relevance="
    
    #URL Encode Query
    $Query = [System.Web.HttpUtility]::UrlEncode($Query)

    #Log Message
    write-verbose "$($MyInvocation.MyCommand) - Query: $Query"

    #Make Request
    $Response = Invoke-WebRequest -Uri ($APIEntry + $Query) -Method Get -Headers $headers -verbose:$false

    if (select-xml -content ($Response) -xpath "/BESAPI/Query/Error") { throw "Query returned an error" }

    ((select-xml -content ($Response) -xpath "/BESAPI/Query/Result/Answer").Node.InnerText.replace("`n","`r`n"))
}

Function Invoke-Action {
     param (
     $siteName, 
     $fixletID,
     $target
     )


     $actionXML = @"
<BES xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BES.xsd">
    <SourcedFixletAction>
        <SourceFixlet>
            <Sitename>$siteName</Sitename>
            <FixletID>$fixletID</FixletID>
            <Action>Action1</Action>
        </SourceFixlet>
        <Target>
             <CustomRelevance>$target</CustomRelevance>
        </Target>
    </SourcedFixletAction>
</BES>
"@
    $Headers = Get-BFConnectHeaders

    $APIEntry = "$(Get-BFServer)" + "api/actions"
    $Response = Invoke-WebRequest -Uri ($APIEntry) -Method POST -Headers $headers -verbose:$false -body $actionXML
}


Function New-BaselineComponent  {
    param (
        $sitename,
        $fixletID
    )

    $name = Invoke-BFSessionQuery -Query "name of fixlet $fixletID of all bes sites whose (name of it = ""$siteName"")"
    $sourceID = $fixletID
    $sourceSiteUrl = Invoke-BFSessionQuery -Query "url of all bes sites whose (name of it = ""$siteName"")"
    $actionscript = Invoke-BFSessionQuery -Query "script of default action of fixlet $fixletID of all bes sites whose (name of it = ""$siteName"")"
    $relevance = Invoke-BFSessionQuery -Query "relevance of fixlet $fixletID of all bes sites whose (name of it = ""$siteName"")"
[xml]$xml= @"
<BaselineComponent Name="" IncludeInRelevance="true" SourceSiteURL="" SourceID="" ActionName="Action1">
    <ActionScript MIMEType="application/x-Fixlet-Windows-Shell"></ActionScript>
    <SuccessCriteria Option="OriginalRelevance"></SuccessCriteria>
    <Relevance></Relevance>
</BaselineComponent>
"@
    $xml.BaselineComponent.Name = $name
    $xml.BaselineComponent.SourceSiteURL = $sourceSiteUrl
    $xml.BaselineComponent.SourceID = $sourceID
    $xml.BaselineComponent.ActionScript.InnerText = $actionscript -join "`n"
    $xml.BaselineComponent.Relevance = $relevance 

    return $xml.OuterXml
}

Function New-BaselineComponentGroup  {
    param (
        [string[]]$baselineComponents
    )
    $groupXML = "<BaselineComponentGroup>"
    foreach($baselineComponent in $baselineComponents){
        $groupXML += $baselineComponent
    }
    $groupXML += "</BaselineComponentGroup>"

    return $groupXML
}

Function New-BaselineComponentCollection {
    param (
        [string[]]$baselineComponentGroups
    )
    $groupXML = "<BaselineComponentCollection>"
    foreach($baselineComponentGroup in $baselineComponentGroups){
        $groupXML += $baselineComponentGroup
    }
    $groupXML += "</BaselineComponentCollection>"

    return $groupXML
}


Function New-Baseline  {
    param (
        $Title,
        $baselineComponentCollection
    )
    return @"
<?xml version="1.0" encoding="UTF-8"?>
<BES xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BES.xsd">
	<Baseline>
		<Title>$Title</Title>
		<Description><![CDATA[&lt;enter a description of the baseline here&gt; ]]></Description>
		<Relevance>true</Relevance>
		<Category></Category>
		<Source>Internal</Source>
		<SourceID></SourceID>
		<SourceReleaseDate>2016-08-18</SourceReleaseDate>
		<SourceSeverity></SourceSeverity>
		<CVENames></CVENames>
		<SANSID></SANSID>
		<Domain>BESC</Domain>
        $baselineComponentCollection
	</Baseline>
</BES>
"@

}

Function Upload-Baseline {
     param (
     $siteName, 
     $xml
     )
  
    $Headers = Get-BFConnectHeaders

    $APIEntry = "$(Get-BFServer)" + "api/import/custom/$siteName"
    $Response = Invoke-WebRequest -Uri ($APIEntry) -Method POST -Headers $headers -verbose:$false -body $XML
    return (select-xml -content ($Response) -xpath "/BESAPI/Baseline/ID").node.InnerXml
}

Function New-PatchGroup {
    param (
        $criteria,
        $target,
        $name
    )

    $ApplicableFixlets = Invoke-BFSessionQuery -Query $criteria
    $myComponents = @()
    foreach ($ApplicableFixlet in $ApplicableFixlets) {
        $myComponents += New-BaselineComponent -sitename "Enterprise Security" -fixletID "$ApplicableFixlet"
    }
    $myComponentGroup = New-BaselineComponentGroup -baselineComponents $myComponents
    $myComponentCollection = New-BaselineComponentCollection -baselineComponentGroups $myComponentGroup
    $myBaseline = New-Baseline -Title $name -baselineComponentCollection $myComponentCollection
    $myBaselineID = Upload-Baseline -siteName "Autopatching - Windows" -xml $myBaseline
    Invoke-Action -siteName "Autopatching - Windows" -fixletID $myBaselineID -target $target

}

New-PatchGroup -name "Critical - $((Get-Date).ToString("yyyyMMdd"))" -target "true" -criteria "ids of elements of (set of fixlets whose (applicable computer count of it > 0 and source severity of it = ""Critical"" and exists default action of it) of all bes sites whose (name of it = ""Enterprise Security""))"