$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

# Description: This script shows how to post Az.Storage Analytics logs to Azure Log Analytics workspace
#
# Before running this script:
#     - Create or have a storage account, and enable analytics logs
#     - Create Azure Log Analytics workspace
#     - Change the following values:
#           - $Config
#           - $WorkspaceId
#           - $SharedKey
#           - $LogType
#
# What this script does:
#     - Use Storage Powershell to enumerate all log blobs in $logs container in a storage account
#     - Use Storage Powershell to read all log blobs
#     - Convert each log line in the log blob to JSON payload
#     - Use Log Analytics HTTP Data Collector API to post JSON payload to Log Analytics workspace
#
# Note: This script is sample code. No support is provided.
#
# Reference:
#     - Log Analytics Data Collector API: https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
#

#Login-AzAccount

$configJson = Get-AutomationVariable -Name 'Config'
$config = ConvertFrom-Json $configJson

# Replace with your Workspace Id
# Find in: Azure Portal > Log Analytics > {Your workspace} > Advanced Settings > Connected Sources > Windows Servers > WORKSPACE ID
$WorkspaceId =  Get-AutomationVariable -Name 'WorkspaceId'

# Replace with your Primary Key
# Find in: Azure Portal > Log Analytics > {Your workspace} > Advanced Settings > Connected Sources > Windows Servers > PRIMARY KEY
$SharedKey = Get-AutomationVariable -Name 'SharedKey'

# Specify the name of the record type that you'll be creating
# After logs are sent to the workspace, you will use "MyStorageLogs1_CL" as stream to query.
$LogType = "MyStorageLogs1_CL"

# You can use an optional field to specify the timestamp from the data. 
# If the time field is not specified, Log Analytics assumes the time is the message ingestion time
$TimeStampField = ""

# Sample of two records in json to be sent to Log Analytics workspace
$json = @"
[{  "StringValue": "MyString1",
    "NumberValue": 42,
    "BooleanValue": true,
    "DateValue": "2016-05-12T20:00:00.625Z",
    "GUIDValue": "9909ED01-A74C-4874-8ABF-D2678E3AE23D"
},
{   "StringValue": "MyString2",
    "NumberValue": 43,
    "BooleanValue": false,
    "DateValue": "2016-05-12T20:00:00.625Z",
    "GUIDValue": "8809ED01-A74C-4874-8ABF-D2678E3AE23D"
}]
"@

#
# Create the function to create the authorization signature
#
Function Build-Signature ($WorkspaceId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId,$encodedHash
    return $authorization
}

#
# Create the function to create and post the request
#
Function Post-LogAnalyticsData($WorkspaceId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -workspaceId $WorkspaceId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}


# Submit the data to the API endpoint
#Post-LogAnalyticsData -workspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType

#
# Convert ; to "%3B" between " in the csv line to prevent wrong values output after split with ;
#
Function ConvertSemicolonToURLEncoding([String] $InputText)
{
    $ReturnText = ""
    $chars = $InputText.ToCharArray()
    $StartConvert = $false

    foreach($c in $chars)
    {
        if($c -eq '"') {
            $StartConvert = ! $StartConvert
        }

        if($StartConvert -eq $true -and $c -eq ';')
        {
            $ReturnText += "%3B"
        } else {
            $ReturnText += $c
        }
    }

    return $ReturnText
}

#
# If a text doesn't start with ", add "" for json value format
# If a text contains "%3B", replace it back to ";"
#
Function FormalizeJsonValue($Text)
{
    $Text1 = ""
    if($Text.IndexOf("`"") -eq 0) { $Text1=$Text } else {$Text1="`"" + $Text+ "`""}

    if($Text1.IndexOf("%3B") -ge 0) {
        $ReturnText = $Text1.Replace("%3B", ";")
    } else {
        $ReturnText = $Text1
    }
    return $ReturnText
}

Function ConvertLogLineToJson([String] $logLine)
{
    #Convert semicolon to %3B in the log line to avoid wrong split with ";"
    $logLineEncoded = ConvertSemicolonToURLEncoding($logLine)

    $elements = $logLineEncoded.split(';')

    $FormattedElements = New-Object System.Collections.ArrayList
                
    foreach($element in $elements)
    {
        # Validate if the text starts with ", and add it if not
        $NewText = FormalizeJsonValue($element)

        # Use "> null" to avoid annoying index print in the console
        $FormattedElements.Add($NewText) > null
    }

    $Columns = 
    (   "version-number",
        "request-start-time",
        "operation-type",
        "request-status",
        "http-status-code",
        "end-to-end-latency-in-ms",
        "server-latency-in-ms",
        "authentication-type",
        "requester-account-name",
        "owner-account-name",
        "service-type",
        "request-url",
        "requested-object-key",
        "request-id-header",
        "operation-count",
        "requester-ip-address",
        "request-version-header",
        "request-header-size",
        "request-packet-size",
        "response-header-size",
        "response-packet-size",
        "request-content-length",
        "request-md5",
        "server-md5",
        "etag-identifier",
        "last-modified-time",
        "conditions-used",
        "user-agent-header",
        "referrer-header",
        "client-request-id"
    )

    # Propose json payload
    $logJson = "[{";
    For($i = 0;$i -lt $Columns.Length;$i++)
    {
        $logJson += "`"" + $Columns[$i] + "`":" + $FormattedElements[$i]
        if($i -lt $Columns.Length - 1) {
            $logJson += ","
        }
    }
    $logJson += "}]";

    return $logJson
}

Function ProcessContainer($storageContext, $containerName)
{
    $Token = $Null
    $MaxReturn = 5000
    $SuccessPost = 0
    $FailedPost = 0
    
    Write-Output("> Reading container {0}" -f $containerName)

    do {
        $Blobs = Get-AzureStorageBlob -Context $storageContext -Container $containerName  -MaxCount $MaxReturn -ContinuationToken $Token | where-object { $_.LastModified -gt (Get-Date).AddHours(-1)} 
        if($Null -eq $Blobs) {
            break
        }

        #Set-StrictMode will cause Get-AzureStorageBlob returns result in different data types when there is only one blob
        if($Blobs.GetType().Name -eq "AzureStorageBlob") {
            $Token = $Null
        } else {
            $Token = $Blobs[$Blobs.Count - 1].ContinuationToken;
        }

        # Enumerate log blobs
        foreach($blob in $Blobs)
        {
            Write-Output("> Downloading blob: {0}" -f $blob.Name)
            $filename = ".\log.txt"
            Get-AzureStorageBlobContent -Context $storageContext -Container $containerName  -Blob $blob.Name -Destination $filename -Force > Null
            
            Write-Output("> Posting logs to log analytic worspace: {0}" -f $blob.Name)
            $Lines = Get-Content $filename

            # Enumerate log lines in each log blob
            foreach($line in $Lines)
            {
                $json = ConvertLogLineToJson($line)
                
                #Write-Output $json
                $Response = Post-LogAnalyticsData -workspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType

                if($Response -eq "200") {
                    $SuccessPost++
                } else { 
                    $FailedPost++
                    Write-Output "> Failed to post one log to Log Analytics workspace"
                }
            }
        }
    }
    While ($Null -ne $Token)

    Write-Output "> Log lines posted to Log Analytics workspace: success = $SuccessPost, failure = $FailedPost"
}

$config | ForEach-Object {
    $storageContext = New-AzureStorageContext -ConnectionString $_.connectionString
    $containerName = $_.container

    ProcessContainer($storageContext.Context, $containerName)
}
