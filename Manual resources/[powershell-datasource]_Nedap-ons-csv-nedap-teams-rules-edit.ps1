# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$Path = $NedapOnsTeamsMappingPath
$rules = Import-Csv -Path $Path -Delimiter ";"

# AFAS API Parameters #
$token = $AfasToken;
$baseUri = $AfasBaseUri;

<#--------- AFAS script ----------#>
# Default function to get paged connector data
function Get-AFASConnectorData {
    param(
        [parameter(Mandatory = $true)]$Token,
        [parameter(Mandatory = $true)]$BaseUri,
        [parameter(Mandatory = $true)]$Connector,
        [parameter(Mandatory = $true)][ref]$data
    )

    try {
        $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Token))
        $authValue = "AfasToken $encodedToken"
        $Headers = @{ Authorization = $authValue }

        $take = 100
        $skip = 0

        $uri = $BaseUri + "/connectors/" + $Connector + "?skip=$skip&take=$take"
        $dataset = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -UseBasicParsing

        foreach ($record in $dataset.rows) { [void]$data.Value.add($record) }

        $skip += 100
        while ($dataset.rows.count -ne 0) {
            $uri = $BaseUri + "/connectors/" + $Connector + "?skip=$skip&take=$take"

            $dataset = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -UseBasicParsing

            $skip += 100

            foreach ($record in $dataset.rows) { [void]$data.Value.add($record) }
        }
    }
    catch {
        $data.Value = $null
        Write-Verbose $_.Exception -Verbose
    }
}


$organizationalUnits = New-Object System.Collections.ArrayList
Get-AFASConnectorData -Token $token -BaseUri $baseUri -Connector "T4E_HelloID_OrganizationalUnits" ([ref]$organizationalUnits) 
$afasLocations = $organizationalUnits | Select-Object ExternalId, DisplayName 

$employments = New-Object System.Collections.ArrayList
Get-AFASConnectorData -Token $token -BaseUri $baseUri -Connector "T4E_HelloID_Employments" ([ref]$employments)
$employments = $employments | Select-Object Functie_code, Functie_omschrijving #| Group-Object Persoonsnummer -AsHashTable

if($true -eq $includePositions)
{
    $positions = New-Object System.Collections.ArrayList
    Get-AFASConnectorData -Token $token -BaseUri $baseUri -Connector "T4E_HelloID_Positions" ([ref]$positions)
    $positions = $positions | Select-Object Functie_code, Functie_omschrijving #| Group-Object Persoonsnummer -AsHashTable
}

    if($true -eq $includePositions)
    {
        $employments += $positions
    }
    


$afasEmployments = $employments | Sort-Object Functie_Code -Unique 


<#---------- Nedap script -----------#>
$script:Uri = $NedapOnsConnectionURL
$script:CertificatePath = $NedapOnsCertificatePFX
$script:CertificatePassword = $NedapOnsCertificatePassword

function Get-ResponseStream {
    [cmdletbinding()]
    param(
        $Exception
    )
    $result = $Exception.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $responseReader = $reader.ReadToEnd()
    $reader.Dispose()
    Write-Output  $responseReader
}

function Import-NedapCertificate {
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The path to the pfx certificate, it must be accessible by the agent.")]
        $CertificatePath,

        [Parameter(Mandatory = $true)]
        $CertificatePassword
    )

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($CertificatePath, $CertificatePassword, 'UserKeySet')
    if ($cert.NotAfter -le (Get-Date)) {
        throw "Certificate has expired on $($cert.NotAfter)..."
    }
    $script:Certificate = $cert
}

function Get-NedapTeamList {
    [Cmdletbinding()]
    param()  # Two Script Parameters ([$script:uri] Nedap BaseUri [$script:Certificate] Nedap Certificate )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $webRequestSplatting = @{
        Uri             = "$($script:uri)/t/teams"
        Method          = "Get"
        Certificate     = $script:Certificate
        Headers         = (@{"accept" = "application/json" })
        ContentType     = "application/json; charset=utf-8"
        UseBasicParsing = $true
    }
    try {
        $response = Invoke-WebRequest @webRequestSplatting
        $teams = $response.Content | ConvertFrom-Json
        Write-Output  $teams.teams
    } catch {
        if ($_.ErrorDetails) {
            $errorReponse = $_.ErrorDetails
        } elseif ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errorReponse = $reader.ReadToEnd()
            $reader.Dispose()
        }
        throw "Could not read Nedap teams from '$uri', message: $($_.exception.message), $($errorReponse.error)"
    }
}
Import-NedapCertificate -CertificatePath $script:CertificatePath  -CertificatePassword $script:CertificatePassword


$joinedAfasDataset =@()
foreach($rowA in $rules) {
    $rowB = $afasLocations | Where-Object ExternalId -eq $rowA.'Department.ExternalId'
    $rowC = $afasEmployments | Where-Object Functie_code -eq $rowA.'Title.ExternalId'
    $joinedRow = @{
        OE = $rowA.'Department.ExternalId'        
        Department = $rowB.DisplayName
        FunctionId = $rowA.'Title.ExternalId'
        Functions = $rowC.Functie_omschrijving
        NedapTeamIds = $rowA.NedapTeamId
        NedapTeams = $null
    }
    $joinedAfasDataset += New-Object -Type PSObject -Property $joinedRow
}
$joinedAfasDataset = $joinedAfasDataset | Where-Object Department -ne $null

$nedapTeams = Get-NedapTeamList  | Select-Object name, id, identificationNo


foreach($rowA in $joinedAfasDataset) {
    $joinedNedapDataset =@()
    $mystring = ''
    $nedapIds = $rowA.NedapTeamIds.Split(',')
    foreach($id in $nedapIds) {
        $rowB = $nedapTeams | Where-Object Id -eq $id
        $joinedRow = @{
            NedapTeams = $rowB.Name
        }
        $joinedNedapDataset += New-Object -Type PSObject -Property $joinedRow        
    }
    $mystring = $joinedNedapDataset | ForEach-Object {$_.NedapTeams}
    $rowA.NedapTeams = $mystring -join ", "
    
}

ForEach($r in $joinedAfasDataset)
        {
            #Write-Output $Site 
            $returnObject = @{ AFASOEid=$r.OE; AFASOE=$r.Department; FunctionId=$r.FunctionId; Functions=$r.Functions; NedapTeamIds=$r.NedapTeamIds; NedapTeams=$r.NedapTeams; }
            Write-Output $returnObject                
        } 
