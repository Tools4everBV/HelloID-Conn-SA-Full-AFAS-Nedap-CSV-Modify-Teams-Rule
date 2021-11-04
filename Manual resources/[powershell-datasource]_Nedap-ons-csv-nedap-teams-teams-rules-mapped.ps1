$selectedNedapIds = $datasource.selectedMapping.NedapTeamIds
$selectedNedapIds = $selectedNedapIds.Split(',')

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
    }
    catch {
        if ($_.ErrorDetails) {
            $errorReponse = $_.ErrorDetails
        }
        elseif ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errorReponse = $reader.ReadToEnd()
            $reader.Dispose()
        }
        throw "Could not read Nedap teams from '$uri', message: $($_.exception.message), $($errorReponse.error)"
    }
}
Import-NedapCertificate -CertificatePath $script:CertificatePath  -CertificatePassword $script:CertificatePassword
$teams = Get-NedapTeamList | Where-Object id -in $selectedNedapIds | Select-Object name, id, identificationNo

ForEach ($team in $teams) {
    $returnObject = @{ Id = $team.id; DisplayName = $team.name; identificatonNo = $team.identificationNo }
    Write-Output $returnObject                
}
