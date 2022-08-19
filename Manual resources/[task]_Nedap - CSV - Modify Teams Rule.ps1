$jobCode = $form.teamsMappings.FunctionId
$organisationalUnit = $form.teamsMappings.AFASOEid
$teamsNew = $form.dualList.right.toJsonString
$teamsOriginal = $form.teamsMappings.NedapTeamIds

#Step 1 - delete rule
$path = $NedapOnsTeamsMappingPath

$CSV = import-csv $Path -Delimiter ";"
$filteredCSV = foreach ($line in $CSV) {
    if (-not(($line.'Department.ExternalId' -eq $organisationalUnit) -and ($line.NedapLocationIds -eq $locationsOriginal) -and ($line.'Title.ExternalId' -eq $jobCode))) {
        $line 
    }
}
$filteredCSV | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | ForEach-Object { $_.Replace('"', '') } | Out-File $path

#Step 2 - add new rule definition
$afasLocation = $organisationalUnit
$afasJobCode = $jobCode
$nedapTeams = $teamsNew | ConvertFrom-Json

foreach ($n in $nedapTeams) {
    $nedapTeamsString = $nedapTeamsString + $n.Id.ToString() + ","
}

$nedapTeamsString = $nedapTeamsString.Substring(0, $nedapTeamsString.Length - 1)

$rule = [PSCustomObject]@{
    "Department.ExternalId" = $afasLocation;
    "Title.ExternalId"      = $afasJobCode
    "NedapTeamId"           = $nedapTeamsString;
}

$rule | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | ForEach-Object { $_ -replace '"', "" }  | Select-Object -Skip 1  | Add-Content $path -Encoding UTF8

$Log = @{
    Action            = "Undefined" # optional. ENUM (undefined = default) 
    System            = "NedapOns" # optional (free format text) 
    Message           = "Updated team rule for department [$organisationalUnit] and optional title [$jobCode] from Nedap Team id(s) [$teamsOriginal] to Nedap Team id(s) [$teamsNew] in mapping file [$path]" # required (free format text) 
    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
    TargetDisplayName = "$path" # optional (free format text) 
    TargetIdentifier  = "" # optional (free format text) 
}
#send result back  
Write-Information -Tags "Audit" -MessageData $log
