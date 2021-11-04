#Step 1 - delete rule
$Path = $NedapOnsTeamsMappingPath

$CSV = import-csv $Path -Delimiter ";"
$filteredCSV = foreach ($line in $CSV) {
    if (-not(($line.'Department.ExternalId' -eq $organisationalUnit) -and ($line.NedapLocationIds -eq $locationsOriginal) -and ($line.'Title.ExternalId' -eq $jobCode))) {
        $line 
    }
}
$filteredCSV | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | ForEach-Object { $_.Replace('"', '') } | Out-File $Path

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

$rule | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | ForEach-Object { $_ -replace '"', "" }  | Select-Object -Skip 1  | Add-Content $Path -Encoding UTF8
