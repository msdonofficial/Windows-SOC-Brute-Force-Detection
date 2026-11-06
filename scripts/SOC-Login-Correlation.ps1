
# SOC - Failed to Successful Login Correlation
# Detects 5 or more failures followed by a successful login
# for the same account and source IP within 10 minutes.

$Threshold = 5
$TimeWindowMinutes = 10

$StartTime = (Get-Date).AddMinutes(-30)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$Logons = foreach ($Event in $Events) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventID     = $Event.Id
        Account     = $Data['TargetUserName']
        SourceIP    = $Data['IpAddress']
    }
}

$FailedLogons = $Logons | Where-Object {
    $_.EventID -eq 4625 -and $_.Account -eq 'SOC_LabTest'
}

$SuccessfulLogons = $Logons | Where-Object {
    $_.EventID -eq 4624 -and $_.Account -eq 'SOC_LabTest'
}

$Correlations = foreach ($Success in $SuccessfulLogons) {

    $PreviousFailures = @(
        $FailedLogons | Where-Object {
            $_.SourceIP -eq $Success.SourceIP -and
            $_.TimeCreated -lt $Success.TimeCreated -and
            $_.TimeCreated -ge $Success.TimeCreated.AddMinutes(-$TimeWindowMinutes)
        }
    )

    if ($PreviousFailures.Count -ge $Threshold) {

        [PSCustomObject]@{
            Account          = $Success.Account
            SourceIP         = $Success.SourceIP
            FailedAttempts   = $PreviousFailures.Count
            SuccessfulLogin  = $Success.TimeCreated
            Severity         = 'High'
        }
    }
}

if ($Correlations) {

    foreach ($Alert in $Correlations) {
        Write-Host "`n[HIGH ALERT] Failed logins followed by successful login!" -ForegroundColor Red
        $Alert | Format-List
    }

    $Correlations | Export-Csv `
        "$env:USERPROFILE\Desktop\SOC-Correlation-Alerts.csv" `
        -NoTypeInformation -Append

} else {

    Write-Host "`n[INFO] No suspicious failed-to-successful login sequence detected." -ForegroundColor Green
}
