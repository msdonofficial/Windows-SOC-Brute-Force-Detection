
# Windows SOC - Brute Force Detection
# Detection threshold: 5 failures in 10 minutes

$Threshold = 5
$TimeWindowMinutes = 10

$StartTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$FailedLogons = foreach ($Event in $Events) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Account     = $Data['TargetUserName']
        SourceIP    = $Data['IpAddress']
        Workstation = $Data['WorkstationName']
    }
}

$Alerts = $FailedLogons |
    Group-Object Account, SourceIP |
    Where-Object { $_.Count -ge $Threshold }

if ($Alerts) {

    foreach ($Alert in $Alerts) {
        Write-Host "`n[ALERT] Possible Brute Force Activity!" -ForegroundColor Red
        Write-Host "Account: $($Alert.Group[0].Account)"
        Write-Host "Source IP: $($Alert.Group[0].SourceIP)"
        Write-Host "Failed Attempts: $($Alert.Count)"
        Write-Host "Time Window: $TimeWindowMinutes minutes"
    }
# Windows SOC - Brute Force Detection
# Threshold: 5 failures within 10 minutes

$Threshold = 5
$TimeWindowMinutes = 10

$StartTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)
$AlertLogPath = "$env:USERPROFILE\Desktop\SOC-Alerts.csv"

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$FailedLogons = foreach ($Event in $Events) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Account     = $Data['TargetUserName']
        SourceIP    = $Data['IpAddress']
        Workstation = $Data['WorkstationName']
    }
}

$Alerts = $FailedLogons |
    Group-Object Account, SourceIP |
    Where-Object { $_.Count -ge $Threshold }

if ($Alerts) {

    foreach ($Alert in $Alerts) {

        $Severity = if ($Alert.Count -ge 8) {
            "High"
        } else {
            "Medium"
        }

        $AlertRecord = [PSCustomObject]@{
            DetectionTime = Get-Date
            Account       = $Alert.Group[0].Account
            SourceIP      = $Alert.Group[0].SourceIP
            Workstation   = $Alert.Group[0].Workstation
            FailedAttempts = $Alert.Count
            TimeWindow    = "$TimeWindowMinutes minutes"
            Severity      = $Severity
        }

        Write-Host "`n[ALERT] Possible Brute Force Activity!" -ForegroundColor Red
        $AlertRecord | Format-List

        $AlertRecord | Export-Csv -Path $AlertLogPath `
            -NoTypeInformation -Append
    }

    Write-Host "Alert saved to: $AlertLogPath" -ForegroundColor Yellow

} else {

    Write-Host "`n[INFO] No brute-force threshold reached." -ForegroundColor Green
    Write-Host "Failed logons found: $($FailedLogons.Count)"
    Write-Host "Detection threshold: $Threshold"
}


} else {

    Write-Host "`n[INFO] No brute-force threshold reached." -ForegroundColor Green
    Write-Host "Failed logons found: $($FailedLogons.Count)"
    Write-Host "Detection threshold: $Threshold"
}
