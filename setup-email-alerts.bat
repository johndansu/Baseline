@echo off
REM Baseline Email Alert Configuration

echo Configuring Email Alerts for Baseline
echo ===================================

REM Create alert configuration
set ALERT_EMAIL=admin@yourcompany.com
set SMTP_SERVER=smtp.yourcompany.com
set SMTP_PORT=587
set SMTP_USER=baseline-alerts@yourcompany.com
set SMTP_PASS=your-email-password

REM Create PowerShell email script
powershell -Command "& {
    $EmailFrom = 'baseline-alerts@yourcompany.com'
    $EmailTo = '%ALERT_EMAIL%'
    $Subject = 'Baseline Production Alert'
    $Body = 'Baseline has detected critical policy violations that require immediate attention.'
    $SMTPServer = '%SMTP_SERVER%'
    $SMTPPort = %SMTP_PORT%
    $Username = '%SMTP_USER%'
    $Password = '%SMTP_PASS%'

    # Create email object
    $MailMessage = New-Object System.Net.Mail.MailMessage $EmailFrom, $EmailTo, $Subject, $Body
    $SMTPClient = New-Object System.Net.Mail.SmtpClient $SMTPServer, $SMTPPort
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)

    # Send test email
    try {
        $SMTPClient.Send($MailMessage)
        Write-Host 'Email alert configuration successful'
    } catch {
        Write-Host 'Email configuration failed:' $_.Exception.Message
    }
}"

echo Email alert configuration completed
echo Update the SMTP settings in this script with your actual email server details
echo.
