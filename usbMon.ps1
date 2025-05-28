#################################################################################
#  Author       : TCHUISSEU Cyriaque @Kercy4D 
#  Date         : 2025-05-20
#  Project      : USB Device Detection and Response 
#  Description  : This script is build as a proof-of-concept for detecting and responding device USB connection to unauthorized USB device connections using Wazuh capabilities.
#  Dedicace     : Dedicated to the Wazuh Team.Thank you for your commitment to open-source security.
#  OS           : Windows 10
#  GitHub       : https://github.com/kercy4D/USBMonWazuh/ 
#  Version      : 1.0.2
#  Linkedin     : https://www.linkedin.com/in/cyriaque-t-ab710a221
#################################################################################
#Initialisation of yara
$yaraRule ="C:\\Program Files (x86)\\ossec-agent\\active-response\\bin\\yara\\rules\\yara_rules.yar"
$yara_exe ="C:\\Program Files (x86)\\ossec-agent\active-response\\bin\\yara\\yara64.exe"

#Initialisation of log file
$logFile ="C:\Traces\usb_monitor.log"
#if directory does not exist,we create a new one
if(-not (Test-Path "C:\Traces"))
{
    New-Item -Path "C:\Traces" -ItemType Directory
}

#Function for log record
function usb_loginfo
{

#Get info parameters 
    param($drive)
    $driveLetter = $drive.DeviceID
    $volumeName = $drive.VolumeName
    $fileSys = $drive.FileSystem
    # convert size in GB
    $sizeGB = "{0:N2}" -f ($drive.Size / 1GB)
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
#Yara scan execution
    $yara_scan =& $yara_exe $yaraRule $driveLetter |Out-String
    $yara_scan =$yara_scan -replace "`r`n"," "
    $yara_scan =$yara_scan -replace "SuspectFiles",""

#Get model via deviceID
    $usbDrives = Get-WmiObject Win32_DiskDrive |Where-Object {$_.Partitions -eq 1}
    $model =$usbDrives | ForEach-Object{ $_.Model} | Select-Object -First 1
    $entry = "usbmon: $date  Drive: $driveLetter  Name: $volumeName  FileSystem: $fileSys  SizeStorage : $sizeGB GB  Model : $model threatDetected : $yara_scan"
    #Append entry to usb_monitor.log
    Add-Content -Path $logFile -Value $entry
    Write-Host $entry
}

#Enable loop monitoring
Write-Host "USB monitoring launch (ctrl+C to stop)..."

while($true)
{
$usbDrives = Get-WmiObject win32_LogicalDisk | Where-Object {$_.DriveType -eq 2}
    forEach($drive in $usbDrives){
    $id = $drives.DeviceID
    if(-not $Global:detectedDrives)
    { $Global:detectedDrives = @()
    }
    if($Global:detectedDrives -notcontains $id)
    { $Global:detectedDrives = $id
      usb_loginfo -drive $drive
    }
    }
#Cleaning the removed USB
   
    Start-Sleep -Seconds 3
}
