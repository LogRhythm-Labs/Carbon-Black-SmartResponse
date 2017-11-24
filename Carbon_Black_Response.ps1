#requires -version 3.0

  #==========================================#
  # LogRhythm Security Operations            #
  # Carbon Black - SmartResponse             #
  # michael . swisher @ logrhythm . com      #
  # v0.2  --  November, 2017                 #
  #==========================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

Param
(
    [string]$hostname, 
    [string]$command,
    [string]$object,
    [string]$key,
    [string]$location,
    [string]$baseURL,
    [string]$insecure = $false
)

$coreHeaders = @{
    "X-Auth-Token"=$key;
    "Content-Type"="application/json";
}

#-----------------------------------------------------------------------------------------
#-------------------------------------------HELP------------------------------------------
#-----------------------------------------------------------------------------------------

$helpMessage = @"
This script is designed to automate certain functions within Carbon Black Live Response.
Through a series of API calls the script can perform and array of functions.

The script requires the following arguments at a minimum:
    - hostname: The hostname of the system you wish to interact with
    - command: The command you would like to perform
    - object: The unique parameter for each command
    - key: An administrator account API key (preferably with Global Administrator)
    - baseURL: The base url for your Carbon Black server

There are some additional arguments that may be required or are optional in the case of the
self-signed certificates flag [insecure]. These are the following:
    - location: File path for target output or file to access (required for 'delete')
    - insecure: Optional flag to disable ssl/tls validation
        ^ Use this if your Carbon Black server uses self-signed certificates

Example: .\Carbon_Black_Response.ps1 -hostname 'acme-computer' -key '<redacted>' \
    -command 'isolate' -object 'false' -baseURL 'https://carbon.acme.com:1234' \
    -insecure 'true'

    The above example would enable isolation on the system acme-computer

***Below is a list and description of the current commands***

isolate - Isolating a host will remove the system's ability to access the Interdigital 

Network.
*******************************************************************************************

****
    To enable isolation use the perameter true.
    To disable isolation use the perameter false.

    Ex. 'Carbon_Black_Response.ps1' PW3797 Isolate false

memdump - Creates a memory dump of targeted system locally and on warhammer
***************************************************************************
    The memory dump will be saved at the path designated in the object field.
    This name of the file must be added at the end of the output path.

    Ex. 'Carbon_Black_Response.ps1' PV0029 memdump C:\Users\exampleUser\memdump
    Ex. 'Carbon_Black_Response.ps1' PV0029 memdump /Users/exampleUser/memdump

    To analyze the memory dumps use recall located on openstack

kill - Kill a process currently running on targeted system
**********************************************************
    The object parameter is the process ID

    Ex. 'Carbon_Black_Response.ps1' PV0029 kill 2134

delete - Delete a file from the targeted system
***********************************************
    The object parameter is the filepath.

    Ex. 'Carbon_Black_Response.ps1' PW3797 delete c:\temp\example.txt
    Ex. 'Carbon_Black_Response.ps1' PW3797 delete /temp/example.txt

get - copy file from targeted system to warhammer session data
**************************************************************
    The object parameter is the filepath.

    Ex. 'Carbon_Black_Response.ps1' PW3797 get c:\temp\example.txt

ps - List all current processes on targeted system
**************************************************

"@

#-----------------------------------------------------------------------------------------
#---------------------------------------End of HELP---------------------------------------
#-----------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------
#-------------------------------Ignore Self-Signed Certificates---------------------------
#-----------------------------------------------------------------------------------------

If ($insecure.ToLower() -eq "true")
{
    try
    {
        #Break indentation format. IDE doesn't like it.
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
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Write-Host "Certificate validation is being ignored."
    }
    catch{
        Write-Error "Failed to ignore certificate validation."
        Write-Error $_.Exception|format-list -force
        exit 1
    }
}
#-----------------------------------------------------------------------------------------
#-------------------------------End of Ignore Self-Signed Certificates--------------------
#-----------------------------------------------------------------------------------------

function wait_for_session_active($Session_id){
    $finished = $false
    while($finished -eq $false){
        $statusURL = "$baseURL/api/v1/cblr/session/$Session_id"
        try{
            $statusResponse = Invoke-RestMethod -uri $statusURL -Headers $coreHeaders 
        }
        catch{
            Write-Error "Bad URL: $statusURL"
            exit 1
        }
        if($statusResponse.status -eq "active"){
            $finished = $true
        }
    }
}

function fetch_command($session_id, $command_id){
    try{
        $url = "$baseURL/api/v1/cblr/session/$session_id/command/$command_id"
        $response = Invoke-RestMethod -uri $url -Headers $coreHeaders
        while($response.status -eq "pending"){
            Start-Sleep -s 1
            $response = Invoke-RestMethod -uri $url -Headers $coreHeaders
        }
    }
    catch{
        #Write-Host $response
    }

    return $response
}

function acquire_sensor_id($Hostname){
    Write-Host "Acquiring sensor ID..."
    $url = "$baseURL/api/v1/sensor?hostname=$Hostname"
    Write-Host "url: $url"
    $response = Invoke-RestMethod -uri $url -Headers $coreHeaders
    Write-Host $response
    #In case cb deployment is corrupt with client device having multiple ID's
    if($response.id.GetType() -eq [System.Object[]]){
        Write-Host "Sensor_id: ", $response.id[0]
        return $response.id[0]
    }else{
        Write-Host "Sensor_id: ", $response.id
        return $response.id 
    }
}

function create_session($Sensor_id){
    
    Write-Host "Creating session with $hostname..."
    try{
        $body = @{
            "sensor_id" = $Sensor_id
        } | ConvertTo-Json
        $url = "$baseURL/api/v1/cblr/session"
        $response = Invoke-RestMethod -Uri $url -Headers $coreHeaders -Method Post -Body $body
        $session_id = $response.id
        Write-Host $session_id
    }
    catch{
        $statusURL = "$baseURL/api/v1/cblr/session"
        $statusResponse = Invoke-RestMethod -uri $statusURL -Headers $coreHeaders
        foreach($session in $statusResponse){
            if(($session.sensor_id -eq $sensor_id) -and (($session.status -eq "pending") -or ($session.status -eq "active"))){
                $session_id = $session.id
                Write-Host $session_id
                break
            }
        }
    }
    Write-Host "Waiting for session $session_id to become active..."
    wait_for_session_active($session_id)
    return $session_id
}

function command_handler($Session_id, $body){
    Write-Host "Executing $command..."
    $url = "$baseURL/api/v1/cblr/session/$Session_id/command"
    $response = Invoke-RestMethod -uri $url -Headers $coreHeaders -Method Post -Body $body
    $command_id = $response.id
    $commandResponse = fetch_command $Session_id $command_id

    return $commandResponse
}

function execute_response($body){
    Write-Host "Beginning execution..."
    $sensor_id = acquire_sensor_id($hostname)
    $session_id = create_session($sensor_id)
    Write-Host "Session is now active."
    $returnVal = command_handler $session_id $body
    return $returnVal, $session_id
}

function main{

    #Remove / at end of baseURL if present to avoid issues with URL 
    if($baseURL[$baseURL.length - 1] -eq '/'){
        $baseURL = $baseURL.Substring(0, $baseURL.length - 1)
    }

    switch($command.ToLower()){

        "ps"{
            $body = @{"name"="process list"} | ConvertTo-Json
            $returnVal = execute_response($body)
            if($location){
                echo "" | Out-File $location
                ForEach ($item in $returnVal.processes) {
                    echo $item | Out-File $location -Append
                }
                Write-Host "Results stored: $location"
            }
            else{
                ForEach ($item in $returnVal.processes) {
                    Write-Host $item
                }
            }

        }

        "kill"{
            $body = @{"name"="kill"; "object"=[int]$object} | ConvertTo-Json
            $returnVal = execute_response($body)
        }

        "get"{
            $body = @{"name"="get file"; "object"=$object} | ConvertTo-Json
            $returnVal, $Session_id = execute_response($body)
             
            #Retrieve file after it gets pushed to Carbon Black Server           
            $file_id = $returnVal.file_id
            
            $url = "$baseURL/api/v1/cblr/session/$Session_id/file/$file_id/content"
            if($object.Contains('/')){
                $output = $location + $object.Substring($object.LastIndexOf("/")+1)
            }
            elseif($object.Contains('\')){
                $output = $location + $object.Substring($object.LastIndexOf("\")+1)
            }
            else{
                Write-Error "Invalid source path: $object"
                exit 1
            }
            write-host $output

            $scriptBlock = {
                param($url, $coreHeaders, $output, $location, $insecure)
                try{
                    #Adopt parent process certificate policy
                    If ($insecure.ToLower() -eq "true")
                    {
                        try
                        {
                            #Break indentation format. IDE doesn't like it.
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
                            $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
                            [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
                            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                            Write-Host "Certificate validation is being ignored."
                        }
                        catch{
                            Write-Error "Failed to ignore certificate validation."
                            Write-Error $_.Exception|format-list -force
                            exit 1
                        }
                    }
                    
                    Invoke-RestMethod -Uri $url -Headers $coreHeaders -OutFile $output
                    <#
                    echo $location | Out-File ($location + "status.txt")
                    #>

                }
                catch{
                    
                    #Write-Error "Error retrieving file."
                    echo $url | Out-File $($location + "error.txt")
                    
                    echo $_ | Out-File $($location + "error.txt") -Append
                    exit 1
                }
            }

            Start-Job -ScriptBlock $scriptBlock -ArgumentList $url, $coreHeaders, $output, $location, $insecure

        }

        "isolate"{
            $sensor_id = acquire_sensor_id($hostname)
            $url = "$baseURL/api/v1/sensor/$sensor_id"
            $response = Invoke-RestMethod -Uri $url -Headers $coreHeaders
            Write-Host "Handling isolation..."
            if($object.ToLower() -eq "false"){
                $response.network_isolation_enabled = $False
            }
            elseif($object.ToLower() -eq  "true"){
                $response.network_isolation_enabled = $True
            }
            else{
                Write-Error "Invalid parameter for isolate command."
                exit 1
            }
            $response = Invoke-RestMethod -uri $url -Headers $coreHeaders -Method Put -Body ($response|ConvertTo-Json)
            Write-Host $response
        }

        "delete"{
            $body = @{"name"="delete file"; "object"=$object} | ConvertTo-Json
            $returnVal = execute_response($body)

        }
        #Need to include the name of the output file in the path.
        "memdump"{
            $body = @{"name"="memdump"; "object"=$object;} | ConvertTo-Json
                Write-Host "Beginning execution..."
                $sensor_id = acquire_sensor_id($hostname)
    
                $session_id = create_session($sensor_id)
                Write-Host "Session is now active."
                Write-Host "Executing $command..."
                $url = "$baseURL/api/v1/cblr/session/$Session_id/command"
                $response = Invoke-RestMethod -uri $url -Headers $coreHeaders -Method Post -Body $body
                $command_id = $response.id

                $scriptBlock = {
                    param($baseURL, $session_id, $command_id, $coreHeaders)
                    try{
                        #Adopt parent process certificate policy
                        If ($insecure.ToLower() -eq "true")
                        {
                            try
                            {
                                #Break indentation format. IDE doesn't like it.
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
                                $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
                                [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
                                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                                Write-Host "Certificate validation is being ignored."
                            }
                            catch{
                                Write-Error "Failed to ignore certificate validation."
                                Write-Error $_.Exception|format-list -force
                                exit 1
                            }
                        }
                        $url = "$baseURL/api/v1/cblr/session/$session_id/command/$command_id"
                        $response = Invoke-RestMethod -uri $url -Headers $coreHeaders
                        while($response.status -eq "pending"){
                            Start-Sleep -s 1
                            $response = Invoke-RestMethod -uri $url -Headers $coreHeaders
                        }
                    }
                    catch{
                        #Write-Host $response
                    }
                }
                Start-Job $scriptBlock -ArgumentList $baseURL, $session_id, $command_id, $coreHeaders, $insecure

        }

        "help"{
            Write-Host $helpMessage
            exit 0
        }

        default{
            exit 1
        }
    }
}

main

Write-Host "$command on $object for host $hostname executed successfully."
exit 0
# SIG # Begin signature block
# MIIcdQYJKoZIhvcNAQcCoIIcZjCCHGICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZS2DMFQxS9OzF0CdreM5WChw
# KKugghebMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTKMIIDsqADAgECAhA7fcSpOOvoChwkFo65IyOmMA0GCSqGSIb3DQEBCwUAMH8x
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0G
# A1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMg
# Q2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBMB4XDTE3MDQwNDAwMDAwMFoX
# DTIwMDQwNDIzNTk1OVowYjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRv
# MRAwDgYDVQQHDAdCb3VsZGVyMRYwFAYDVQQKDA1Mb2dSaHl0aG0gSW5jMRYwFAYD
# VQQDDA1Mb2dSaHl0aG0gSW5jMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEArr9SaqNn81S+mF151igpNeqvzWs40uPSf5tXu9iQUqXCWx25pECOcNk7W/Z5
# O9dXiQmdIvIFF5FqCkP6rzYtKx3OH9xIzoSlOKTxRWj3wo+R1vxwT9ThOvYiz/5T
# G5TJZ1n4ILFTd5JexoS9YTA7tt+2gbDtjKLBorYUCvXv5m6PREHpZ0uHXGCDWrJp
# zhiYQdtyAfxGQ6J9SOekYu3AiK9Wf3nbuoxLDoeEQ4boFW3iQgYJv1rRFA1k4AsT
# nsxDmEhd9enLZEQd/ikkYrIwkPVN9rPH6B+uRsBxIWIy1PXHwyaCTO0HdizjQlhS
# RaV/EzzbyTMPyWNluUjLWe0C4wIDAQABo4IBXTCCAVkwCQYDVR0TBAIwADAOBgNV
# HQ8BAf8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N2LnN5bWNiLmNv
# bS9zdi5jcmwwYQYDVR0gBFowWDBWBgZngQwBBAEwTDAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUHAQEESzBJ
# MB8GCCsGAQUFBzABhhNodHRwOi8vc3Yuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpo
# dHRwOi8vc3Yuc3ltY2IuY29tL3N2LmNydDAfBgNVHSMEGDAWgBSWO1PweTOXr32D
# 7y4rzMq3hh5yZjAdBgNVHQ4EFgQUf2bE5CWM4/1XmNZgr/W9NahQJkcwDQYJKoZI
# hvcNAQELBQADggEBAHfeSWKiWK1eI+cD/1z/coADJfCnPynzk+eY/MVh0jOGM2dJ
# eu8MBcweZdvjv4KYN/22Zv0FgDbwytBFgGxBM6pSRU3wFJN9XroLJCLAKCmyPN7H
# IIaGp5RqkeL4jgKpB5R6NqSb3ES9e2obzpOEvq49nPCSCzdtv+oANVYj7cIxwBon
# VvIqOZFxM9Bj6tiMDwdvtm0y47LQXM3+gWUHNf5P7M8hAPw+O2t93hPmd2xA3+U7
# FqUAkhww4IhdIfaJoxNPDjQ4dU+dbYL9BaDfasYQovY25hSe66a9S9blz9Ew2uNR
# iGEvYMyxaDElEXfyDSTnmR5448q1jxFpY5giBY0wggTTMIIDu6ADAgECAhAY2tGe
# Jn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHKMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5l
# dHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1
# dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVi
# bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0wNjEx
# MDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdv
# cmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhv
# cml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGlj
# IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWeYAyq50s7Ttx8vDxFHLsr4P4p
# AvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3S7P+j34HV+zvQ9tmYhVhz2AN
# pNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ2ENjalJL0o/ocFFN0Ylpe8dw
# 9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE75C55ADk3Tq1Gf8CuvQ87uCL
# 6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6sKlLHj9UESeSNY0eIPGmDy/5H
# vSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80h5aK7lPoJRUCAwEAAaOBsjCB
# rzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARh
# MF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvD
# z4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdp
# ZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQAD
# ggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSnoHgSrWIORXBkxeeXZi2YCX5f
# r9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjmBpFAGLn4we3f20Gq4JYgyc1k
# FTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpYT2DKfoJqCwKqJRc5tdt/54Rl
# KpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh9BFvELWV/OdCBTLbzp1RXii2
# noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2GdpxEevaVXPZdMggzpFS2GD9o
# XPJCSoU4VINf0egs8qwR1qjtY2owggVZMIIEQaADAgECAhA9eNf5dklgsmF99PAe
# yoYqMA0GCSqGSIb3DQEBCwUAMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVy
# aVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4
# BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQg
# dXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGljIFByaW1h
# cnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0xMzEyMTAwMDAwMDBa
# Fw0yMzEyMDkyMzU5NTlaMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEw
# MC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENB
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl4MeABavLLHSCMTXaJNR
# YB5x9uJHtNtYTSNiarS/WhtR96MNGHdou9g2qy8hUNqe8+dfJ04LwpfICXCTqdpc
# DU6kDZGgtOwUzpFyVC7Oo9tE6VIbP0E8ykrkqsDoOatTzCHQzM9/m+bCzFhqghXu
# PTbPHMWXBySO8Xu+MS09bty1mUKfS2GVXxxw7hd924vlYYl4x2gbrxF4GpiuxFVH
# U9mzMtahDkZAxZeSitFTp5lbhTVX0+qTYmEgCscwdyQRTWKDtrp7aIIx7mXK3/nV
# jbI13Iwrb2pyXGCEnPIMlF7AVlIASMzT+KV93i/XE+Q4qITVRrgThsIbnepaON2b
# 2wIDAQABo4IBgzCCAX8wLwYIKwYBBQUHAQEEIzAhMB8GCCsGAQUFBzABhhNodHRw
# Oi8vczIuc3ltY2IuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwbAYDVR0gBGUwYzBh
# BgtghkgBhvhFAQcXAzBSMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1dGgu
# Y29tL2NwczAoBggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5bWF1dGguY29tL3Jw
# YTAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2IuY29tL3BjYTMtZzUu
# Y3JsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMC
# AQYwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJLTEtNTY3MB0G
# A1UdDgQWBBSWO1PweTOXr32D7y4rzMq3hh5yZjAfBgNVHSMEGDAWgBR/02Wnwt3s
# u/AwCfNDOfoCrzMxMzANBgkqhkiG9w0BAQsFAAOCAQEAE4UaHmmpN/egvaSvfh1h
# U/6djF4MpnUeeBcj3f3sGgNVOftxlcdlWqeOMNJEWmHbcG/aIQXCLnO6SfHRk/5d
# yc1eA+CJnj90Htf3OIup1s+7NS8zWKiSVtHITTuC5nmEFvwosLFH8x2iPu6H2aZ/
# pFalP62ELinefLyoqqM9BAHqupOiDlAiKRdMh+Q6EV/WpCWJmwVrL7TJAUwnewus
# GQUioGAVP9rJ+01Mj/tyZ3f9J5THujUOiEn+jf0or0oSvQ2zlwXeRAwV+jYrA9zB
# UAHxoRFdFOXivSdLVL4rhF4PpsN0BQrvl8OJIrEfd/O9zUPU8UypP7WLhK9k8tAU
# ITGCBEQwggRAAgEBMIGTMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEw
# MC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENB
# AhA7fcSpOOvoChwkFo65IyOmMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTckX8SghOZpwslTsY5
# 4dIIjqVWGTANBgkqhkiG9w0BAQEFAASCAQASxhrGzrMAue9t+99RE90eUtf0Lnkp
# Lobg5EBMXmWPteghbLcNsmq9JphlUY3fCfiO9OcqEaTh6pAzjwtu8DIHG1iceYUh
# GQn3NrRpuR6tO4DvhzCIkGfvmEbS40ZqrSTAD1z7uG4AtzON52wDXMZ4L5g60ic4
# X6rJu2sebU9I8UyF0K6/OWLXBjU8cuw+RxN++VssztWiMw10+KD3OkpVF4HY9s9S
# /+93xgnTwx2PojCUqIUJNMozdeiCp9SrjsDJnYYQaV+22fsSkQQfifSWonGryfJ5
# Kc06QsSi7X0yefaUAH67zpPOq03nucHbg3CBCuPBYc6pFsAr3xj+P5DgoYICCzCC
# AgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P9DjI/r81bgTYapgbGlAwCQYF
# Kw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkF
# MQ8XDTE3MTEyNDE4NTkwMVowIwYJKoZIhvcNAQkEMRYEFOZ4xN90JzI+KjldJp2Q
# zvzUsHPzMA0GCSqGSIb3DQEBAQUABIIBABTSf6TfTFvrcScrsh0nR+GHzqm0T2h3
# 9fo31R2ly9Y+D4cTiKnAGE7Lg4sTjBDDhqhPIJh2dEMOqgnn5XcDtD1mklJI0iS/
# sSmhzp1hawmzMCPREo82acTvEC2iDhZSMM/ew45CwoV6GJ6rP4Ebb65dqg2BuI5k
# sEJO7++xslgRHHchd13h+ramms/8QLvhUz97M/w7KoiNAwmexnpYiL8t8cSKxdLG
# MadB289w6d7kU9K889mNfwZLwLLQs0Xbj+UUChUUHtXJyjWFdMMuVYsZ6MMYWIkO
# P49wD009T4zy3WVhxTE7smcvuXZjmvz8MBEuarixQvHrC1GUUX3sf4o=
# SIG # End signature block
