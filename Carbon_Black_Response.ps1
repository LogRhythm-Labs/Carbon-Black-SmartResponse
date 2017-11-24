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
                param($url, $coreHeaders, $output, $location)
                try{
                    
                    Invoke-RestMethod -Uri $url -Headers $coreHeaders -OutFile $output
                    '''
                    echo $location | Out-File ($location + "status.txt")
                    '''

                }
                catch{
                    
                    #Write-Error "Error retrieving file."
                    echo $url | Out-File $location + "error.txt"
                    
                    echo $_ | Out-File ($location + "error.txt") -Append
                    exit 1
                }
            }

            Start-Job -ScriptBlock $scriptBlock -ArgumentList $url, $coreHeaders, $output, $location

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
                Start-Job $scriptBlock -ArgumentList $baseURL, $session_id, $command_id, $coreHeaders

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
# MIIdxgYJKoZIhvcNAQcCoIIdtzCCHbMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJXuFRY7lxdwpJVKAIRJ/oQJU
# Rtmgghi2MIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# ggTTMIIDu6ADAgECAhAY2tGeJn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHK
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsT
# FlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlT
# aWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZl
# cmlTaWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkgLSBHNTAeFw0wNjExMDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl
# cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWdu
# LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT
# aWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgLSBHNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWe
# YAyq50s7Ttx8vDxFHLsr4P4pAvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3
# S7P+j34HV+zvQ9tmYhVhz2ANpNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ
# 2ENjalJL0o/ocFFN0Ylpe8dw9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE
# 75C55ADk3Tq1Gf8CuvQ87uCL6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6s
# KlLHj9UESeSNY0eIPGmDy/5HvSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80
# h5aK7lPoJRUCAwEAAaOBsjCBrzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
# AwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcG
# BSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJp
# c2lnbi5jb20vdnNsb2dvLmdpZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8z
# MTMwDQYJKoZIhvcNAQEFBQADggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSn
# oHgSrWIORXBkxeeXZi2YCX5fr9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjm
# BpFAGLn4we3f20Gq4JYgyc1kFTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpY
# T2DKfoJqCwKqJRc5tdt/54RlKpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh
# 9BFvELWV/OdCBTLbzp1RXii2noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2G
# dpxEevaVXPZdMggzpFS2GD9oXPJCSoU4VINf0egs8qwR1qjtY2owggU0MIIEHKAD
# AgECAhBvzqThCU6soC46iUEXOXVFMA0GCSqGSIb3DQEBBQUAMIG0MQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWdu
# IFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9mIHVzZSBhdCBodHRwczov
# L3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTEwMS4wLAYDVQQDEyVWZXJpU2lnbiBD
# bGFzcyAzIENvZGUgU2lnbmluZyAyMDEwIENBMB4XDTE1MDQwOTAwMDAwMFoXDTE3
# MDQwMTIzNTk1OVowZjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRAw
# DgYDVQQHEwdCb3VsZGVyMRgwFgYDVQQKFA9Mb2dSaHl0aG0sIEluYy4xGDAWBgNV
# BAMUD0xvZ1JoeXRobSwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKwJYFWf7THEfBgk4pfEUtyGbYUnZmXxJVTTtyy5f0929hCAwuy09oEHpZqD
# uregBi0oZmGo+GJT7vF6W0PZCieXFzxyNfWqJxFb1mghKo+6aweDXWXEdpp/y38k
# /+iu9MiiOFVuJzKNxMD8F6iJ14kG64K+P9gNxIu2t4ajKRDKhN5V8dSDYqdjHlM6
# Vt2WcpqUR3E2LQXrls/aYmKe1Dg9Lf8R/0OeJPLQdnXuSIhBTTdrADmhwgh9F/Q5
# Wj0hS2rURWEIdn3HQsW5xJcHuYxh3YQUIIoDybY7ZolGrRNa1gKEEZVy3iMKoK28
# HEFkuBVGtVSqRed9um99XUU1udkCAwEAAaOCAY0wggGJMAkGA1UdEwQCMAAwDgYD
# VR0PAQH/BAQDAgeAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9zZi5zeW1jYi5j
# b20vc2YuY3JsMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUH
# AQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vc2Yuc3ltY2QuY29tMCYGCCsGAQUF
# BzAChhpodHRwOi8vc2Yuc3ltY2IuY29tL3NmLmNydDAfBgNVHSMEGDAWgBTPmanq
# eyb0S8mOj9fwBSbv49KnnTAdBgNVHQ4EFgQUoxV4rZFrQYUJv5kT9HiDLKNevs0w
# EQYJYIZIAYb4QgEBBAQDAgQQMBYGCisGAQQBgjcCARsECDAGAQEAAQH/MA0GCSqG
# SIb3DQEBBQUAA4IBAQDtr3hDFtDn6aOruSnJYX+0YqoWREkevcGwpM0bpuJvpCRo
# Fkl8PDobpukMNQdod3/4Iee+8ZRDObYAdKygL4LbLWlaG++wxPQJUXKurRgx/xrm
# SueNFE4oXPGkGG1m3Ffvp38MfUY3VR22z5riQmc4KF2WOTl2eJFiAKTRv31Wf46X
# V3TnMeSuJU+HGNQx1+XXYuK7vgZdyxRVftjbNSW26v/6PAv7slYyiOCvYvnSVCo4
# Kdc+zHj02Nm0IfGyuO+d+992+hEEnWk/WxLwjYXMs6hcHAmuFcfMNY0/mstdWq5/
# dlT/rOBNvFOpMshhwxT1Gl5FlpLzmdj/AbGaUPDSMIIGCjCCBPKgAwIBAgIQUgDl
# qiVW/BqG7ZbJ1EszxzANBgkqhkiG9w0BAQUFADCByjELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBO
# ZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBh
# dXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1
# YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwHhcNMTAw
# MjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtDELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3
# b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNp
# Z24uY29tL3JwYSAoYykxMDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2Rl
# IFNpZ25pbmcgMjAxMCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# APUjS16l14q7MunUV/fv5Mcmfq0ZmP6onX2U9jZrENd1gTB/BGh/yyt1Hs0dCIzf
# aZSnN6Oce4DgmeHuN01fzjsU7obU0PUnNbwlCzinjGOdF6MIpauw+81qYoJM1SHa
# G9nx44Q7iipPhVuQAU/Jp3YQfycDfL6ufn3B3fkFvBtInGnnwKQ8PEEAPt+W5cXk
# lHHWVQHHACZKQDy1oSapDKdtgI6QJXvPvz8c6y+W+uWHd8a1VrJ6O1QwUxvfYjT/
# HtH0WpMoheVMF05+W/2kk5l/383vpHXv7xX2R+f4GXLYLjQaprSnTH69u08MPVfx
# MNamNo7WgHbXGS6lzX40LYkCAwEAAaOCAf4wggH6MBIGA1UdEwEB/wQIMAYBAf8C
# AQAwcAYDVR0gBGkwZzBlBgtghkgBhvhFAQcXAzBWMCgGCCsGAQUFBwIBFhxodHRw
# czovL3d3dy52ZXJpc2lnbi5jb20vY3BzMCoGCCsGAQUFBwICMB4aHGh0dHBzOi8v
# d3d3LnZlcmlzaWduLmNvbS9ycGEwDgYDVR0PAQH/BAQDAgEGMG0GCCsGAQUFBwEM
# BGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAhMB8wBwYFKw4DAhoEFI/l0xqGrI2O
# a8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28u
# Z2lmMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3Bj
# YTMtZzUuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AudmVyaXNpZ24uY29tMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItODAdBgNVHQ4E
# FgQUz5mp6nsm9EvJjo/X8AUm7+PSp50wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
# Qzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQADggEBAFYi5jSkxGHLSLkBrVaoZA/ZjJHE
# u8wM5a16oCJ/30c4Si1s0X9xGnzscKmx8E/kDwxT+hVe/nSYSSSFgSYckRRHsExj
# jLuhNNTGRegNhSZzA9CpjGRt3HGS5kUFYBVZUTn8WBRr/tSk7XlrCAxBcuc3IgYJ
# viPpP0SaHulhncyxkFz8PdKNrEI9ZTbUtD1AKI+bEM8jJsxLIMuQH12MTDTKPNjl
# N9ZvpSC9NOsm2a4N58Wa96G0IZEzb4boWLslfHQOWP51G2M/zjF8m48blp7FU3aE
# W5ytkfqs7ZO6XcghU8KCU2OvEg1QhxEbPVRSloosnD2SGgiaBS7Hk6VIkdMxggR6
# MIIEdgIBATCByTCBtDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJ
# bmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJU
# ZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykx
# MDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAxMCBD
# QQIQb86k4QlOrKAuOolBFzl1RTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUohZSyT0JPCs47bLj
# Nt9vsuptd40wDQYJKoZIhvcNAQEBBQAEggEAVG0Y8h28JStkFEQv4V3g5BSq4bjb
# /uwAne4oR2NTo5RA7Ikpgk7jMJ8y2Ed3MnaHcidf11obbgR/u+d4BHMVwmGv5Dk4
# Td96QW5sBpD2xk2PVXkOgsOmxxaqr1N8eJrgehKPCjp+3oDvAu0P/1d5uiI/dgft
# j5sMqy0DnWhYolcPcfiJdCFft8SzCT8/cnDqIl/Bw1te/qw+A2d7MMnLuJI8I0aQ
# 2SWBggKPshBMl23HGdf7QwknZluFcoxNmvl6RsOu+Bktdp7z6fiwbNbvxXnOVDuk
# fjntQw2g0yYCYp6A2jcorAYgjU8p5Q3BkdsJKOO1eG8Mqx0yUIe1cl8EPKGCAgsw
# ggIHBgkqhkiG9w0BCQYxggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYD
# VQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGlt
# ZSBTdGFtcGluZyBTZXJ2aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNzAxMTMwMDE1MjVaMCMGCSqGSIb3DQEJBDEWBBQYZvMkedZDLl20rdtf
# SE/ctrUPkDANBgkqhkiG9w0BAQEFAASCAQBJ3l+qb/+MzBxmV1SIA0CNc78w21E4
# aZC98xA+aZcc34fnTjqigt+UckZ/VJFTNfSedxFDvwo+dS38qi4nwa224TSltKLh
# ibyKbtjcxUO5Eg8zEzTwFFaEBvKQ3Wp+PiB3q/Tx2/AGT3U5loujrSsnRj4fuOnu
# 8oskgPXcizepk+JjvHMpqp6brYKw3ci/695UYC1LIDT+dvqfoxESnpqM7J7p6E8v
# POOyMdBXdc7cGlEygr3sATpddFgfV4YErsB4ECUOYcLTbWD2P7Eux+NQRNt5IKcN
# UOxZjUdlXDmQRvRqzF8SsznpoOxRS75scd2LNXirXf086wwNJSCcd4Q3
# SIG # End signature block
