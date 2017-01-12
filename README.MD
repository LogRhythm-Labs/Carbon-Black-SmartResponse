
		LogRhythm Security Operations
		Carbon Black - SmartResponse
		michael . swisher @ logrhythm . com
		v0.1  --  November, 2016


## Carbon Black PowerShell API Script

For more information, please see the blog post on LogRhythm's Carbon Black integration:

	[Coming Soon!]

## Introduction:

This script provides basic functionality to interact with Carbon Black using PowerShell. Interactions with the server are performed using Invoke-RestMethod and passing the commands with their parameters inside of a JSON body. In order to use, make sure you acquire an API key from the Carbon Black interface or your Carbon Black administrator.

## Available Commands:
	delete		Delete file on remote host
	get			Download file from remote host to a local directory
	isolate		Isolate remote host network availability (still allows connection to Carbon Black server)
	kill		Kill process on remote host
	memdump		Dump memory to remote directory on remote host
	ps			List all processes of remote host (output to specified local file, otherwise output to console)

## Usage:

#### delete
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'delete' -object '<target file on remote system>'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'delete' -object '\\network-share\example\malicious.exe'

#### get
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'get' -object '<target file on remote system>' -location '<directory for output on local system>'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'get' -object '\\network-share\target.user\malicious.exe' -location '\\network-share\MeMyselfAndCarbonBlack\Documents\'

#### isolate
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'isolate' -object '<true|false>'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'isolate' -object 'true'

#### kill
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'kill' -object '<process ID to kill on remote system>'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'kill' -object '1234'

#### memdump
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'memdump' -object '<dump location on remote system>'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'memdump' -object '\\network-share\target.user\memdumpfile.dmp'

#### ps
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'ps' -object '<local file output path>'
		.\Carbon_Black_Response.ps1 -hostname '<target host>' -key '<your API key>' -baseURL '<url to your Carbon Black server>' -command 'ps'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'ps' -object '\\network-share\MeMyselfAndCarbonBlack\Documents\targetSystemProcesses.txt'
		Example:
		.\Carbon_Black_Response.ps1 -hostname 'USVM01PRODEMAIL' -key 'adsfasdfasdvsdf' -baseURL 'https://carbon.example.com:1234' -command 'ps'

## Use Cases:

Outside of the obvious available commands, this script provides functionality to create a process flow for responding to events by building on top of what is currently found within the script. This is extremely useful for event response and incident management. For instance, if a user had their system compromised, a script could execute a memory dump, followed by isolating the compromised system from all network activity [with the exception of connectivity to Carbon Black]. Going off of the previous example, if the culprit program is known, it would be possible to kill the process, get a copy of the file for later analysis, then follow with deleting the file. [Refer to example response script for further details.

## Development:

All commands are executed within a switch command found in the main function. In order to add a command (generally speaking), simply add another switch statement. From there to prepare the command parameters, add the following two lines of code to the body of the switch statement command:

$body = @{"name"="<static command name as specified by Carbon Black API>"; "object"=$object} | ConvertTo-Json
$returnVal, $Session_id = execute_response($body)

The $object variable is the parameter that is passed in as a command line argument when it is executed. It is possible to get more complex or create entirely customized executions as seen with the "get" and "isolate" commands. Anything with file transfer (i.e. commands like "get" and "put") usually require additional API calls. This example will background file transfers and file creation (like "memdump") in order to expedite response for any programs that expect output and have feedback timeouts. It is is NOT necessary to background processes NOR are exit codes; They were added for formality more than necessity.

If the headers that are sent within the HTTP requests need to be modified or need fields added, modify the $coreHeaders variable to make it suit whatever is needed.

If there are issues encountered and the script isn't giving proper output, using a proxy to intercept the requests may be extremely helpful. Burp was used for debugging during the development of this script. An example scenario was to debug the formation of the HTTP requests, and the response structure for the request. With the Invoke-RestMethod command, it is possible to provide proxy information as follows:

## Example:

	Invoke-RestMethod -Uri $url -Headers $coreHeaders -Method Post -Body $body -Verbose -Proxy http://127.0.0.1:8080 -ProxyUseDefaultCredentials

	This example works with a default install of Burp with proxy enabled on the local system.

## Future Goals:

Ideally, this script could be used with an event feed from Carbon Black. We do not currently have a script that retrieves the alerts feed to supplement this. In a dream scenario, an alert for a file with a high risk score would come through, and this script would be used to aid in automating the ban of the file, killing the process if it exists, retrieving a copy of it, followed by deleting it. In extreme scenarios, the system would also be isolated and shutdown by executing a shutdown or locked to prevent user intervention during response and forensics.

## License

Copyright (c) 2016 LogRhythm

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.