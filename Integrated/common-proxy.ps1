param([int]$Port = 8787)

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Host "Investigation Suite proxy listening on http://127.0.0.1:$Port/ (Ctrl+C to stop)"

function Send-Json($response, [int]$status, $payload) {
  $response.StatusCode = $status
  $response.ContentType = 'application/json; charset=utf-8'
  $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 20 -Compress))
  $response.OutputStream.Write($bytes, 0, $bytes.Length)
}

try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request; $response = $context.Response
    $response.Headers.Add('Access-Control-Allow-Origin','*')
    $response.Headers.Add('Access-Control-Allow-Headers','Content-Type, X-API-Key')
    $response.Headers.Add('Access-Control-Allow-Methods','GET, OPTIONS')
    $response.Headers.Add('Access-Control-Allow-Private-Network','true')
    try {
      if ($request.HttpMethod -eq 'OPTIONS') { $response.StatusCode = 204; continue }
      $path = $request.Url.AbsolutePath
      if ($path -like '/api/v3/*') {
        $key = $request.Headers['X-API-Key']
        if ([string]::IsNullOrWhiteSpace($key)) { Send-Json $response 400 @{error='VirusTotal API key is required.'}; continue }
        $uri = 'https://www.virustotal.com' + $path + $request.Url.Query
        $remote = Invoke-WebRequest -Uri $uri -Headers @{ 'x-apikey'=$key; Accept='application/json' } -UseBasicParsing
        $response.StatusCode = [int]$remote.StatusCode; $response.ContentType = 'application/json; charset=utf-8'
        $bytes = [Text.Encoding]::UTF8.GetBytes($remote.Content); $response.OutputStream.Write($bytes,0,$bytes.Length)
        continue
      }
      if ($path -eq '/check') {
        $key = $request.Headers['X-API-Key']; $input = $request.QueryString['input']
        if ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($input)) { Send-Json $response 400 @{error='Input and AbuseIPDB API key are required.'}; continue }
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($input, [ref]$ip)) {
          try { $ip = [Net.Dns]::GetHostAddresses($input) | Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1 } catch {}
        }
        if ($null -eq $ip) { Send-Json $response 400 @{error='The domain could not be resolved to an IPv4 address.'}; continue }
        $encodedIp = [uri]::EscapeDataString($ip.IPAddressToString)
        $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$encodedIp&maxAgeInDays=182&verbose"
        $result = Invoke-RestMethod -Uri $uri -Headers @{ Key=$key; Accept='application/json' } -Method Get
        Send-Json $response 200 $result; continue
      }
      Send-Json $response 404 @{error='Unknown proxy route.'}
    } catch {
      $status = 502
      if ($_.Exception.Response) { try { $status = [int]$_.Exception.Response.StatusCode } catch {} }
      Send-Json $response $status @{error=$_.Exception.Message}
    } finally { $response.OutputStream.Close() }
  }
} finally { if ($listener.IsListening) { $listener.Stop() }; $listener.Close() }
