param([int]$Port = 8787)
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Host "VirusTotal local proxy listening on http://127.0.0.1:$Port/"
try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()
    $response = $context.Response
    $response.Headers.Add('Access-Control-Allow-Origin', '*')
    $response.Headers.Add('Access-Control-Allow-Headers', 'X-API-Key, Content-Type')
    $response.Headers.Add('Access-Control-Allow-Methods', 'GET, OPTIONS')
    $response.Headers.Add('Access-Control-Allow-Private-Network', 'true')
    if ($context.Request.HttpMethod -eq 'OPTIONS') { $response.StatusCode = 204; $response.Close(); continue }
    try {
      $key = $context.Request.Headers['X-API-Key']
      if (-not $key) { throw 'Missing X-API-Key header.' }
      $path = $context.Request.Url.AbsolutePath
      $query = $context.Request.Url.Query
      if ($path -notmatch '^/api/v3/(files|domains|ip_addresses)/') { throw 'Unsupported lookup path.' }
      $uri = "https://www.virustotal.com$path$query"
      $result = Invoke-WebRequest -Uri $uri -Headers @{ 'accept' = 'application/json'; 'x-apikey' = $key } -UseBasicParsing
      $response.StatusCode = $result.StatusCode
      $body = $result.Content
    } catch {
      $response.StatusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 502 }
      $body = "{`"error`":{`"message`":`"$($_.Exception.Message.Replace('"','\"'))`"}}"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $response.ContentType = 'application/json; charset=utf-8'
    $response.ContentLength64 = $bytes.Length
    $response.OutputStream.Write($bytes,0,$bytes.Length)
    $response.Close()
  }
} finally { $listener.Close() }
