# VirusTotal Lookup

An offline HTML interface for bulk VirusTotal lookups of file hashes, domains, and IPv4/IPv6 addresses.

## Files

- `virustotal-lookup.html` — the browser interface.
- `vt-proxy.ps1` — a local PowerShell proxy that forwards requests to VirusTotal API v3.

## Run

1. Open PowerShell and start the proxy. Keep this window open:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\vt-proxy.ps1
   ```

2. Open `virustotal-lookup.html` in a browser.
3. Paste a VirusTotal API key and one or more inputs separated by commas or new lines.

The key is entered at runtime and is not saved in the HTML file.

## Output

- **Malicious** — one or more malicious engine detections.
- **Benign** — harmless detections with no malicious or suspicious detections.
- **No record** — VirusTotal has no record for the input.
- **Unknown** — inconclusive or suspicious-only results; review required.

For malicious results, the page shows detecting engines and relevant related objects such as contacted domains/IPs, communicating files, dropped files, and DNS resolutions. Domain results also include WHOIS information when VirusTotal provides it.

## Notes

- Internet access is required for VirusTotal requests; the UI itself is a standalone HTML file.
- Restart the PowerShell proxy after changing `vt-proxy.ps1`.
- Use a Premium/enterprise VirusTotal license for business workflows. Do not embed an API key in the HTML file or publish it to source control.
