# Collecting Data
$osInfo = Get-ComputerInfo | Select-Object -Property CsName, WindowsVersion, OsArchitecture, WindowsBuildLabEx
$dotNetVersions = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
    Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
    Where-Object { $_.Version -match '^\d+\.\d+' } |
    Select-Object PSChildName, Version
$amsiProviders = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue |
    Select-Object PSChildName
if (-not $amsiProviders) { $amsiProviders = "N/A" }
$antivirus = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
    Select-Object displayName, productState
if (-not $antivirus) { $antivirus = "N/A" }
$firewallRules = Get-WmiObject -Namespace "root\StandardCimv2" -Class "MSFT_NetFirewallRule" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Direction, Action, Enabled
if (-not $firewallRules) { $firewallRules = "N/A" }

# Auto-run executables/scripts/programs
$autoRuns = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Get-ItemProperty -Name * | Select-Object PSChildName, *
if (-not $autoRuns) { $autoRuns = "N/A" }

# Local Users
$localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | 
    Select-Object Name, Disabled
if (-not $localUsers) { $localUsers = "N/A" }

# Installed Hotfixes
$hotfixes = Get-WmiObject -Query "Select * from Win32_QuickFixEngineering" -ErrorAction SilentlyContinue
if (-not $hotfixes) { $hotfixes = "N/A" }

# Installed Products via Registry
$installedProducts = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
if (-not $installedProducts) { $installedProducts = "N/A" }

# Network Information

# Parse ARP table for IP, MAC, Interface, and Type
$parsedArpTable = @()
$arpTable -split "rn" | ForEach-Object {
    if ($_ -match '^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)') {
        $parsedArpTable += @{
            Interface = $matches[1]
            IpAddress = $matches[2]
            MacAddress = $matches[3]
            Type = $matches[4]
        }
    }
}

# 2. DNS cache entries (via WMI)
$dnsCache = Get-WmiObject -Query "SELECT * FROM Win32_DnsClientCache" -ErrorAction SilentlyContinue
if (-not $dnsCache) { $dnsCache = "N/A" }

# 3. Windows network profiles
$networkProfiles = Get-NetConnectionProfile | Select-Object Name, NetworkCategory, IPv4Connectivity, IPv6Connectivity
if (-not $networkProfiles) { $networkProfiles = "N/A" }

# 4. Network shares exposed by the machine
$networkShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue | Select-Object Name, Path, Description
if (-not $networkShares) { $networkShares = "N/A" }

# 5. Current TCP and UDP connections
$tcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
$udpConnections = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort
if (-not $tcpConnections) { $tcpConnections = "N/A" }
if (-not $udpConnections) { $udpConnections = "N/A" }

# 6. Current RPC endpoints mapped
$rpcEndpoints = Get-WmiObject -Class Win32_RPCServer -ErrorAction SilentlyContinue | Select-Object Name, Caption
if (-not $rpcEndpoints) { $rpcEndpoints = "N/A" }

# 7. Open ports status
$openPorts = netstat -an | Select-String "LISTEN"
if (-not $openPorts) { $openPorts = "N/A" }

# Network Interface and Connectivity

# 1. System interface connectors
$networkInterfaces = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress
if (-not $networkInterfaces) { $networkInterfaces = "N/A" }

# 2. LLDP/CDP connections (to infrastructure devices)
$lldpInfo = Get-WmiObject -Namespace "root\StandardCimv2" -Class "MSFT_NetNeighbor" -ErrorAction SilentlyContinue
if (-not $lldpInfo) { $lldpInfo = "N/A" }

# 3. Attached network vectors (systems connected within the VLAN)
$vlanInfo = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
if (-not $vlanInfo) { $vlanInfo = "N/A" }
 


# Create Enhanced HTML Content with Tables for All Key Sections
$htmlContent = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>System Information Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; color: #333; }
        h1 { text-align: center; font-size: 30px; color: #005f8b; margin-bottom: 30px; }
        h2 { color: #005f8b; font-size: 24px; border-bottom: 2px solid #005f8b; padding-bottom: 5px; margin-top: 40px; }
        h3 { color: #007ACC; font-size: 18px; margin-top: 20px; }

        /* Styling for Preformatted Text Blocks */
        pre { background-color: #f4f4f4; padding: 15px; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; font-size: 14px; }

        /* General Table Styling */
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; border: 1px solid #ccc; font-size: 14px; }
        th, td { padding: 12px 15px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #005f8b; color: white; font-weight: bold; text-transform: uppercase; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }

        /* Additional Styling for Key Highlights */
        .highlight { background-color: #fffae5; padding: 10px; border-radius: 5px; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-danger { color: #dc3545; font-weight: bold; }

        /* Header Styling */
        header { text-align: center; margin-bottom: 50px; }
        header img { width: 150px; margin-bottom: 10px; }
    </style>
</head>
<body>

<header>
    <img src='https://i.pinimg.com/originals/7b/bd/b6/7bbdb694fc92ca79c03a04650e05d0c1.png' alt='Logo'>
    <h1>Vulnerability Report</h1>
</header>

<h2>Basic OS Information</h2>
<table>
    <thead>
        <tr><th>Computer Name</th><th>Windows Version</th><th>Architecture</th><th>Build Number</th></tr>
    </thead>
    <tbody>
        <tr>
            <td>$($osInfo.CsName)</td>
            <td>$($osInfo.WindowsVersion)</td>
            <td>$($osInfo.OsArchitecture)</td>
            <td>$($osInfo.WindowsBuildLabEx)</td>
        </tr>
    </tbody>
</table>

<h2>.NET Versions</h2>
<table>
    <thead>
        <tr><th>.NET Version</th><th>Version Number</th></tr>
    </thead>
    <tbody>
        $($dotNetVersions | ForEach-Object {
            "<tr><td>$($_.PSChildName)</td><td>$($_.Version)</td></tr>"
        })
    </tbody>
</table>

<h2>AMSI Providers</h2>
<table>
    <thead>
        <tr><th>Provider Name</th></tr>
    </thead>
    <tbody>
        $($amsiProviders | ForEach-Object {
            "<tr><td>$($_.PSChildName)</td></tr>"
        })
    </tbody>
</table>

<h2>Registered Antivirus</h2>
<table>
    <thead>
        <tr><th>Antivirus Name</th><th>Product State</th></tr>
    </thead>
    <tbody>
        $($antivirus | ForEach-Object {
            "<tr><td>$($_.displayName)</td><td>$($_.productState)</td></tr>"
        })
    </tbody>
</table>

<h2>Firewall Rules</h2>
<table>
    <thead>
        <tr><th>Direction</th><th>Display Name</th><th>Action</th><th>Enabled</th></tr>
    </thead>
    <tbody>
        $($firewallRules | ForEach-Object {
            "<tr><td>$($_.Direction)</td><td>$($_.DisplayName)</td><td>$($_.Action)</td><td>$($_.Enabled)</td></tr>"
        })
    </tbody>
</table>

<h2>Local Users</h2>
<table>
    <thead>
        <tr><th>Name</th><th>Status</th></tr>
    </thead>
    <tbody>
        $($localUsers | ForEach-Object {
            $status = if ($_.Disabled -eq $false) { '<span class="status-ok">Enabled</span>' } else { '<span class="status-danger">Disabled</span>' }
            "<tr><td>$($_.Name)</td><td>$status</td></tr>"
        })
    </tbody>
</table>

<h2>Network Information</h2>

<h3>ARP Table</h3>
<table>
    <thead>
        <tr><th>Interface</th><th>IP Address</th><th>MAC Address</th><th>Type</th></tr>
    </thead>
    <tbody>
        $($arpTable -split "rn" | ForEach-Object {
            if ($_ -match "^\s*(\d+\.\d+\.\d+\.\d+)\s+([a-zA-Z0-9:-]+)\s+(\w+)\s+([a-zA-Z]+)") {
                "<tr><td>$($matches[1])</td><td>$($matches[2])</td><td>$($matches[3])</td><td>$($matches[4])</td></tr>"
            }
        })
    </tbody>
</table>

<h3>Adapter Information</h3>
<table>
    <thead>
        <tr><th>Adapter Name</th><th>Status</th><th>MAC Address</th></tr>
    </thead>
    <tbody>
        $($networkAdapters | ForEach-Object {
            "<tr><td>$($_.Name)</td><td>$($_.Status)</td><td>$($_.MACAddress)</td></tr>"
        })
    </tbody>
</table>

<h3>DNS Cache Entries</h3>
<pre>$($dnsCache | Out-String)</pre>

<h3>TCP and UDP Connections</h3>
<h4>TCP Connections</h4>
<pre>$($tcpConnections | Out-String)</pre>
<h4>UDP Connections</h4>
<pre>$($udpConnections | Out-String)</pre>

<h3>RPC Endpoints</h3>
<pre>$($rpcEndpoints | Out-String)</pre>

<h3>Open Ports Status</h3>
<pre>$openPorts</pre>

<h3>System Interface Connectors</h3>
<pre>$($networkInterfaces | Out-String)</pre>

<h3>LLDP/CDP Connections</h3>
<pre>$($lldpInfo | Out-String)</pre>

<h3>Attached Network Vectors</h3>
<pre>$($vlanInfo | Out-String)</pre>

</body>
</html>
"@

# Saving HTML Report
$userProfile = $env:USERPROFILE
$htmlFilePath = "$userProfile\Desktop\SystemInformationReport.html"
$htmlContent | Out-File -FilePath $htmlFilePath

# Convert HTML to PDF using wkhtmltopdf (if needed)
$wkhtmltopdfPath = "C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"  # Ensure this path is correct
if (Test-Path $wkhtmltopdfPath) {
    $pdfFilePath = "$userProfile\Desktop\SystemInformationReport.pdf"
    Start-Process $wkhtmltopdfPath -ArgumentList "--enable-local-file-access --no-background $htmlFilePath $pdfFilePath"
} else {
    Write-Output "wkhtmltopdf not found. Please install wkhtmltopdf or check the path."
}