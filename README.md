# Netcraft API Frontend

A simple frontend interface for querying the Netcraft Toolbar API.


## Features & Behavior

- Displays:
  - Risk (scale 0–10)
  - First Seen
  - Pattern Matches (> 0 = confirmed malicious activity)
  - IP / Netblock Info

- Provides links to:
  - The full Netcraft report
  - ASN information (via bgp.he.net)
  - The VirusTotal report for the IP

- Includes fallback scanners:
  - Sophos Intelix
  - Cisco Talos
  - IPQualityScore URL Scanner


## Usage

1. Enter a URL  
2. Click `Check`  
3. Review the results  
4. Use your own judgment to interpret them


## Notes

- Not affiliated with Netcraft.  
- For copyright or takedown requests, please open a GitHub iss
