##Subdomain Enum / WAF Origin IP Find
```
VirusTotal
https://www.virustotal.com/vtapi/v2/domain/report

AlienVault
https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1

URLScan (recommended v3)
https://urlscan.io/api/v3/search/?q=domain:<DOMAIN>&size=10000

WebArchive
https://web.archive.org/cdx/search/cdx?url={DOMAIN}&fl=original&collapse=urlkey

Shodan favicon
http.favicon.hash:126547436

Shodan SSL CN search
shodan search ssl.cert.subject.CN:"rapfame.app" 200 --fields ip_str | httx-toolkit -sc -title -server -td
```

##Subdomains & Certificates
```
# crt.sh (CT logs → subdomains)
curl -s "https://crt.sh/?q=%25<DOMAIN>&output=json" \
| jq -r '.[].name_value' | tr '[:upper:]' '[:lower:]' \
| sed 's/\*\.//g' | sort -u

# CertSpotter (CT logs, nice JSON) – no key for light use
curl -s "https://api.certspotter.com/v1/issuances?domain=<DOMAIN>&include_subdomains=true&expand=dns_names" \
| jq -r '.[].dns_names[]' | sed 's/\*\.//g' | sort -u

# SecurityTrails (rich DNS/passive) – API key in header
curl -s "https://api.securitytrails.com/v1/domain/<DOMAIN>/subdomains" \
  -H "APIKEY: $SECURITYTRAILS_KEY" \
| jq -r '.subdomains[] | . + ".<DOMAIN>"'

# Sonar (omnisint community index)
curl -s "https://sonar.omnisint.io/subdomains/<DOMAIN>" | jq -r '.[]'
```

##Passive DNS / Historical URLs
```
# URLScan (search v3) – historical URLs + IPs
curl -s "https://urlscan.io/api/v3/search/?q=domain:<DOMAIN>&size=10000" \
| jq -r '.results[]?.page?.url' | sort -u

# Wayback (CDX) – discovered URLs
curl -s "https://web.archive.org/cdx/search/cdx?url=*.%3CDOMAIN%3E/*&output=json&fl=original&collapse=urlkey" \
| jq -r '.[1:][] | .[0]' | sort -u

# Common Crawl index (may change by crawl id)
curl -s "http://index.commoncrawl.org/CC-MAIN-2024-33-index?url=*.%3CDOMAIN%3E/*&output=json" \
| jq -r '.[].url' | sort -u

```

##DNS/WHOIS/ASNs/Netblocks
```
# Enumerate NS → attempt (safe) AXFR (only if permitted)
for ns in $(dig +short NS <DOMAIN>); do dig AXFR <DOMAIN> @$ns; done

# Team Cymru ASN info (whois)
whois -h whois.cymru.com " -v <IP>"            # IP → ASN/org
whois -h whois.cymru.com " -v AS<ASN>"         # ASN → prefixes

# BGPView (JSON prefixes for ASN)
curl -s "https://api.bgpview.io/asn/AS<ASN>/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'

# Reverse DNS sweep of a CIDR (requires fping/dnsx if you want fast)
prips <CIDR> | xargs -I{} dig +short -x {}

```

##Screenshots / Tech Fingerprinting
```
# URLScan shot URLs (if available)
curl -s "https://urlscan.io/api/v3/search/?q=domain:<DOMAIN>&size=100" \
| jq -r '.results[]?.screenshot' | sed 's#^#/##' | sed 's#^#https://urlscan.io#'

# Wappalyzer (needs key)
curl -s "https://api.wappalyzer.com/v2/lookup/?url=https://<DOMAIN>" \
  -H "x-api-key: $WAPPALYZER_KEY" | jq

```

##Favicon Hash → Infra Pivoting
```
# Download favicon & MMH3 hash (Python one-liner)
python3 - <<'PY'
import mmh3, requests, base64, sys
u = "https://<DOMAIN>/favicon.ico"
r = requests.get(u, timeout=10, verify=False)
h = mmh3.hash(base64.b64encode(r.content))
print(h)
PY

# Shodan query by favicon hash
# (replace HASH)
shodan search http.favicon.hash:HASH --fields ip_str,port,hostnames

```
