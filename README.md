# The Nessus Butcher
### Read data from one or more .nessus files, filter data, and output as text, html or excel

A needed but tedious tasks involved in enterprise vulnerability assessment and remediation is distributing needed findings to each owner.
It is tedious, as ownership usually not align with your typical scanning strategy, and a lot of time and effort is needed to cut and paste needed data to each owner.

A typical strategy may be to scan a geographical region at a time, but a specific branch office or some network infrastructure may have different owners to that region and should therefor have its own vulnerability scan reports. Or when the head office have a global communications responsible that need router findings from all scanned sites.

In such situations, the result from one or more .nessus scans are needed as in-data, then filters are applied to suit this owner, and finally rendered in a format usable for its audience, often excel so they can track remediation progress. 

This is what the nessus butcher does, cut nessus scan reports in easily digestible pieces. All filter option can be inverted to get the opposite result, useful not to lose any data when cutting in two. 

In the butcher analogy, the enterprise is obviously the carcasses, and you are the butcher that separates the rib eye from the t-bone to feed your hungry security managers. 

### Read data from multiple .nessus scan files

Count findings from a single example scan:
```
$ python3 butcher.py examples/example_scan.nessus |wc -l
80
```

Another example:
```
$ python3 butcher.py examples/scanTestReport.nessus |wc -l
40
```

Both files combined. Some findings overlap, hence the total number of findings are lower that adding count from both individual files:
```
$ python3 butcher.py examples/example_scan.nessus examples/scanTestReport.nessus |wc -l
106
```


### Filter options

Filter on severity, to only list critical findings: 
```
$ python3 butcher.py examples/example_scan.nessus --min-severity critical
ID	severity	pluginName	IP
63145	Critical	USN-1638-3 : firefox regressions	192.168.1.43
63023	Critical	USN-1636-1 : thunderbird vulnerabilities	192.168.1.43
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.34,192.168.1.100
34477	Critical	MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (uncredentialed check)	192.168.1.34,192.168.1.100
22194	Critical	MS06-040: Vulnerability in Server Service Could Allow Remote Code Execution (921883) (uncredentialed check)	192.168.1.100
```

Host is used to filter in or out matching hostnames:
```
$ python3 butcher.py examples/*.nessus --min-severity medium --include-host www.baidu.com
ID	severity	pluginName	IP
20007	Medium	SSL Version 2 and 3 Protocol Detection	www.baidu.com
```

Whereas network is used to match all hosts in an entire IPv4 network, according to netmask:
```
$ python3 butcher.py examples/example_scan.nessus --min-severity critical --include-network 192.168.1.0/24
ID	severity	pluginName	IP
63145	Critical	USN-1638-3 : firefox regressions	192.168.1.43
63023	Critical	USN-1636-1 : thunderbird vulnerabilities	192.168.1.43
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.34,192.168.1.100
34477	Critical	MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (uncredentialed check)	192.168.1.34,192.168.1.100
22194	Critical	MS06-040: Vulnerability in Server Service Could Allow Remote Code Execution (921883) (uncredentialed check)	192.168.1.100
```

The title text can be filtered with --match as follows:
```
$ python3 butcher.py examples/example_scan.nessus  --match sql
ID	severity	pluginName	IP
35635	High	MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) (uncredentialed check)	192.168.1.100
34311	High	MS08-040: Microsoft SQL Server Multiple Privilege Escalation (941203) (uncredentialed check)	192.168.1.100
10674	None	Microsoft SQL Server UDP Query Remote Version Disclosure	192.168.1.100
10144	None	Microsoft SQL Server TCP/IP Listener Detection	192.168.1.100
```

Match is a regular expression, which can be useful to find for example matching SSL or TLS with ssl|tls, or Microsoft patch names: MSxx-xxx

```
$ python3 butcher.py examples/example_scan.nessus  --match 'ms[\d]+'
ID	severity	pluginName	IP
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.34,192.168.1.100
34477	Critical	MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (uncredentialed check)	192.168.1.34,192.168.1.100
22194	Critical	MS06-040: Vulnerability in Server Service Could Allow Remote Code Execution (921883) (uncredentialed check)	192.168.1.100
58435	High	MS12-020: Vulnerabilities in Remote Desktop Could Allow Remote Code Execution (2671387) (uncredentialed check)	192.168.1.100
35635	High	MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) (uncredentialed check)	192.168.1.100
34311	High	MS08-040: Microsoft SQL Server Multiple Privilege Escalation (941203) (uncredentialed check)	192.168.1.100
22034	High	MS06-035: Vulnerability in Server Service Could Allow Remote Code Execution (917159) (uncredentialed check)	192.168.1.100
```

The pluginName data is used in the nessus_v2 as a title or description, and as default this is matched against in searches. pluginName can be changed to any other key using the --match-key parameter. 

For example to list all services identified as www use the svc_name key as follows:
```
$ python3 butcher.py examples/example_scan.nessus  --match-key svc_name --match www
ID	severity	pluginName	IP
51192	Medium	SSL Certificate Cannot Be Trusted	192.168.1.43
45411	Medium	SSL Certificate with Wrong Hostname	192.168.1.43
62563	None	SSL Compression Methods Supported	192.168.1.43
56984	None	SSL / TLS Versions Supported	192.168.1.43
45410	None	SSL Certificate commonName Mismatch	192.168.1.43
43111	None	HTTP Methods Allowed (per directory)	192.168.1.43,192.168.1.1
39521	None	Backported Security Patch Detection (WWW)	192.168.1.43
24260	None	HyperText Transfer Protocol (HTTP) Information	192.168.1.43,192.168.1.43
22964	None	Service Detection	192.168.1.43,192.168.1.43,192.168.1.43,192.168.1.1,192.168.1.1
21643	None	SSL Cipher Suites Supported	192.168.1.43
20108	None	Web Server / Application favicon.ico Vendor Fingerprinting	192.168.1.43
14272	None	netstat portscanner (SSH)	192.168.1.43,192.168.1.43
11219	None	Nessus SYN scanner	192.168.1.1,192.168.1.1
10863	None	SSL Certificate Information	192.168.1.43
10107	None	HTTP Server Type and Version	192.168.1.43,192.168.1.43,192.168.1.1
```

To split data in two parts, invers arguments used with the --no-SOMETHING options. In this example, the Paris branch has the network address 10.32.0.0/24:
```
python3 butcher.py france.nessus  --network 10.32.0.0/24 --output-file paris-branch.txt  
python3 butcher.py france.nessus  --no-network 10.32.0.0/24 --output-file france-without-paris.txt
```

My preference is to save IP network data in excel for each owner that need a report:
```
$ python3 butcher.py examples/*.nessus --min-severity critical --network-excel examples/paris_branch_office.xlsx 
ID	severity	pluginName	IP
63145	Critical	USN-1638-3 : firefox regressions	192.168.1.43
63023	Critical	USN-1636-1 : thunderbird vulnerabilities	192.168.1.43
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.34,192.168.1.100
34477	Critical	MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (uncredentialed check)	192.168.1.34,192.168.1.100
22194	Critical	MS06-040: Vulnerability in Server Service Could Allow Remote Code Execution (921883) (uncredentialed check)	192.168.1.100
```

### Output formats
The butcher supports text, html and excel output formats. 
xml and json also exists for debugging.

#### Excel output 
The default text format is great when butchering up the data, but personally I prefer excel when you need the recipient to actually remediate the findings attached:
```
$ python3 butcher.py examples/example_scan.nessus --format excel --output-file examples/findings.xlsx
```
The spreadsheet created has two sheets; long format with each vulnerable host per line, compact format with each finding per line. The long format is usually better suited for remediation tracking: 

![image of excel long sheet format](/examples/excel_long.png) 

The compact sheet proves a better overview:
![image of excel compact sheet format](/examples/excel_compact.png) 

#### Text output 

Text output has two formats, default 'compact' format with a single finding per line and multiple hosts:

```
$ python3 butcher.py examples/example_scan.nessus --id 35362
ID	severity	pluginName	IP
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.34,192.168.1.100
```

Or  --long format with each vulnerability repeated with one line per host:
```
$ python3 butcher.py examples/example_scan.nessus --id 35362 --long
ID	severity	pluginName	IP
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.34
35362	Critical	MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)	192.168.1.100
```

#### HTML output 
The full output format is HTML. A table of findins is included, and a detailed section of each finding:
```
$ python3 butcher.py examples/example_scan.nessus --format html --output-file examples/findings.html
```

![image of html report format](/examples/html_report.png)

#### HTML template 
A custom html mustache HTML template can use used. As a starting point, use the mustache_template=  in butcher.py 
The json structure passed to the template engine can be observed with --format json option.  

### The butcher --help page

```
$ python3 butcher.py --help
Usage: butcher.py [OPTION]... <NESSUS_FILE>...

Compiles a report from one or more .nessus v2 files. Output can be text, html
or excel. Filters can be set to text matches, severity, hosts, IP-networks, or
nessus-IDs

Options:
  -h, --help            show this help message and exit
  -v, --verbose         
  -f FORMAT, --format=FORMAT
                        Optional output format, either of [text, html, excel]
                        (json, xml also exists for debugging) Defaults to text
  -l, --long            Text output can be either one line per IP (long) or
                        one line per finding (compact). Compact is the Default
  -o OUTPUT_FILE, --output-file=OUTPUT_FILE
                        Optional output file to save result as. Mandatory for
                        Excel output.
  -H HTML_TEMPLATE, --html-template=HTML_TEMPLATE
                        Optional Mustache HTML template to use. As a starting
                        point, see the mustache_template=  in this source
                        code.
  -D DUMP_XML_KEY, --dump-xml-key=DUMP_XML_KEY
                        Json dump values corresponding to supplied key, then
                        exit. Example key: preference
  -d, --dump-targets    Dump target addresses used in the scan, and exit

  Filter options, remove data that does not match criteria:
    -m MATCH, --match=MATCH
                        Only show results with a pluginName matching this
                        regex search term, for example 'ms17-010'
    -M NO_MATCH, --no-match=NO_MATCH
                        Only show results with a pluginName NOT matching this
                        regex search term.
    -k MATCH_KEY, --match-key=MATCH_KEY
                        Use this key for --match, defaults to 'pluginName'
    -s MIN_SEVERITY, --min-severity=MIN_SEVERITY
                        Either none, low, medium, high, critical or a number
                        from 0-4, where 0=None, 1=Low, 2=Medium, 3=High, and
                        4=Critical.
    -S MAX_SEVERITY, --max-severity=MAX_SEVERITY
                        Either none, low, medium, high, critical or a number
                        from 0-4, where 0=None, 1=Low, 2=Medium, 3=High, and
                        4=Critical.
    -t HOST, --host=HOST
                        Include host in the report. Use multiple times as
                        needed.
    -T NO_HOST, --no-host=NO_HOST
                        Exclude host from the report. Use multiple times as
                        needed.
    -n NETWORK, --network=NETWORK
                        Include only IPv4-network, with CIDR IP/mask syntax,
                        in the report. Use multiple times as needed. Default
                        mask is /32
    -N NO_NETWORK, --no-network=NO_NETWORK
                        Exclude IPv4-network, with CIDR IP/mask syntax, from
                        the report. Use multiple times as needed.  Default
                        mask is /32
    -r NETWORK_FILE, --network-file=NETWORK_FILE
                        Read CIRDs from file, one per line. Use multiple times
                        as needed.
    -R NO_NETWORK_FILE, --no-network-file=NO_NETWORK_FILE
                        Read CIRDs from file, one per line. Use multiple times
                        as needed.
    -e NETWORK_EXCEL, --network-excel=NETWORK_EXCEL
                        Read CIRDs from column A (or --column). Use multiple
                        times as needed.
    -C COLUMN, --column=COLUMN
                        Use this column in combination with --network-excel
                        Defaults to A
    -i ID, --id=ID      Include only finding with this nessus ID the report.
                        Use multiple times as needed.
    -I NO_ID, --no-id=NO_ID
                        Exclude findings with this nessus ID the report. Use
                        multiple times as needed.
    -b ID_FILE, --id-file=ID_FILE
                        Include only finding, one per line, with this nessus
                        ID the report. Use multiple times as needed.
    -B NO_ID_FILE, --no-id-file=NO_ID_FILE
                        Exclude findings, one per line, with this nessus ID
                        the report. Use multiple times as needed.

Open Source MIT License. Written by Christian Angerbjorn
```

## Prerequisites

The butcher is written in Python3. The following python3 packages are required:
- xmljson
- pymustache
- openpyxl (optional, but needed for excel support)

## License
Open Source MIT License


