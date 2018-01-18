#!/usr/bin/python3

import sys
assert sys.version_info >= (3,0)

import re
import os.path
import optparse
import xml.etree.ElementTree
import operator
import ipaddress
from xmljson import badgerfish as bf
import pymustache
import json
from xml.dom.minidom import parseString

mustache_template = """
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Nessus report</title>
		<style>
@media screen {
			.sensitivity { float: left; background-color: #CC4E21; color: #ffffff; font-size: 16px; font-family:Tahoma; letter-spacing: 0px; border: 2px solid rgba(255, 255, 255, 0.5); border-radius: 10px; -moz-border-radius: 10px; overflow: hidden; padding: 2px 20px; text-align: center; text-shadow: 0px 0px 4px #737373; width: 60px; display: block; box-shadow:  0px 0px 4px 0px #A3A3A3; }
			.bottonCritical { background-color: FireBrick; }
			.buttonHigh { background-color: red; }
			.buttonMedium { background-color: DarkOrange; }
			.buttonLow { background-color: orange; }
			.buttonNone { background-color: gray; }
			.Critical { color: FireBrick; }
			.High { color: red; }
			.Medium { color: DarkOrange; }
			.Low { color: orange; }
			.None { color: gray; }
}
@media print {
			.sensitivity { float: left; color: #000000; font-size: 16px; font-family:Tahoma; overflow: hidden; text-align: center;  width: 30px; display: block; }
}
			.ReportItem {  padding-top 50px;  }
			.ReportItem div {white-space: pre-wrap; padding-bottom: 15px; }
			.desc::first-line {text-decoration: underline;}
			.pluginName {font-size: 120%;}
			.listItem {display:block; min-height:34px}
			.hosts {padding-left: 20px; padding-right: 20px; }
			hr {page-break-after: always;}
		</style>
	</head>
    <body>
        <h2>Nessus Report</h2>
        <div>Generated with the Butcher: https://github.com/angerbjorn/butcher</div>
		<h3>Table of findings:</h3>
		<p class="list">
			{{#severityList}}
			<div class="listItem" id="menu{{pluginID}}">
				<div class="sensitivity button{{risk_factor}}">{{risk_factor}}</div>
				<div class="pluginName"><span class="hosts">#{{count}}</span><a href="#item{{pluginID}}">{{pluginName}}</a></div>
			</div>
			{{/severityList}}
		</p>
		<hr>
		<h3>Details section:</h3>
		<p class="reports">
		
			<!--# ['@port', '@svc_name', '@protocol', '@severity', '@pluginID', '@pluginName', '@pluginFamily', 'agent', 'description', 'fname', 'plugin_modification_date', 'plugin_name', 'plugin_publication_date', 'plugin_type', 'risk_factor', 'script_version', 'solution', 'synopsis', 'plugin_output', 'IP', 'see_also', 'bid', 'cve', 'cvss3_base_score', 'cvss3_temporal_score', 'cvss3_temporal_vector', 'cvss3_vector', 'cvss_base_score', 'cvss_temporal_score', 'cvss_temporal_vector', 'cvss_vector', 'exploit_available', 'exploitability_ease', 'in_the_news', 'osvdb', 'vuln_publication_date', 'xref', 'cpe', 'patch_publication_date', 'cert', 'cwe', 'exploited_by_nessus', 'edb-id', 'icsa', 'cisco-bug-id', 'cisco-sa', 'iava', 'stig_severity', 'tra', 'zdi', 'canvas_package', 'exploit_framework_canvas', 'exploit_framework_core', 'attachment', 'exploit_framework_metasploit', 'metasploit_name', 'msft', 'unsupported_by_vendor', 'mskb', 'exploited_by_malware', 'mcafee-sb', 'cert-cc', 'iavb', 'vmsa', 'exploit_framework_exploithub', 'exploithub_sku', 'hp', 'rhsa', 'secunia', 'd2_elliot_name', 'exploit_framework_d2_elliot']-->
			{{#details}}
				{{#}}
				<div class="ReportItem" id="item{{@pluginID}}">
					<div class="pluginName" style=""><a href="#menu{{@pluginID}}"><span class="{{#risk_factor}}{{$}}{{/risk_factor}}">{{#risk_factor}}{{$}}{{/risk_factor}}</span> - {{@pluginName}}</a></div>

					{{#description}}<div class="description desc">Description:<br>{{$}}</div>{{/description}}
					{{#solution}}<div class="solution desc">Solution:<br>{{$}}</div>{{/solution}}
					{{#synopsis}}<div class="synopsis desc">Synopsis:<br>{{$}}</div>{{/synopsis}}
					<div class="plugin_output desc">Plugin output:<br>{{#plugin_output}}<br> &#11024; &#11024; &#11024; &#11024; &#11024; &#11024; Output for host {{IP}}&nbsp;:&nbsp;{{port}}&nbsp;({{svc_name}}) &#8628; &#8628; &#8628; &#8628; &#8628; &#8628; <br>{{output}}<br>{{/plugin_output}}</div>
					{{#see_also}}<div class="see_also desc">See also:<br>{{$}}</div>{{/see_also}}
					
					{{#exploit_available}}<div class="exploit_available">Exploit available: {{$}}</div>{{/exploit_available}}
					{{#exploit_framework_metasploit}}<div class="">exploit metasploit: {{$}}</div>{{/exploit_framework_metasploit}}
					{{#exploit_framework_core}}<div class="">exploit core: {{$}}</div>{{/exploit_framework_core}}
					{{#exploit_framework_exploithub}}<div class="">exploit exploithub: {{$}}</div>{{/exploit_framework_exploithub}}
					{{#exploit_framework_canvas}}<div class="">exploit canvas: {{$}}</div>{{/exploit_framework_canvas}}
					{{#exploit_framework_d2_elliot}}<div class="">exploit d2_elliot: {{$}}</div>{{/exploit_framework_d2_elliot}}
					{{#secunia}}<div class="">secunia:{{$}}</div>{{/secunia}}
					{{#attachment}}<div class="">attachment:{{$}}</div>{{/attachment}}
					{{#in_the_news}}<div class="">in_the_news:{{$}}</div>{{/in_the_news}}
					
					<div class="IPS">Affected hosts: {{#IP}}<span class="IP">{{IP}} : {{port}}&nbsp;({{svc_name}})</span>   {{/IP}}</div>
					<div>Plugin ID: {{@pluginID}}</div>
					<div class="bid ">bid: {{#bid}}{{$}} {{/bid}}</div>
					<div class="xref ">xref: {{#xref}}{{$}} {{/xref}}</div>
					<div class="cve ">cve: {{#cve}}{{$}} {{/cve}}</div>
					<div class="osvdb ">osvdb: {{#osvdb}}{{$}} {{/osvdb}}</div>

				</div>
				<hr>
				{{/}}
			{{/details}}
		</p>
    </body>
</html>
"""

def getValue( key, data ):
	if data.get(key):
		return data.get(key)
	elif data.find(key) != None :
		return data.find(key).text
	else:
		print('Unknown key error: "%s"\n\nSome common keys are:\n%s\nThe full nessus_v2 file format is documented in the nessus_v2_file_format.pdf paper.\nAlso, --format xml or json can be helpful to understand the data structure and keys used.' %(key, ' '.join(['port', 'svc_name', 'protocol', 'severity', 'pluginID', 'pluginName', 'pluginFamily', 'agent', 'description', 'fname', 'plugin_modification_date', 'plugin_name', 'plugin_publication_date', 'plugin_type', 'risk_factor', 'script_version', 'solution', 'synopsis', 'plugin_output', 'IP', 'see_also', 'bid', 'cve', 'cvss3_base_score', 'cvss3_temporal_score', 'cvss3_temporal_vector', 'cvss3_vector', 'cvss_base_score', 'cvss_temporal_score', 'cvss_temporal_vector', 'cvss_vector', 'exploit_available', 'exploitability_ease', 'in_the_news', 'osvdb', 'vuln_publication_date', 'xref', 'cpe', 'patch_publication_date', 'cert', 'cwe', 'exploited_by_nessus', 'edb-id', 'icsa', 'cisco-bug-id', 'cisco-sa', 'iava', 'stig_severity', 'tra', 'zdi', 'canvas_package', 'exploit_framework_canvas', 'exploit_framework_core', 'attachment', 'exploit_framework_metasploit', 'metasploit_name', 'msft', 'unsupported_by_vendor', 'mskb', 'exploited_by_malware', 'mcafee-sb', 'cert-cc', 'iavb', 'vmsa', 'exploit_framework_exploithub', 'exploithub_sku', 'hp', 'rhsa', 'secunia', 'd2_elliot_name', 'exploit_framework_d2_elliot'])), file=sys.stderr)
		exit()

if __name__ == "__main__":
	parser = optparse.OptionParser(usage="Usage: %prog [OPTION]... <NESSUS_FILE>...", description="Compiles a report from one or more .nessus v2 files. Output can be text, html or excel. Filters can be set to text matches, severity, hosts, IP-networks, or nessus-IDs", epilog='Open Source MIT License. Written by Christian Angerbjorn')
	parser.add_option("-v", "--verbose", action="store_true")

	parser.add_option("-f", "--format",  default='text', help='Optional output format, either of [text, html, excel] (json, xml also exists for debugging) Defaults to text')
	parser.add_option("-l", "--long", action="store_true", help="Text output can be either one line per IP (long) or one line per finding (compact). Compact is the Default")
	parser.add_option("-o", "--output-file", help="Optional output file to save result as. Mandatory for Excel output.")
	parser.add_option("-H", "--html-template", help="Optional Mustache HTML template to use. As a starting point, see the mustache_template=  in this source code.")

	parser.add_option("-D", "--dump-xml-key", help='Json dump values corresponding to supplied key, then exit. Example key: preference')
	parser.add_option("-d", "--dump-targets",  action="store_true", help='Dump target addresses used in the scan, and exit')

	group = optparse.OptionGroup(parser, 'Filter options, remove data that does not match criteria')
	group.add_option("-m", "--match", help="Only show results with a pluginName matching this regex search term, for example 'ms17-010'")
	group.add_option("-M", "--no-match", help="Only show results with a pluginName NOT matching this regex search term.")
	group.add_option("-k", "--match-key", default='pluginName', help="Use this key for --match, defaults to 'pluginName'")
	group.add_option("-s", "--min-severity", default='0', help="Either none, low, medium, high, critical or a number from 0-4, where 0=None, 1=Low, 2=Medium, 3=High, and 4=Critical.")
	group.add_option("-S", "--max-severity", default='4', help="Either none, low, medium, high, critical or a number from 0-4, where 0=None, 1=Low, 2=Medium, 3=High, and 4=Critical.")
	group.add_option("-t", "--host", action="append", default=[], help="Include host in the report. Use multiple times as needed.")
	group.add_option("-T", "--no-host", action="append", default=[], help="Exclude host from the report. Use multiple times as needed.")
	group.add_option("-n", "--network", action="append", default=[], help="Include only IPv4-network, with CIDR IP/mask syntax, in the report. Use multiple times as needed. Default mask is /32")
	group.add_option("-N", "--no-network", action="append", default=[], help="Exclude IPv4-network, with CIDR IP/mask syntax, from the report. Use multiple times as needed.  Default mask is /32")
	group.add_option("-r", "--network-file", action="append", default=[], help="Read CIRDs from file, one per line. Use multiple times as needed.")
	group.add_option("-R", "--no-network-file", action="append", default=[], help="Read CIRDs from file, one per line. Use multiple times as needed.")
	group.add_option("-e", "--network-excel", action="append", default=[], help="Read CIRDs from column A (or --column). Use multiple times as needed.")
	group.add_option("-C", "--column", action="append", default='A', help="Use this column in combination with --network-excel Defaults to A")
	group.add_option("-i", "--id", action="append", default=[], help="Include only finding with this nessus ID the report. Use multiple times as needed.")
	group.add_option("-I", "--no-id", action="append", default=[], help="Exclude findings with this nessus ID the report. Use multiple times as needed.")
	group.add_option("-b", "--id-file", action="append", default=[], help="Include only finding, one per line, with this nessus ID the report. Use multiple times as needed.")
	group.add_option("-B", "--no-id-file", action="append", default=[], help="Exclude findings, one per line, with this nessus ID the report. Use multiple times as needed.")
	parser.add_option_group(group)
	(ops, args) = parser.parse_args()

	if len(args) == 0:
		parser.error("At least one .nessus is required!")

	severity = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
	# min
	if ops.min_severity:
		if ops.min_severity.isdigit():
			ops.min_severity = int(ops.min_severity)
		else:
			try:
				ops.min_severity = severity[ops.min_severity.lower()]
			except: 
				parser.error('--min-severity has to be either a number from 0-4 or none, low, medium, high, critical')
	# max
	if ops.max_severity:
		if ops.max_severity.isdigit():
			ops.max_severity = int(ops.max_severity)
		else:
			try:
				ops.max_severity = severity[ops.max_severity.lower()]
			except:
				parser.error('--max-severity has to be either a number from 0-4 or none, low, medium, high, critical')

	if ops.format and ops.format not in ['text', 'html', 'excel', 'json', 'xml']:
		parser.error("Format can only be one of [text, html, excel, json, xml]")
		
	if ops.format == 'excel' and not ops.output_file:
		parser.error('Excel output require an --output-file')
	
		
	# read in/exclude nessus IDs from file 
	for nf in ops.id_file:
		with open( nf, 'r' ) as f: 
			for n in f.read().splitlines():
				ops.id.append( n )
	for nf in ops.no_id_file:
		with open( nf, 'r' ) as f: 
			for n in f.read().splitlines():
				ops.no_id.append( n )

	# read in/exclude networks from file 
	for nf in ops.network_file:
		with open( nf, 'r' ) as f: 
			for n in f.read().splitlines():
				ops.network.append( n )
	for nf in ops.no_network_file:
		with open( nf, 'r' ) as f: 
			for n in f.read().splitlines():
				ops.no-network.append( n )

	# read include networks from excel 
	if ops.network_excel or ops.format == 'excel':
		from openpyxl import load_workbook, Workbook

	for ef in ops.network_excel:
		wb = load_workbook( filename=ef )
		for i, row in enumerate(wb.active.iter_rows()):
			ops.network.append( row[ ord(ops.column.upper())-65 ].value )

	if ops.verbose:
		for k in ops.id:
			print("Include nessus ID: %s" %k, file=sys.stderr)
		for k in ops.no_id:
			print("Exclude nessus ID: %s" %k, file=sys.stderr)
			
			
	includeHosts = set() # list of IP-addresses or hostnames. (hence not ipaddress.overlap used...)
	excludeHosts = set()

	reg = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	for n in ops.network:
		matchObj = re.search( reg, n )
		if matchObj and matchObj.group(1):
			if ops.verbose:
				print("Including network %s" %n, file=sys.stderr) 
			for addr in ipaddress.ip_network(n):
				includeHosts.add( str(addr) )
		else:
			print("'%s' does not appear to be a network?" %n, file=sys.stderr)
	for n in ops.no_network:
		matchObj = re.search( reg, n )
		if matchObj and matchObj.group(1):
			if ops.verbose:
				print("Excluding network %s" %n, file=sys.stderr) 
			for addr in ipaddress.ip_network(n):
				excludeHosts.add( str(addr) )
		else:
			print("'%s' does not appear to be a network?" %n, file=sys.stderr)

	for h in ops.host:
		includeHosts.add( h )
		if ops.verbose:
			print("Including host %s" % h, file=sys.stderr)
	for h in ops.no_host:
		excludeHosts.add( h )
		if ops.verbose:
			print("Excluding host %s" % h, file=sys.stderr)

	# dict of pluginId and finding data 
	compact = {} # {"pluginID, meaning 12345":{findings-data}}
	# list of some findidng data, so that we can sort in order or severity 
	findings = [] # [{findings-data}, {findings-data}, {findings-data}]
	long_findings = [] # [{findings-data}, {findings-data}, {findings-data}]


	if ops.dump_xml_key or ops.dump_targets:
		for nessus_file in args:
			with open( nessus_file, 'r' ) as f:
				print( "Dumping data from: ", nessus_file, " - - - - - ") 
				if ops.dump_xml_key:
					for policy in xml.etree.ElementTree.parse(f).getroot().iter(ops.dump_xml_key):			
						print( json.dumps( bf.data(policy), indent=4))
				if ops.dump_targets:
					for policy in xml.etree.ElementTree.parse(f).getroot().iter("preference"):
						if policy.find("name").text == "TARGET":
							print(  policy.find("value").text )
		exit()

	for nessus_file in args:
		with open( nessus_file, 'r' ) as f:
			if ops.verbose:
				print( "Reading data from %s " %nessus_file, file=sys.stderr) 
			try: 
				for report in xml.etree.ElementTree.parse(f).getroot().iter('Report'):			
					for rh in report.findall("ReportHost"):
						IP = rh.get("name")
						# filter include or exclude this host? 
						if includeHosts == set() or IP in includeHosts:
							if excludeHosts == set() or IP not in excludeHosts:
								for ri in rh.findall("ReportItem"):
									# filter Severity 
									if ops.min_severity <=  int(ri.get("severity")):
										if ops.max_severity >= int(ri.get("severity")):
											# filter ID
											if ops.id == [] or str(ri.get("pluginID")) in ops.id:
												if ops.no_id == [] or ri.get("pluginID") not in ops.no_id:
													if not ops.match or (ops.match and re.search( ops.match, getValue(ops.match_key, ri ), re.IGNORECASE)):
														if not ops.no_match or (ops.no_match and not re.search(ops.no_match, getValue(ops.match_key, ri), re.IGNORECASE)):
															# filter done!
															if ops.format in ['text', 'excel']:
																# one line per IP output
																long_findings.append( {"pluginID":ri.get("pluginID"), "risk_factor":ri.find("risk_factor").text, "pluginName":ri.get("pluginName"), "IP":IP , "severity":int(ri.get("severity"))})

																# compact output, meaning one file per finding
																if not ri.get("pluginID") in compact:
																	# new
																	findings.append( {"pluginID":ri.get("pluginID"), "severity":int(ri.get("severity")), "risk_factor":ri.find("risk_factor").text, "pluginName":ri.get("pluginName")})
																	compact[ri.get("pluginID")] = {"pluginID":ri.get("pluginID"), "risk_factor":ri.find("risk_factor").text, "pluginName":ri.get("pluginName"), "IP":[IP], "severity":int(ri.get("severity"))}
																else:
																	# exists
																	compact[ri.get("pluginID")]["IP"].append( IP )

															# html output
															elif ops.format in ['html', 'json']:
																if not ri.get("pluginID") in compact:
																	# first finding
																	findings.append( {"pluginID":ri.get("pluginID"), "severity":int(ri.get("severity")), "risk_factor":ri.find("risk_factor").text, "pluginName":ri.get("pluginName"), 'count':0})
																	compact[ri.get("pluginID")] = bf.data(ri)
																	compact[ri.get("pluginID")]["ReportItem"]["IP"] = [{"IP":IP, "port": ri.get("port"), "svc_name": ri.get("svc_name")}]
																else:
																	# exists
																	compact[ri.get("pluginID")]["ReportItem"]["IP"].append( {"IP":IP, "port": ri.get("port"), "svc_name": ri.get("svc_name")} )

																if ri.find("plugin_output") != None and ri.find("plugin_output").text :
																	if (not "plugin_output" in compact[ri.get("pluginID")]["ReportItem"]) or type(compact[ri.get("pluginID")]["ReportItem"]["plugin_output"]) != list  :
																		# first plugin output for this finding
																		compact[ri.get("pluginID")]["ReportItem"]["plugin_output"] = [{"output":ri.find("plugin_output").text, "IP":IP, "port": ri.get("port"), "svc_name": ri.get("svc_name")}]
																	else:
																		# output exists, add data to that
																		compact[ri.get("pluginID")]["ReportItem"]["plugin_output"].append( {"output":ri.find("plugin_output").text, "IP":IP, "port": ri.get("port"), "svc_name": ri.get("svc_name")} )
																	# print( json.dumps(compact[ri.get("pluginID")]["ReportItem"]["plugin_output"] , indent=4))

															elif ops.format == 'xml':
																findings.append( ri )


			except xml.etree.ElementTree.ParseError as err:
				print("Failed to parse XML data in file %s Error: %s" %(nessus_file, err),  file=sys.stderr) 
				print("Input file most likely not a .nessus file?",  file=sys.stderr) 
				exit()

	if ops.format != 'xml':
		# sort data
		findings.sort(key=operator.itemgetter("severity", "pluginID"), reverse=True)
		long_findings.sort(key=operator.itemgetter("severity", "pluginID"), reverse=True)

	if ops.format in ('html', 'text', 'json', 'xml'):
		outFile = None
		if ops.output_file:
			outFile = open( ops.output_file, 'w' )
		
	# text output
	if ops.format == 'xml':
		# only add newline when not alredy there 
		nl = '\n'
		if ord(xml.etree.ElementTree.tostring( findings[0] )[-1:]) in [10,13]: # check last digit is 10 or 13. str compare failes on this bin object...
			nl = ''
		for f in findings:
			print( parseString( xml.etree.ElementTree.tostring( f )).toprettyxml(newl=nl), file=outFile)

	# text output
	elif ops.format == 'text':
		print ("ID","severity","pluginName","IP", sep="\t", file=outFile)
		if not ops.long:
			for f in findings:
				k = f.get("pluginID")
				print( compact[k].get("pluginID"), compact[k].get("risk_factor"), compact[k].get("pluginName"), ",".join(compact[k].get("IP")), sep="\t", file=outFile) 
		else:
			for f in long_findings:
				print( f.get("pluginID"), f.get("risk_factor"), f.get("pluginName"), f.get("IP"), sep="\t", file=outFile) 


		# html output
	elif ops.format in ['html', 'json']:
		# custom template
		if ops.html_template:
			with open(ops.html_template, "r") as t:
				mustache_template = t.read()
			
		details = []
		for k in compact.keys():
			details.append( compact[ k ]["ReportItem"] )

		# add finding count to Table of findings:
		for f in findings:
			f['count'] = len( compact[f["pluginID"]]["ReportItem"]["IP"])

		# render
		jReports = {"details":details, "severityList":findings }
		if ops.format == 'json':
			print( json.dumps(jReports, indent=4), file=outFile)
		else:
			print( pymustache.render( mustache_template, jReports ), file=outFile)
	
	# excel output 
	elif ops.format == 'excel':
		excel_wb = None
		excel_long = None
		excel_compact = None
		
		# add to existing book 
		if os.path.isfile( ops.output_file ):
			excel_wb = load_workbook( filename = ops.output_file)
			excel_long = excel_wb.create_sheet("long")
		else:
			# new book 
			excel_wb = Workbook()
			excel_long = excel_wb.active
			excel_long.title = "long"
		excel_compact = excel_wb.create_sheet("Compact")
		
		excel_compact.append( ("ID","Severity","pluginName","IP" ))
		excel_long.append(( "ID","Severity","pluginName","IP", "Remediation status", "Owner" ))  

		for f in findings:
			k = f.get("pluginID")
			excel_compact.append( ( int(compact[k].get("pluginID")), compact[k].get("risk_factor"), compact[k].get("pluginName"), ",".join(compact[k].get("IP")) ) ) 

		for f in long_findings:
			excel_long.append(( int(f.get("pluginID")), f.get("risk_factor"), f.get("pluginName"), f.get("IP"))) 
	
		excel_wb.save( ops.output_file )
		
	
		
		