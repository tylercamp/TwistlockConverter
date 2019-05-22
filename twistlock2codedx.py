#!/usr/bin/python
#
## Convert various Twistlock CSV files to Code Dx XML
#
import sys
import argparse
import csv
import xml.etree.ElementTree as ET
import datetime

## Decompose the Twistlock Vulnerability Hosts CSV
#
def twistlockVulnerabilityHosts(findings, filename) :
	print("|---- Detected Twistlock Vulnerability Hosts CSV file")
	with open(filename, 'r') as csvfile :
		reader = csv.DictReader(csvfile)
		
		# produce a Code Dx finding for each row of the file
		for row in reader :
			
			# create the "finding" element with a severity and type
			finding = ET.SubElement(findings, 'finding', { 'severity' : row['Severity'], 'type' : 'Network' })
			description = ET.SubElement(finding, 'description', { 'format' : 'plain-text' })
			description.text = row['Description']
			
			# network findings do not need a location.  But the ingestion routines in Code Dx do.
			# create a bogus location item
			ET.SubElement(finding, 'location', { 'type' : 'url', 'path' : '' })
			
			# create the tool item
			attr = { 'name' : 'Twistlock',
					 'category' : row['Type'],
					 'code' : row['Compliance ID']
					}
			tool = ET.SubElement(finding, 'tool', attr)
			
			# process in the CVE.  After the split, 1 is year, and 2 is sequence-number.  None of the incoming
			# records I have indicate when multiple CVEs are recorded.  I would assume by spaces in the name,
			# but I do not know, and have not programmed anything for it.  
			#
			# I simple mindedly assume a single CVE per record
			if '' != row['CVE ID'] :
				cves = ET.SubElement(finding, 'cves')
				cve = row['CVE ID'].split('-')
				cve = ET.SubElement(cves, 'cve', { 'year' : cve[1], 'sequence-number' : cve[2] })
			
			# create a "host" record
			host = ET.SubElement(finding, 'host')
			ET.SubElement(host, 'hostname').text = row['Hostname']
			ET.SubElement(host, 'operating-system').text = row['Distro']
			
			# create the metadata tag.  There may be some with no metadata
			metadata = ET.SubElement(finding, 'metadata')
			ET.SubElement(metadata, 'value', { 'key' : 'CVSS'}).text = row['CVSS']
			ET.SubElement(metadata, 'value', { 'key' : 'Package Name'}).text = row['Package Name'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Package Version'}).text = row['Package Version'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Package License'}).text = row['Package License'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Vendor Status'}).text = row['Vendor status'] 

## Decompose the Twistlock Vulnerability Images CSV
#
def twistlockVulnerabilityImages(findings, filename) :
	print("|---- Detected Twistlock Vulnerability Image CSV file")
	with open(filename, 'r') as csvfile :
		reader = csv.DictReader(csvfile)
		
		# produce a Code Dx finding for each row of the file
		for row in reader :
			
			# create the "finding" element with a severity and type
			finding = ET.SubElement(findings, 'finding', { 'severity' : row['Severity'], 'type' : 'Network' })
			description = ET.SubElement(finding, 'description', { 'format' : 'plain-text' })
			description.text = row['Description']
			
			# network findings do not need a location.  But the ingestion routines in Code Dx do.
			# create a bogus location item
			ET.SubElement(finding, 'location', { 'type' : 'url', 'path' : '' })
			
			# create the tool item
			attr = { 'name' : 'Twistlock',
					 'category' : row['Type'],
					 'code' : row['Compliance ID']
					}
			tool = ET.SubElement(finding, 'tool', attr)
			
			# process in the CVE.  After the split, 1 is year, and 2 is sequence-number.  None of the incoming
			# records I have indicate when multiple CVEs are recorded.  I would assume by spaces in the name,
			# but I do not know, and have not programmed anything for it.  
			#
			# I simple mindedly assume a single CVE per record
			if '' != row['CVE ID'] :
				cves = ET.SubElement(finding, 'cves')
				cve = row['CVE ID'].split('-')
				cve = ET.SubElement(cves, 'cve', { 'year' : cve[1], 'sequence-number' : cve[2] })
			
			# create a "host" record
			host = ET.SubElement(finding, 'host')
			ET.SubElement(host, 'hostname').text = row['Hostname']
			ET.SubElement(host, 'operating-system').text = row['Distro']
			
			# create the metadata tag.  There may be some with no metadata
			metadata = ET.SubElement(finding, 'metadata')
			ET.SubElement(metadata, 'value', { 'key' : 'CVSS'}).text = row['CVSS']
			ET.SubElement(metadata, 'value', { 'key' : 'Package Name'}).text = row['Package Name'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Package Version'}).text = row['Package Version'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Package License'}).text = row['Package License'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Vendor Status'}).text = row['Vendor Status'] 
			ET.SubElement(metadata, 'value', { 'key' : 'Risk Factors'}).text = row['Risk Factors'] 
	
## Determine the appropriate CSV file that is input and process it
#
def twistlockProcessFile(findings, filename) :
	
	# routine identification table.  We use the first field of the CSV to determine what 
	# should be executed.
	decoder = { 'Registry' : twistlockVulnerabilityImages,
				'Hostname' : twistlockVulnerabilityHosts
			  }
	executor = ''
	
	# read in the given CSV file.  We use the field names to determine what type of
	# Twistlock input file it is.
	with open(filename, 'r') as csvfile :
		# get the first line, and split it up by commas
		line = csvfile.readline().split(',')
		
		# Use the initial column name in the first line to calculate the appropriate file
		# decoder we wish to use.  Once that is set in 'executor', then we exit the
		# with clause to close the file, and process the entire file
		executor = decoder[line[0]]
	
	# call the executor to generate the information we need for Code Dx XML
	executor(findings, filename)
			

## Main Entry Point
#
def main(args) :
	
	# set up the finding list for Code Dx XML.
	findings = ET.Element('findings')
	
	# begin the process by ingesting the Twistlock file information for defects found
	# We need to determine which of the several CSV files we have here
	print("|- Loading Twistlock CSV files")
	for filename in args.input_files :
		print("|-- processing \"" + filename + "\"")
		twistlockProcessFile(findings, filename)
		
	# create the root information and tree
	report_xml = ET.Element('report', { 'date' : datetime.datetime.now().isoformat() })
	report_xml.append(findings)
	tree = ET.ElementTree(report_xml)
	tree.write(args.output, xml_declaration=True, encoding='utf-8', method='xml')
	

## Environment Entry Point
#
parser = argparse.ArgumentParser()
parser.add_argument("--output",   "-o", required=True,  help="Output Code Dx file")
parser.add_argument("--filter",   "-f", required=False, help="Filter results (currently unused)")
parser.add_argument("input_files",  nargs="*")
args = parser.parse_args()

if __name__ == "__main__" :
	main(args)
	
print(":---------- Done.")
