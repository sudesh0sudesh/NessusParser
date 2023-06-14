import argparse
import csv
import re
from xml.etree import ElementTree as ET

def parse_nessus_file(nessus_file):
    with open(nessus_file, 'r') as file:
        return ET.parse(file)

def get_affected_hosts(nessus_tree, vulnerability_name):
    affected_hosts = {}
    root = nessus_tree.getroot()
    report_hosts = root.findall(".//ReportHost")
    for report_host in report_hosts:
        report_items = report_host.findall(".//ReportItem")
        for item in report_items:
            if vulnerability_name in item.attrib['pluginName']:
                cvss_node = item.find(".//cvss_base_score")
                if cvss_node is not None:
                    cvss_score = float(cvss_node.text)
                    if cvss_score > 0:
                        hostname = report_host.attrib.get('name', '')
                        host_info = affected_hosts.get(hostname, {})
                        port = item.attrib.get('port', '')
                        protocol = item.attrib.get('protocol', '')
                        if port not in host_info:
                            host_info[port] = protocol
                        affected_hosts[hostname] = host_info
    return affected_hosts

def get_unique_vulnerabilities(nessus_tree):
    vulnerabilities = set()
    root = nessus_tree.getroot()
    report_hosts = root.findall(".//ReportHost")
    for report_host in report_hosts:
        report_items = report_host.findall(".//ReportItem")
        for item in report_items:
            if item.attrib['pluginName'] not in vulnerabilities:
                 cvss_node = item.find(".//cvss_base_score")
                 if cvss_node is not None:
                    cvss_score = float(cvss_node.text)
                    if cvss_score > 0:
                        vulnerabilities.add(item.attrib['pluginName'])
                      
    return vulnerabilities

def write_to_csv(affected_hosts, vulnerability_name, csv_file):
    fieldnames = ['Host', 'Ports', 'vulnerability_name']
    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'Host': vulnerability_name})
        writer.writeheader()
        for hostname, host_info in affected_hosts.items():
            ports = ', '.join([f'{port}/{protocol}' for port, protocol in host_info.items()])
            writer.writerow({'Host': hostname, 'Ports': ports, 'vulnerability_name': vulnerability_name})

# Main code
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse Nessus file and generate CSV file of affected hosts.')
    parser.add_argument('nessus_file', help='Path to the Nessus file')
    args = parser.parse_args()

    nessus_file = args.nessus_file
    nessus_tree = parse_nessus_file(nessus_file)
    #csv_file = input("Enter the path for the output CSV file: ")
    vulnerbilities=get_unique_vulnerabilities(nessus_tree)
    for vulnerability_name in vulnerbilities:
        affected_hosts = get_affected_hosts(nessus_tree, vulnerability_name)
        filename = re.sub(r'[\\ \/*?:"<>|]',"",vulnerability_name)
        write_to_csv(affected_hosts, vulnerability_name, filename+'.csv')
    print("CSV file generated successfully.")

        

   
        

    print("Exiting the program.")
