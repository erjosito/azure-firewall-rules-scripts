################################################################################################
# Reads a fortigate config and exports commands to append the rules to an existing AzFW Policy
#
# Example:
# python ./read_fortigate_config.py ./fortigate_output.txt
# az network firewall policy rule-collection-group collection rule add --name 1073742000 --source-addresses 10.15.5.20/32 10.15.5.40/32 10.15.5.30/32 10.15.5.50/32 10.5.22.140/32 10.5.22.145/32 10.5.22.150/32 10.5.22.155/32 --destination-addresses 10.10.40.21/32 10.10.40.22/32 --protocols tcp udp --destination-ports 288 33434
# az network firewall policy rule-collection-group collection rule add --name 1073742041 --source-addresses 10.15.5.40/32 10.15.5.50/32 10.5.22.140/32 10.5.22.150/32 --destination-addresses 10.10.40.21/32 10.10.40.22/32 --protocols tcp udp --destination-ports 22
#
#################################################################################################


import re
import sys
import random
import string
import argparse
import socket
from types import prepare_class


def netmask_to_cidr(m_netmask):
    try:
        ip = socket.gethostbyname(d)
        if ip:
            return ip
        else:
            return(sum([ bin(int(bits)).count("1") for bits in m_netmask.split(".") ]))
    except Exception:
        # Return a random IP
        return(sum([ bin(int(bits)).count("1") for bits in m_netmask.split(".") ]))

def resolve_name(fqdn):
    return str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "/32"

# Get input arguments
parser = argparse.ArgumentParser(description='Get the latest flow logs in a storage account')
parser.add_argument('--file', dest='file_name', action='store',
                    help='you need to supply a file to analyze')
parser.add_argument('--format', dest='format', action='store',
                    default="azcli",
                    help='output format. Possible values: azcli (default), json')
parser.add_argument('--verbose', dest='verbose', action='store_true',
                    default=False,
                    help='run in verbose mode (default: False)')
args = parser.parse_args()


file_name = args.file_name
verbose = args.verbose

# Initialize variables
random.seed()
rules = []
new_policy = None  # We start with an empty policy
supported_protocols = ['tcp', 'udp', 'icmp']

# Process rules line by line
with open(file_name) as fp:
    for cnt, line in enumerate(fp):
        m = re.match('\W+policy\s+(\w+)\s+', line)
        if m:
            policy_name = m.groups()[0]
            # print ("Policy name found:", policy_name)
            if new_policy:
                rules.append(new_policy)
            new_policy={"name": policy_name, "protocols": [], "dstports": [], "action": ""}
            if verbose:
                print ("Found new policy", policy_name)
                input ("Press Enter to continue...")
        else:
            # action
            m = re.match('action\W+(\w+)', line)
            if m:
                if m.groups()[0] == "accept":
                    new_policy["action"] = "Allow"
                    if verbose:
                        print ("Adding Allow action")
                elif m.groups()[0] == "drop":
                    new_policy["action"] = "Deny"
                    if verbose:
                        print ("Adding Deny action")
                else:
                    new_policy["action"] = m.groups()[0]
                    if verbose:
                        print ("Adding unknown action", m.groups()[0])
            # comments
            else:
                m = re.match('\W+comments\W+\"(.+)\"', line)
                if m:
                    new_policy["comments"] = m.groups()[0]
                    if verbose:
                        print ("Adding comments:", m.groups()[0])
                # dstaddr (comes before srcaddr)
                else:
                    m = re.match('dstaddr', line)
                    if m:
                        new_policy["dstaddr"] = []
                    # srcaddr
                    m = re.match('srcaddr', line)
                    if m:
                        new_policy["srcaddr"] = []
                    # If the line is "subnet: 10.0.0.0 255.0.0.0", see whether to put it in srcaddr or dstaddr, depending on whether srcaddr is already a key
                    m = re.match('\W+subnet\W+([\d\.]+)\W+([\d\.]+)', line)
                    if m:
                        # If srcaddr is already a key, it means we are now looking at it
                        # Otherwise it needs to be dstaddr
                        cidr = m.groups()[0] + '/' + str(netmask_to_cidr(m.groups()[1]))
                        if "srcaddr" in new_policy.keys():
                            new_policy["srcaddr"].append(cidr)
                            if verbose:
                                print ("Adding CIDR", cidr, "to source addresses")
                        else:
                            new_policy["dstaddr"].append(cidr)
                            if verbose:
                                print ("Adding CIDR", cidr, "to destination addresses")
                    # If the line is just a CIDR (10.0.0.0/8), see whether to put it in srcaddr or dstaddr, depending on whether srcaddr is already a key
                    m = re.match('(\d+\.\d+\.\d+\.\d+\/\d+)', line)
                    if m:
                        # If srcaddr is already a key, it means we are now looking at it
                        # Otherwise it needs to be dstaddr
                        cidr = m.groups()[0]
                        if "srcaddr" in new_policy.keys():
                            new_policy["srcaddr"].append(cidr)
                            if verbose:
                                print ("Adding CIDR", cidr, "to source addresses")
                        else:
                            new_policy["dstaddr"].append(cidr)
                            if verbose:
                                print ("Adding CIDR", cidr, "to destination addresses")
                    # The line could be an IP address range
                    m = re.match('(\d+\.\d+\.\d+\.\d+) - (\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        # If srcaddr is already a key, it means we are now looking at it
                        # Otherwise it needs to be dstaddr
                        ip1 = m.groups()[0]
                        ip2 = m.groups()[1]
                        ip_range = ip1 + "-" + ip2
                        if "srcaddr" in new_policy.keys():
                            new_policy["srcaddr"].append(ip_range)
                            if verbose:
                                print ("Adding IP range", ip_range, "to source addresses")
                        else:
                            new_policy["dstaddr"].append(ip_range)
                            if verbose:
                                print ("Adding IP range", ip_range, "to destination addresses")
                    # If the line is just a FQDN (alphanumeric or dots), see whether to put it in srcaddr or dstaddr, depending on whether srcaddr is already a key
                    # Since we have no access to schindler's DNS, I will generate random IP addresses here
                    m = re.match('^([\w|\.]+)$', line)
                    if m:
                        # If srcaddr is already a key, it means we are now looking at it
                        # Otherwise it needs to be dstaddr
                        fqdn = m.groups()[0]
                        cidr = resolve_name(fqdn)
                        if "srcaddr" in new_policy.keys():
                            new_policy["srcaddr"].append(cidr)
                            if verbose:
                                print ("Adding CIDR", cidr, "to source addresses instead of FQDN", fqdn)
                        else:
                            new_policy["dstaddr"].append(cidr)
                            if verbose:
                                print ("Adding CIDR", cidr, "to destination addresses instead of FQDN", fqdn)
                    # Port ranges
                    m = re.match('\W+(\w+)\-portrange\W+(\d+)', line)
                    if m:
                        protocol=m.groups()[0]
                        port=m.groups()[1]
                        if not protocol in new_policy["protocols"]:
                            new_policy["protocols"].append(protocol)
                            if verbose:
                                print ("Adding protocol", protocol)
                        if not port in new_policy["dstports"] and int(port) > 0:
                            new_policy["dstports"].append(port)
                            if verbose:
                                print ("Adding port", port)
                    # Protocol xyz (normally ICMP or IP)
                    m = re.match('protocol\W+(\w+)', line)
                    if m:
                        protocol=m.groups()[0].lower()
                        if protocol in supported_protocols:
                            if not protocol in new_policy["protocols"]:
                                new_policy["protocols"].append(protocol)
                                if verbose:
                                    print ("Adding protocol", protocol)
                        elif protocol == "ip":
                            new_policy["protocols"] = ['Any']
                            new_policy["dstports"] = ["'*'"]
                            if verbose:
                                print ("Adding protocol ANY and all ports")

                    # tcp|udp port
                    m = re.match('(tcp|udp)\W+(\w+)', line)
                    if m:
                        protocol=m.groups()[0]
                        port=m.groups()[1]
                        if protocol in supported_protocols:
                            if not protocol in new_policy["protocols"]:
                                new_policy["protocols"].append(protocol)
                                if verbose:
                                    print ("Adding protocol", protocol)
                            if not port in new_policy["dstports"] and int(port) > 0:
                                new_policy["dstports"].append(port)
                                if verbose:
                                    print ("Adding port", port)

# Add the last found policy
if new_policy:
    rules.append(new_policy)

# Az CLI init commands to create an AzFWPolicy, a collection group and a collection
if args.format == "azcli":
    rg = 'fortinet'
    location = 'westeurope'
    azfw_policy_name = 'mypolicy'
    azfw_collection_group = 'fortinet'
    print ("az group create -n {rg} -l {location}".format(rg=rg, location=location))
    print ("az network firewall policy create -n {azfw_policy_name} -g {rg}".format(azfw_policy_name=azfw_policy_name, rg=rg))
    print ("az network firewall policy rule-collection-group create -n {azfw_collection_group} --policy-name {azfw_policy_name} -g {rg} --priority 1000".format(azfw_collection_group=azfw_collection_group, azfw_policy_name=azfw_policy_name, rg=rg))

    # Process generated rules
    priority = 1000
    for rule in rules:
        priority += 10
        # If the only protocol is ICMP, open up all ports
        if rule["protocols"] == ['icmp']:
            rule["dstports"] = ["'*'"]
        # Add a random suffix to the policy name to make sure it is unique
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        rule["name"] = rule["name"] + "-" + random_suffix
        # Send the AzCLI command to stdout
        print("az network firewall policy rule-collection-group collection add-filter-collection --rule-type NetworkRule -o none", \
            "-g {rg} --rcg-name {rcg_name} --policy-name {azfw_policy_name} --action {action} --collection-priority {priority} --name {name} --rule-name {name} --source-addresses {srcip} --destination-addresses {dstip} --ip-protocols {prot} --destination-ports {dstports}" \
                .format(name=rule["name"], srcip=' '.join(rule["srcaddr"]), dstip=' '.join(rule["dstaddr"]), dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"], azfw_policy_name=azfw_policy_name, priority=str(priority), rg=rg, rcg_name=azfw_collection_group))

elif args.format == "json":
    rg = 'fortinet'
    location = 'westeurope'
    azfw_policy_name = 'jsonpolicy'
    azfw_collection_group = 'fortinet'
    template_header = """{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": { },
    "variables": {
        "location": "[resourceGroup().location]"
    },
    "resources": ["""
    template_footer="]}"
    policy_resource="""        {{
            "type": "Microsoft.Network/firewallPolicies",
            "apiVersion": "2020-11-01",
            "name": "{azfw_policy_name}",
            "location": "[variables('location')]",
            "properties": {{
                "sku": {{
                    "tier": "Standard"
                }},
                "threatIntelMode": "Alert"
            }}
        }},"""
    rcg_header = """        {{
            "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
            "apiVersion": "2020-11-01",
            "name": "{azfw_policy_name}/{rcg_name}",
            "location": "[variables('location')]",
            "dependsOn": [
                "[resourceId('Microsoft.Network/firewallPolicies', '{azfw_policy_name}'))]"
            ],
            "properties": {{
                "priority": 1000,
                "ruleCollections": ["""
    rc = """{{
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "action": {{
                            "type": "{action}"
                        }},
                        "rules": [
                            {{
                                "ruleType": "NetworkRule",
                                "name": "{name}",
                                "ipProtocols": [
                                    {protocols}
                                ],
                                "sourceAddresses": [
                                    {srcips}
                                ],
                                "sourceIpGroups": [],
                                "destinationAddresses": [
                                    {dstips}
                                ],
                                "destinationIpGroups": [],
                                "destinationFqdns": [],
                                "destinationPorts": [
                                    {dstports}
                                ]
                            }}
                        ],
                        "name": "{name}",
                        "priority": {priority}
                    }}"""
    rcg_footer = "] } }"

    print (template_header)
    print (policy_resource.format(azfw_policy_name=azfw_policy_name))
    print (rcg_header.format(azfw_policy_name=azfw_policy_name, rcg_name=azfw_collection_group))

    # Go over the rules
    priority = 1000
    for rule in rules:
        # If not the first rule, print a ',' to separate JSON objects
        if priority != 1000:
            print(',')
        priority += 10
        # If the only protocol is ICMP, open up all ports
        if rule["protocols"] == ['icmp']:
            rule["dstports"] = ['"*"']
        # Replace single quotes with double quotes (in case there is another '*' in the port list)
        rule['dstports'] = [str(item).replace("'", '"') for item in rule['dstports']]
        # Add a random suffix to the policy name to make sure it is unique
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        rule["name"] = rule["name"] + "-" + random_suffix
        # If no action was detected, default to 'Accept'
        if rule["action"] == "":
            rule["action"] = "Accept"
        # Send the JSON code to stdout
        protocols = ['"' + item + '"' for item in rule["protocols"]]
        srcaddr = ['"' + item + '"' for item in rule["srcaddr"]]
        dstaddr = ['"' + item + '"' for item in rule["dstaddr"]]
        try:
            print(rc.format(name=rule['name'], action=rule["action"], priority=priority, protocols=','.join(protocols), srcips=','.join(srcaddr), dstips=','.join(dstaddr), dstports=','.join(rule["dstports"])))
            # .format(name=rule["name"], srcip=' '.join(rule["srcaddr"]), dstip=' '.join(rule["dstaddr"]), dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"], azfw_policy_name=azfw_policy_name, priority=str(priority), rg=rg, rcg_name=azfw_collection_group))
        except Exception as e:
            print ("Error", str(e),"when printing rule", str(rule))
            pass

    # Close the JSON code
    print (rcg_footer)
    print (template_footer)
else:
    print ("Format", args.format, "not recognized!")