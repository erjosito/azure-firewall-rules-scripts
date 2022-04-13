################################################################################################
# Reads a fortigate config and exports commands to append the rules to an existing AzFW Policy
#
# Example:
# python ./read_fortigate_config.py --file ./fortigate_output.txt --format json
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
    if resolve_fqdns:
        # Since we have no access to corporate DNS, I will generate random IP addresses here if FQDNs are to be resolved
        return str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "/32"
    else:
        # If FQDN resolution is disabled, just return the same FQDN without resolving it
        return fqdn

# Get input arguments
parser = argparse.ArgumentParser(description='Get the latest flow logs in a storage account')
parser.add_argument('--file', dest='file_name', action='store',
                    help='you need to supply a file to analyze')
parser.add_argument('--format', dest='format', action='store',
                    default="azcli",
                    help='output format. Possible values: azcli (default), json, csv')
parser.add_argument('--min-rule', dest='min_rule', action='store', type=int,
                    default=1,
                    help='minimum rule number to include in the output. The default is 1 (start with 1st rule)')
parser.add_argument('--max-rule', dest='max_rule', action='store', type=int,
                    default=0,
                    help='Max rule number to include in the output. The default is 0 (do not use a maximum)')
parser.add_argument('--policy-name', dest='policy_name', action='store',
                    default="jsonpolicy",
                    help='Name for the Azure Firewall Policy. The default is "jsonpolicy"')
parser.add_argument('--rcg-name', dest='rcg_name', action='store',
                    default="fortinet",
                    help='Name for the Rule Collection Group. The default is "fortinet"')
parser.add_argument('--rcg-priority', dest='rcg_prio', action='store', type=int,
                    default=1000,
                    help='Priority for the generated Rule Collection Group. The default is 1000')
parser.add_argument('--rules-per-collection', dest='rules_per_collection', action='store', type=int,
                    default=10,
                    help='Number of rules per collection. The default is 10')
parser.add_argument('--verbose', dest='verbose', action='store_true',
                    default=False,
                    help='run in verbose mode (default: False)')
parser.add_argument('--dont-resolve-fqdns', dest='resolve_fqdns', action='store_false',
                    default=True,
                    help='Do not resolve FQDNs specified in the default ruleset (default: False)')
args = parser.parse_args()


file_name = args.file_name
verbose = args.verbose
resolve_fqdns = args.resolve_fqdns

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
                if m.groups()[0].lower() == "accept":
                    new_policy["action"] = "Allow"
                    if verbose:
                        print ("Adding Allow action")
                elif m.groups()[0].lower() == "drop":
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
    azfw_collection_group = args.rcg_name
    rcg_prio = args.rcg_prio
    print ("az group create -n {rg} -l {location}".format(rg=rg, location=location))
    print ("az network firewall policy create -n {azfw_policy_name} -g {rg}".format(azfw_policy_name=azfw_policy_name, rg=rg))
    print ("az network firewall policy rule-collection-group create -n {azfw_collection_group} --policy-name {azfw_policy_name} -g {rg} --priority {rcg_prio}".format(azfw_collection_group=azfw_collection_group, azfw_policy_name=azfw_policy_name, rg=rg, rcg_prio=rcg_prio))

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

elif args.format == "csv":
    # Print headers
    print ("Action, Rule name, Source IPs, Destination IPs, Protocols, Destination ports")
    # Process generated rules
    for rule in rules:
        # If the only protocol is ICMP, open up all ports
        if rule["protocols"] == ['icmp']:
            rule["dstports"] = ["'*'"]
        # Send the CSV lines to stdout, one line per src/dst combination
        for srcaddr in rule["srcaddr"]:
            for dstaddr in rule["dstaddr"]:
                #print("{action}, {name}, {srcip}, {dstip}, {prot}, {dstports}".format(name=rule["name"], srcip=' '.join(rule["srcaddr"]), dstip=' '.join(rule["dstaddr"]), dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"]))
                print("{action}, {name}, {srcip}, {dstip}, {prot}, {dstports}".format(name=rule["name"], srcip=srcaddr, dstip=dstaddr, dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"]))

elif args.format == "json":
    rg = 'fortinet'
    # api_version = "2020-11-01"
    api_version = "2021-02-01"
    location = 'westeurope'
    azfw_policy_name = args.policy_name
    azfw_collection_group = args.rcg_name
    rcg_prio = args.rcg_prio
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
            "apiVersion": "{api_version}",
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
            "apiVersion": "{api_version}",
            "name": "{azfw_policy_name}/{rcg_name}",
            "location": "[variables('location')]",
            "dependsOn": [
                "[resourceId('Microsoft.Network/firewallPolicies', '{azfw_policy_name}')]"
            ],
            "properties": {{
                "priority": {rcg_prio},
                "ruleCollections": ["""
    rc_header = """{{
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "name": "{name}",
                        "priority": {priority},
                        "action": {{
                            "type": "{action}"
                        }},
                        "rules": ["""
    rule_json = """                            {{
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
                            }}"""
    rc_footer = "                        ]}"
    rcg_footer = "] } }"

    print (template_header)
    print (policy_resource.format(azfw_policy_name=azfw_policy_name, api_version=api_version))
    print (rcg_header.format(azfw_policy_name=azfw_policy_name, rcg_name=azfw_collection_group, rcg_prio=rcg_prio, api_version=api_version))

    # Go over the rules
    priority = 1000
    rule_index = 1
    output_rule_index = 1
    collection_index = 1
    for rule in rules:
        if (rule_index >= args.min_rule) and (args.max_rule == 0 or rule_index <= args.max_rule):
            # If the only protocol is ICMP, open up all ports
            if rule["protocols"] == ['icmp']:
                rule["dstports"] = ['"*"']
            # Replace single quotes with double quotes (in case there is another '*' in the port list)
            rule['dstports'] = [str(item).replace("'", '"') for item in rule['dstports']]
            # Add a random suffix to the policy name to make sure it is unique
            random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
            rule["name"] = rule["name"] + "-" + random_suffix
            # If no action was detected, default to 'Allow'
            if rule["action"] == "":
                rule["action"] = "Allow"
            # Replace "Any" by a list of protocols (not sure if this is needed)
            if rule["protocols"] == ['Any']:
                rule["protocols"] = ['tcp', 'udp', 'icmp']
            # Replace "0.0.0.0/0" by "*" (not sure if this is needed)
            if rule["srcaddr"] == ['0.0.0.0/0'] or len(rule["srcaddr"]) == 0:
                rule["srcaddr"] = ['*']
            if rule["dstaddr"] == ['0.0.0.0/0'] or len(rule["dstaddr"]) == 0:
                rule["dstaddr"] = ['*']
            # Add quotes to the string elements to make them JSON-conform
            protocols = ['"' + item + '"' for item in rule["protocols"]]
            srcaddr = ['"' + item + '"' for item in rule["srcaddr"]]
            dstaddr = ['"' + item + '"' for item in rule["dstaddr"]]
            # If the first rule in a collection, print the collection header
            if (output_rule_index - 1) % args.rules_per_collection == 0:
                # If this is not the first collection, close the previous one
                if collection_index > 1:
                    print (rc_footer, ',')
                    priority += 10
                # Open the new collection
                random_collection_name = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
                print (rc_header.format(action=rule["action"], name=random_collection_name, priority=priority))
                collection_index += 1
            # If not the first rule in a collection, print a ',' to separate JSON objects
            else:
                print(',')
            # Output text
            try:
                print(rule_json.format(name=rule['name'], protocols=','.join(protocols), srcips=','.join(srcaddr), dstips=','.join(dstaddr), dstports=','.join(rule["dstports"])))
                # .format(name=rule["name"], srcip=' '.join(rule["srcaddr"]), dstip=' '.join(rule["dstaddr"]), dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"], azfw_policy_name=azfw_policy_name, priority=str(priority), rg=rg, rcg_name=azfw_collection_group))
            except Exception as e:
                print ("Error", str(e),"when printing rule", str(rule))
                pass
            # Increment counters
            output_rule_index += 1
        rule_index += 1

    # Close the JSON code
    print (rc_footer)
    print (rcg_footer)
    print (template_footer)
else:
    print ("Format", args.format, "not recognized!")