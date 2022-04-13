import requests
import argparse
import json

# Helper functions

# True if any of the urls contained in the URL list contains a wildcard ('*')
def urls_contain_wildcard(urls):
    for url in urls:
        if '*' in url:
            return True
    return False

# Check whether URLs are correct:
#   - Wildcard needs to be in the beginning of the string, not valid in the middle
def verify_urls(urls):
    corrected_urls = []
    for url in urls:
        if url.find('*') <= 0:
            corrected_urls.append(url)
        else:
            corrected_urls.append(url[url.find('*'):])
            if args.verbose:
                print("WARNING: URL {0} reduced to {1}".format(url, url[url.find('*'):]))
    return corrected_urls

# Arguments
parser = argparse.ArgumentParser(description='Update a checklist spreadsheet with JSON-formated Azure Resource Graph results')
parser.add_argument('--policy-name', dest='policy_name', action='store',
                    default="o365policy",
                    help='Name for the Azure Firewall Policy. The default is "o365policy"')
parser.add_argument('--format', dest='format', action='store',
                    default="json",
                    help='output format. Possible values: json, none')
parser.add_argument('--verbose', dest='verbose', action='store_true',
                    default=False,
                    help='run in verbose mode (default: False)')
args = parser.parse_args()

# Variables
o365_endpoints_url = 'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7'
app_rules = []
net_rules = []
rcg_prio = "10000"
rc_app_name = 'o365app'
rc_app_prio = "11000"
rc_net_name = 'o365net'
rc_net_prio = "10900"

# Get O365 endpoints
response = requests.get(o365_endpoints_url)
if response.status_code == 200:
    if args.verbose:
        print ("DEBUG: File {0} downloaded successfully".format(o365_endpoints_url))
    try:
        # Deserialize JSON to object variable
        o365_data = json.loads(response.text)
    except Exception as e:
        print("Error deserializing JSON content: {0}".format(str(e)))
        sys.exit(1)

# Go through the rules
cnt_apprules = 0
cnt_netrules_ip = 0
cnt_netrules_fqdn = 0
cnt_endpoints = 0
for endpoint in o365_data:
    cnt_endpoints += 1
    # App Rule
    if ('tcpPorts' in endpoint) and ((endpoint['tcpPorts'] == "80,443") or (endpoint['tcpPorts'] == "443")):
        cnt_apprules += 1
        if 'urls' in endpoint:
            new_rule = {
                'name': 'id' + str(endpoint['id']),
                'action': 'allow',
                'dst_fqdn': verify_urls(endpoint['urls']),
                'dst_ports': str(endpoint['tcpPorts']).split(",")
            }
            app_rules.append(new_rule)
        else:
            print('ERROR Endpoint ID {0} is web-based but does not have URLs'.format(endpoint['id']))
    # IP-based Net Rule
    elif (('urls' in endpoint) and urls_contain_wildcard(endpoint['urls'])) or not ('urls' in endpoint):
        cnt_netrules_ip += 1
        if ('ips' in endpoint) and (('tcpPorts' in endpoint) or ('udpPorts' in endpoint)):
            new_rule = {
                'name': 'id' + str(endpoint['id']),
                'action': 'allow',
                'dst_ip': endpoint['ips'],
                'dst_fqdn': ''
            }
            if 'tcpPorts' in endpoint:
                new_rule['protocols'] = [ 'tcp' ]
                new_rule['dst_ports'] = str(endpoint['tcpPorts']).split(",")
            else:
                new_rule['protocols'] = [ 'udp' ]
                new_rule['dst_ports'] = str(endpoint['udpPorts']).split(",")
            net_rules.append(new_rule)
            # Watch out for UDP+TCP!
            if ('udpPorts' in endpoint) and ('tcpPorts' in endpoint):
                print("WARNING: Endpoint ID {0} has both TCP and UDP ports!".format(endpoint['id']))
        else:
            if not ('ips' in endpoint):
                print('ERROR: Endpoint ID {0} is IP-based with wildcards, but does not have ips'.format(endpoint['id']))
            if not ('udpPorts' in endpoint):
                print('ERROR: Endpoint ID {0} is IP-based with wildcards, but does not have udpPorts'.format(endpoint['id']))
            if args.verbose:
                print('DEBUG: endpoint:', str(endpoint))
    # FQDN-based Net Rule
    else:
        cnt_netrules_fqdn += 1
        if ('urls' in endpoint) and (('tcpPorts' in endpoint) or ('udpPorts' in endpoint)):
            new_rule = {
                'name': 'id' + str(endpoint['id']),
                'action': 'allow',
                'dst_ip': '',
                'dst_fqdn': endpoint['urls'],
            }
            if 'tcpPorts' in endpoint:
                new_rule['protocols'] = [ 'tcp' ]
                new_rule['dst_ports'] = str(endpoint['tcpPorts']).split(",")
            else:
                new_rule['protocols'] = [ 'udp' ]
                new_rule['dst_ports'] = str(endpoint['udpPorts']).split(",")
            net_rules.append(new_rule)
            # Watch out for UDP+TCP!
            if ('udpPorts' in endpoint) and ('tcpPorts' in endpoint):
                print("WARNING: Endpoint ID {0} has both TCP and UDP ports!".format(endpoint['id']))
        else:
            if not ('urls' in endpoint):
                print('ERROR: Endpoint ID {0} is IP-based with wildcards, but does not have urls'.format(endpoint['id']))
            if not ('udpPorts' in endpoint):
                print('ERROR: Endpoint ID {0} is IP-based with wildcards, but does not have udpPorts'.format(endpoint['id']))
            if args.verbose:
                print('DEBUG: endpoint:', str(endpoint))

##########
# Output #
##########

if args.format == "json":
    # api_version = "2020-11-01"
    api_version = "2021-02-01"
    azfw_policy_name = args.policy_name
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
                "dnsSettings": {{
                    "servers": [],
                    "enableProxy": true
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
    rc_header = """                  {{
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "name": "{name}",
                        "priority": {priority},
                        "action": {{
                            "type": "{action}"
                        }},
                        "rules": ["""
    net_rule_json = """                            {{
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
                                "destinationFqdns": [
                                    {dstfqdns}
                                ],
                                "destinationPorts": [
                                    {dstports}
                                ]
                            }}"""
    app_rule_json = """                            {{
                                "ruleType": "ApplicationRule",
                                "name": "{name}",
                                "terminateTLS": false,
                                "protocols": [
                                    {protocols}
                                ],
                                "sourceAddresses": [
                                    {srcips}
                                ],
                                "fqdnTags": [],
                                "webCategories": [],
                                "targetUrls": [],
                                "destinationAddresses": [],
                                "targetFqdns": [
                                    {dstfqdns}
                                ]
                            }}"""
    protocol_https_only = """{ "protocolType": "Https", "port": 443 }"""
    protocol_https_and_http = """{ "protocolType": "Http", "port": 80 }, { "protocolType": "Https", "port": 443 }"""
    rc_footer = "                        ]}"
    rcg_footer = "      ] } }"

    print (template_header)
    print (policy_resource.format(azfw_policy_name=azfw_policy_name, api_version=api_version))

    # RCG
    print (rcg_header.format(azfw_policy_name=azfw_policy_name, rcg_name=rc_net_name, rcg_prio=rc_net_prio, api_version=api_version))

    # Net rules
    output_net_rule_index = 1
    for rule in net_rules:
        # Add quotes to the string elements to make them JSON-conform
        protocols = ['"' + item + '"' for item in rule["protocols"]]
        srcaddr = [ '"*"' ]
        dstaddr = ['"' + item + '"' for item in rule["dst_ip"]]
        dstfqdn = ['"' + item + '"' for item in rule["dst_fqdn"]]
        # If the first rule in a collection, print the collection header
        if output_net_rule_index == 1:
            # Open the new collection
            print (rc_header.format(action=rule["action"], name=rc_net_name, priority=rc_net_prio))
        # If not the first rule in a collection, print a ',' to separate JSON objects
        else:
            print('                            ,')
        # Output text
        try:
            print(net_rule_json.format(name=rule['name'], protocols=','.join(protocols), srcips=','.join(srcaddr), dstips=','.join(dstaddr), dstfqdns=','.join(dstfqdn), dstports=','.join(rule["dst_ports"])))
            # .format(name=rule["name"], srcip=' '.join(rule["srcaddr"]), dstip=' '.join(rule["dstaddr"]), dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"], azfw_policy_name=azfw_policy_name, priority=str(priority), rg=rg, rcg_name=azfw_collection_group))
        except Exception as e:
            print ("Error", str(e),"when printing rule", str(rule))
            pass
        # Increment counters
        output_net_rule_index += 1
    print (rc_footer, ',')

    # App rules
    output_app_rule_index = 1
    for rule in app_rules:
        # Add quotes to the string elements to make them JSON-conform
        srcaddr = [ '"*"' ]
        dstfqdn = ['"' + item + '"' for item in rule["dst_fqdn"]]
        if '80' in rule['dst_ports']:
            protocols = protocol_https_and_http
        else:
            protocols = protocol_https_only
        # If the first rule in a collection, print the collection header
        if output_app_rule_index == 1:
            # Open the new collection
            print (rc_header.format(action=rule["action"], name=rc_app_name, priority=rc_app_prio))
        # If not the first rule in a collection, print a ',' to separate JSON objects
        else:
            print('                            ,')
        # Output text
        try:
            print(app_rule_json.format(name=rule['name'], srcips=','.join(srcaddr), dstips=','.join(dstaddr), dstfqdns=','.join(dstfqdn), protocols=protocols))
            # .format(name=rule["name"], srcip=' '.join(rule["srcaddr"]), dstip=' '.join(rule["dstaddr"]), dstports=' '.join(rule["dstports"]), prot=' '.join(rule["protocols"]), action=new_policy["action"], azfw_policy_name=azfw_policy_name, priority=str(priority), rg=rg, rcg_name=azfw_collection_group))
        except Exception as e:
            print ("Error", str(e),"when printing rule", str(rule))
            pass
        # Increment counters
        output_app_rule_index += 1
    print (rc_footer)

    # Close the JSON code
    print (rcg_footer)
    print (template_footer)
elif args.format == "none":
    if args.verbose:
        print('DEBUG: {0} endpoints analized: {1} app rules, {2} FQDN-based net rules and {3} IP-based net rules'.format(str(cnt_endpoints), str(cnt_apprules), str(cnt_netrules_fqdn), str(cnt_netrules_ip)))
        # print('DEBUG: Net rules:', str(net_rules))
        # print('DEBUG: App rules:', str(app_rules))
else:
    print ("Format", args.format, "not recognized!")