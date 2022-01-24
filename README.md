# Some tools to work with Azure Firewall Rules

The purpose of this repo is providing some examples that illustrate different techniques to work with Azure Firewall Rules. At this time two use cases are included:

- Processing a text file with rules with a different syntax and output Azure Firewall syntax (ARM JSON or CLI)
- Analyzing an existing Azure Policy and look for potential optimization through the usage of IP Groups to reduce the consumption of IP objects

## Disclaimer

These scripts are shared as they are, and they are not supported by Microsoft in any way, shape or form. Be sure to test and validate the output of these scripts. If you find any issue with them, I would be thankful if you opened an issue in this repo.

## Importing Azure Firewall rules from a Fortigate configuration

As source configuration the example in this repo uses a configuration extracted from a Fortigate firewall. The goal of [read_fortigate_config.py](./read_fortigate_config.py) is not focusing on converting Fortigate configuration to Azure (other repos out there already extract Fortigate config to JSON, which would be easy to parse), but to offering a generic schema for processing generic, text-based configurations.

The Python code in the example will process the source file line by line, and through an extensive usage of regex will create an array of objects. This array can be converted to either an ARM template or to Azure CLI code (which allows to test object after object).

For example, let's say that the source configuration is a firewall ruleset with two policies:

```
# -- policy 1001 --
action: accept
dstaddr:
192.168.20.15/32
service:
tcp 1433
srcaddr:
172.17.1.100 - 172.17.1.200
172.17.2.100 - 172.17.2.200
172.17.3.100 - 172.17.3.200
172.17.4.100 - 172.17.4.200
# -- policy 1002 --
dstaddr:
0.0.0.0/0
service:
protocol IP
srcaddr:
172.16.1.0/24
172.16.2.0/24
```

The Python script [read_fortigate_config.py](./read_fortigate_config.py) can be run without any flags, and it will default to generate Azure CLI commands to replicate those two policies into an Azure Firewall Policy resource:

```
(base) C:\Repos\azure-config-converter>python .\read_fortigate_config.py --file fortigate_test.txt
az group create -n fortinet -l westeurope
az network firewall policy create -n mypolicy -g fortinet
az network firewall policy rule-collection-group create -n fortinet --policy-name mypolicy -g fortinet --priority 1000
az network firewall policy rule-collection-group collection add-filter-collection --rule-type NetworkRule -o none -g fortinet --rcg-name fortinet --policy-name mypolicy --action  --collection-priority 1010 --name 1001-sx6j --rule-name 1001-sx6j --source-addresses 172.17.1.100-172.17.1.200 172.17.2.100-172.17.2.200 172.17.3.100-172.17.3.200 172.17.4.100-172.17.4.200 --destination-addresses 192.168.20.15/32 --ip-protocols tcp --destination-ports 1433
az network firewall policy rule-collection-group collection add-filter-collection --rule-type NetworkRule -o none -g fortinet --rcg-name fortinet --policy-name mypolicy --action  --collection-priority 1020 --name 1002-UWxo --rule-name 1002-UWxo --source-addresses 172.16.1.0/24 172.16.2.0/24 --destination-addresses 0.0.0.0/0 --ip-protocols Any --destination-ports '*'
```

Or if an ARM template is preferred, the `--format` flag can be used:

```
(base) C:\Repos\azure-config-converter>python .\read_fortigate_config.py --file fortigate_test.txt --format json
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": { },
    "variables": {
        "location": "[resourceGroup().location]"
    },
    "resources": [
        {
            "type": "Microsoft.Network/firewallPolicies",
            "apiVersion": "2020-11-01",
            "name": "jsonpolicy",
            "location": "[variables('location')]",
            "properties": {
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            }
        },
        {
            "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
            "apiVersion": "2020-11-01",
            "name": "jsonpolicy/fortinet",
            "location": "[variables('location')]",
            "dependsOn": [
                "[resourceId('Microsoft.Network/firewallPolicies', 'jsonpolicy'))]"
            ],
            "properties": {
                "priority": 1000,
                "ruleCollections": [
{
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "action": {
                            "type": "Allow"
                        },
                        "rules": [
                            {
                                "ruleType": "NetworkRule",
                                "name": "1001-albp",
                                "ipProtocols": [
                                    "tcp"
                                ],
                                "sourceAddresses": [
                                    "172.17.1.100-172.17.1.200","172.17.2.100-172.17.2.200","172.17.3.100-172.17.3.200","172.17.4.100-172.17.4.200"
                                ],
                                "sourceIpGroups": [],
                                "destinationAddresses": [
                                    "192.168.20.15/32"
                                ],
                                "destinationIpGroups": [],
                                "destinationFqdns": [],
                                "destinationPorts": [
                                    1433
                                ]
                            }
                        ],
                        "name": "1001-albp",
                        "priority": 1010
                    }
,
{
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "action": {
                            "type": "Accept"
                        },
                        "rules": [
                            {
                                "ruleType": "NetworkRule",
                                "name": "1002-USgk",
                                "ipProtocols": [
                                    "Any"
                                ],
                                "sourceAddresses": [
                                    "172.16.1.0/24","172.16.2.0/24"
                                ],
                                "sourceIpGroups": [],
                                "destinationAddresses": [
                                    "0.0.0.0/0"
                                ],
                                "destinationIpGroups": [],
                                "destinationFqdns": [],
                                "destinationPorts": [
                                    "*"
                                ]
                            }
                        ],
                        "name": "1002-USgk",
                        "priority": 1020
                    }
] } }
]}
```

Hopefully you can find some code here that you can reuse, if converting some text-based configuration into an Azure pattern such as Azure CLI or Azure Resource Manager templates

## Optimizing an existing Firewall Policy

The second script provided in this repo is [inspect_policy.py](./inspect_policy.py). It analyzes an existing Azure Firewall Policy in JSON format (this can be obtained exporting the Azure Firewall Policy from the portal), and then running the script. The output will contain high level information about optimization possibilities by adding IP Groups (and hence reducing the total amount of IP objects that the Azure Firewall Policy consumes).

First, you can run the `--help` parameter to see the available options:

```
(base)> python ./inspect_policy.py --help
usage: inspect_policy.py [-h] [--file FILE_NAME] [--rule-name RULE_NAME]
                         [--ip-group-detail] [--rule-detail]
                         [--allow-larger-groups] [--verbose]

Analyze Azure Firewall Policy

optional arguments:
  -h, --help            show this help message and exit
  --file FILE_NAME      you need to supply a file to analyze
  --rule-name RULE_NAME
                        you can supply a rule name to see the details of that
                        rule
  --ip-group-detail     Display detailed info about potential new IP groups
                        (default: False)
  --rule-detail         Display detailed info about rules (default: False)
  --allow-larger-groups
                        Display detailed info about rules (default: False)
  --verbose             run in verbose mode (default: False)
  ```
  
  Second, you can provide the JSON-based Azure Firewall Policy for analysis and see the results:
  
  ```
(base)> python ./inspect_policy.py --file ./2022-01-12T12_35_11.json
Number of Network Rule Collections: 223
Number of Rules: 1144
Maximum number of Rules in a Collection: 68
Total number of IP objects for the policy (1144 rules processed): 38986
Maximum number of IP objects per rule: 4836
86 rules using source IP groups, 26 rules using destination IP groups
558 rules found with more than 5000 IP objects
9 unique IP groups originally defined in the ruleset, maximum utilization of existing groups is 65
490 unique new IP groups could be added, maximum object count in these new groups is 139
Given the limit of 100 IP groups per policy, 91 new IP groups can still be defined
Overall potential savings of IP objects with 91 IP groups: 35801 - from 38986 to 3185 (91.83%)
```

If you want to see what IP Groups exactly should be created and which rules would be optimized, you can add the parameters `--ip-group-detail` or `--rule=detail` to get extra verbose information.

You can additional tune the maximum number of IP groups that you want to use (100 is the Azure maximum, but you might want to leave some space for future growth), and generate ARM JSON code to create the recommended IP Groups:

```
python ./inspect_policy.py --file ./2022-01-12T12_35_11.json --no-summary --ip-group-arm --max-ip-groups 80 >new_ipgroup_template.json
```
