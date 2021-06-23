# Converting text-based configs to Azure code

The purpose of this repo is providing an example that illustrates a possibility to convert configuration files from disparate sources to code that can be imported into Azure.

As source configuration the example in this repo uses a configuration extracted from a Fortigate firewall. The goal of this repo is not focusing on converting Fortigate configuration to Azure (other repos out there already extract Fortigate config to JSON, which would be easy to parse), but to offering a generic schema for processing generic, text-based configurations.

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

The Python script can be run without any flags, and it will default to generate Azure CLI commands to replicate those two policies into an Azure Firewall Policy resource:

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
