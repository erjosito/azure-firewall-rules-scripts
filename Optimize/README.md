# Optimizing an existing Firewall Policy

[inspect_policy.py](./inspect_policy.py) analyzes an existing Azure Firewall Policy in JSON format (this can be obtained exporting the Azure Firewall Policy from the portal), and then running the script. The output will contain high level information about optimization possibilities by adding IP Groups (and hence reducing the total amount of IP objects that the Azure Firewall Policy consumes).

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
