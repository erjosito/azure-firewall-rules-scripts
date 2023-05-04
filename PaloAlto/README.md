# Importing Azure Firewall rules from a Palo Alto configuration

As explained in [Palo Alto config guide](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/firewall-administration/use-the-web-interface/export-configuration-table-data), Palo Alto configuration tables (policies, address groups, services and service groups) can be exported in CSV.

The script [pa2azfw.py](./pa2azfw.py) will search for all CSV files in the specified folder (it defaults to the current working directory), and generage an ARM template that can be applied to generate a new policy with a rule collection group containing all rules, or just the rule connection group inside of an existing template. You can specify the logging level for more or less verbosity of the output:

```bash
# Explore the available flags and options
python3 ./pa2azfw.py --help
# Create ARM template (note that only the ipv4 mode has been tested)
python3 ./pa2azfw.py --output json --log-level warning --ip-version ipv4 --use-ip-groups >pa-policy.json
# Deploy ARM Template
rg=myrg
location=westeurope
az group create -n $rg -l $location
az deployment group create -n pa2azfw$RANDOM -g $rg -o none --template-file ./pa-policy.json
```
