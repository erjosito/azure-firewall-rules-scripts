# Creating a policy with O365 endpoints

Note that this script is obsolete after the tags created as documented in [Use Azure Firewall to protect Office 365](https://learn.microsoft.com/en-us/azure/firewall/protect-office-365).

The script `o365_rules.py` downloads the JSON in `https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7` and generates an ARM template for an Azure Firewall Policy that can be imported to Azure:

```bash
# Explore the available flags and options
python3 ./o365_rules.py --help
# Run in test mode
python3 ./o365_rules.py --format none --verbose
# Generate ARM template
python3 ./o365_rules.py >o365sample.json
# Deploy ARM Template
rg=myrg
location=westeurope
az group create -n $rg -l $location
az deployment group create -n o365$RANDOM -g $rg -o none --template-file ./o365sample.json
```
