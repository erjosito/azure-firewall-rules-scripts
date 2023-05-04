# Some tools to work with Azure Firewall Rules

The purpose of this repo is providing some examples that illustrate different techniques to work with Azure Firewall Rules. At this time two use cases are included:

- Processing a text file with rules with a different syntax and output Azure Firewall syntax (ARM JSON or CLI)
- Analyzing an existing Azure Policy and look for potential optimization through the usage of IP Groups to reduce the consumption of IP objects

## Disclaimer

These scripts are shared as they are, and they are not supported by Microsoft in any way, shape or form. Be sure to test and validate the output of these scripts. If you find any issue with them, I would be thankful if you opened an issue in this repo.

## Scripts in this repo

You can find the following contents in this repo:

- [Generating a rule collection group from a Fortigate ruleset](./Fortigate/README.md)
- [Generating a rule collection group from a Palo Alto ruleset](./PaloAlto/README.md)
- [Generating a rule collection group from a Checkpoint ruleset](./Checkpoint/README.md)
- [Inspect an Azure Policy and look for optimization possibilities](./Optimize/README.md)
- [Generating a rule colllection group for O365 endpoints](./O365/README.md) (this script is obsolete after the release of [Use Azure Firewall to protect Office 365](https://learn.microsoft.com/en-us/azure/firewall/protect-office-365))
