import argparse
import json
import re
import os
import sys
import copy
# https://docs.python.org/3/library/ipaddress.html
import ipaddress


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
            if log_level >= 4:
                print("WARNING: URL {0} reduced to {1}".format(url, url[url.find('*'):]))
    return corrected_urls

# Filters out IP addresses based on the args.ip_version parameter (can be ipv4, ipv6 or both)
def filter_ips(ip_list):
    # For both versions, dont filter
    if args.ip_version == 'both':
        return ip_list
    else:
        filtered_ips = []
        for ip in ip_list:
            # For 'ipv4', return only those who match the IPv4 check
            if is_ipv4(ip) and (args.ip_version == 'ipv4'):
                filtered_ips.append(ip)
            # For 'ipv6', return only non-IPv4 addresses (assumed to be ipv6 then)
            elif (not is_ipv4(ip)) and (args.ip_version == 'ipv6'):
                filtered_ips.append(ip)
        # if log_level >= 7:
        #     print("DEBUG: IP list {0} filtered to {1}".format(str(ip_list), str(filtered_ips)))
        return filtered_ips

# True if parameter exists as address group in the array address_group_list
def is_address_group(str_var):
    ip_grp_found = next((x for x in address_groups if x['name'] == str_var), None)
    if ip_grp_found:
        return True
    else:
        return False

# True if the ipgroup (name in 1st parameter) is used by the net rules (2nd parameter)
def ipgrp_used_by_rules(ipgrp_name, new_rules):
    ipgrp_string = "[resourceId('Microsoft.Network/ipGroups', '{0}')]".format(ipgrp_name)
    for this_new_rule in new_rules:
        if 'destinationIpGroups' in this_new_rule:
            if ipgrp_string in this_new_rule['destinationIpGroups']:
                return True
        if 'sourceIpGroups' in this_new_rule:
            if ipgrp_string in this_new_rule['sourceIpGroups']:
                return True
        else:
            if log_level >= 4:
                print("WARNING: it looks like the key 'destinationIpGroups' is missing from rule '{0}'".format(str(this_new_rule)), file=sys.stderr)
    return False

# True if parameter is a valid FQDN according to RFCs 952, 1123
def is_fqdn(str_var):
    # return bool(re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)",str(str_var)))
    # Modified the regex above to only match on TLDs between 2 and 4 characters
    return bool(re.match(r"(?=^.{4,253}$)(^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$)",str(str_var)))

# Returns correct CIDR. For exmample:
#   correct_cidr('192.168.0.1/24') = '192.168.0.0/24'
def correct_cidr(cidr):
    # If we actually got a CIDR
    if '/' in cidr:
        try:
            correct_cidr = str(ipaddress.ip_interface(cidr).network)
            if correct_cidr != cidr and log_level >= 4:
                print("WARNING: changing wrong CIDR '{0}' into correct CIDR '{1}'".format(cidr, correct_cidr), file=sys.stderr)
            return correct_cidr
        except:
            return cidr
    # Otherwise, we probably just got an IP address, so there is nothing to check
    else:
        return cidr

# True if parameter is an ipv4 address
def is_ipv4(ip_address):
    # First check regex:
    if bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)$",str(ip_address))):
        # Then use ipaddress module:
        if '/' in ip_address:
            try: 
                ip_address = ipaddress.ip_interface(ip_address)  # Using 'ip_interface' instead of 'ip_network', since we can correct later with 'correct_cidr'
                return True
            except:
                if log_level >=4:
                    print('WARNING: incorrect CIDR {0} found'.format(ip_address), file=sys.stderr)
                return False
        else:
            try: 
                ip_address = ipaddress.ip_address(ip_address)
                return True
            except:
                if log_level >=4:
                    print('WARNING: incorrect IP address {0} found'.format(ip_address), file=sys.stderr)
                return False
    else:
        return False

# Returns the contained IPv4 is the provided string contains an IPv4 like 1.2.3.4 or 1.2.3.4-32 
def contains_ipv4(text):
    result = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:-\d{1,2}|)$",str(text))
    try:
        return result.group().replace('-', '/')
    except:
        return None

# Perform some checks on the rule to add, and append it to the list of rules provided in the 2nd argument
def append_rule(rule_to_be_appended, rules_to_append_to):
    if log_level >= 8:
        print("DEBUG: appending to rules:", str(rule_to_be_appended), file=sys.stderr)
    split_rule_counter = 0
    src_fields = ('sourceAddresses', 'sourceIpGroups')
    dst_fields = ('destinationAddresses', 'destinationIpGroups', 'destinationFqdns')
    all_fields = src_fields + dst_fields
    for src_field in src_fields:
        for dst_field in dst_fields:
            # Only look at combinations where the src_field and dst_field are non-zero
            if len(rule_to_be_appended[src_field]) > 0 and len(rule_to_be_appended[dst_field]) > 0:
                temp_rule = copy.copy(rule_to_be_appended)
                split_rule_counter += 1
                temp_rule['name'] = temp_rule['name'] + '-' + str(split_rule_counter)
                # Blank all the rest fieldsd
                for blank_field in all_fields:
                    if blank_field != src_field and blank_field != dst_field:
                        temp_rule [blank_field] = []
                rules_to_append_to.append(temp_rule)
    if split_rule_counter > 1:
        if log_level >= 7:
            print("DEBUG: Palo Alto rule id {0} has been split in {1} Azure Firewall rules".format(rule_to_be_appended['id'], split_rule_counter), file=sys.stderr)
    return rules_to_append_to
    # exist_addresses = bool(len(rule_to_be_appended['destinationAddresses']) > 0)
    # exist_fqdns = bool(len(rule_to_be_appended['destinationFqdns']) > 0)
    # exist_ipgroups = bool(len(rule_to_be_appended['destinationIpGroups']) > 0)
    # only_exist_addresses = exist_addresses and not (exist_fqdns or exist_ipgroups)
    # only_exist_fqdns = exist_fqdns and not (exist_addresses or exist_ipgroups)
    # only_exist_ipgroups = exist_ipgroups and not (exist_addresses or exist_fqdns)
    # exist_addresses_and_fqdns = exist_addresses and exist_fqdns and not exist_ipgroups
    # exist_addresses_and_ipgroups = exist_addresses and exist_ipgroups and not exist_fqdns
    # exist_fqdns_and_ipgroups = exist_fqdns and exist_ipgroups and not exist_addresses
    # exist_all = exist_addresses and exist_fqdns and exist_ipgroups
    # if only_exist_addresses or only_exist_fqdns or only_exist_ipgroups:
    #     rules_to_append_to.append(rule_to_be_appended)
    # elif exist_addresses_and_fqdns:
    #     rule1 = copy.copy(rule_to_be_appended)
    #     rule2 = copy.copy(rule_to_be_appended)
    #     rule1['destinationAddresses'] = []
    #     rule2['destinationFqdns'] = []
    #     rule1['name'] = rule_to_be_appended['name'] + "-1"
    #     rule2['name'] = rule_to_be_appended['name'] + "-2"
    #     rules_to_append_to.append(rule1)
    #     rules_to_append_to.append(rule2)
    # elif exist_addresses_and_ipgroups:
    #     rule1 = copy.copy(rule_to_be_appended)
    #     rule2 = copy.copy(rule_to_be_appended)
    #     rule1['destinationAddresses'] = []
    #     rule2['destinationIpGroups'] = []
    #     rule1['name'] = rule_to_be_appended['name'] + "-1"
    #     rule2['name'] = rule_to_be_appended['name'] + "-2"
    #     rules_to_append_to.append(rule1)
    #     rules_to_append_to.append(rule2)
    # elif exist_fqdns_and_ipgroups:
    #     rule1 = copy.copy(rule_to_be_appended)
    #     rule2 = copy.copy(rule_to_be_appended)
    #     rule1['destinationFqdns'] = []
    #     rule2['destinationIpGroups'] = []
    #     rule1['name'] = rule_to_be_appended['name'] + "-1"
    #     rule2['name'] = rule_to_be_appended['name'] + "-2"
    #     rules_to_append_to.append(rule1)
    #     rules_to_append_to.append(rule2)
    # elif exist_all:
    #     rule1 = copy.copy(rule_to_be_appended)
    #     rule2 = copy.copy(rule_to_be_appended)
    #     rule3 = copy.copy(rule_to_be_appended)
    #     rule1['destinationFqdns'] = []
    #     rule1['destinationIpGroups'] = []
    #     rule2['destinationAddresses'] = []
    #     rule2['destinationIpGroups'] = []
    #     rule3['destinationAddresses'] = []
    #     rule3['destinationFqdns'] = []
    #     rule1['name'] = rule_to_be_appended['name'] + "-1"
    #     rule2['name'] = rule_to_be_appended['name'] + "-2"
    #     rule3['name'] = rule_to_be_appended['name'] + "-3"
    #     rules_to_append_to.append(rule1)
    #     rules_to_append_to.append(rule2)
    #     rules_to_append_to.append(rule3)
    # return rules_to_append_to


# Arguments
parser = argparse.ArgumentParser(description='Generate an ARM template to create a Rule Collection Group in an Azure policy with rules that allow access to M365 endpoints.')
parser.add_argument('--csv-folder', dest='csv_folder', action='store',
                    default=".",
                    help='Local folder containing CSV files. The default is "."')
parser.add_argument('--policy-name', dest='policy_name', action='store',
                    default="azfwpolicy",
                    help='Name for the Azure Firewall Policy. The default is "azfwpolicy"')
parser.add_argument('--policy-sku', dest='policy_sku', action='store',
                    default="Standard",
                    help='SKU for the Azure Firewall Policy. Possible values: Standard, Premium (default: Standard)')
parser.add_argument('--do-not-create-policy', dest='dont_create_policy', action='store_true',
                    default=False,
                    help='If specified, do not include ARM code for the policy, only for the rule collection group. Use if the policy already exists.')
parser.add_argument('--rcg-name', dest='rcg_name', action='store',
                    default="frompaloalto",
                    help='Name for the Rule Collection Group to create in the Azure Firewall Policy. The default is "o365"')
parser.add_argument('--rcg-priority', dest='rcg_prio', action='store',
                    default="10000",
                    help='Priority for the Rule Collection Group to create in the Azure Firewall Policy. The default is "10000"')
parser.add_argument('--use-ip-groups', dest='use_ipgroups', action='store_true',
                    default=False,
                    help='Whether some address groups should be converted to Azure IP Groups (default: False)')
parser.add_argument('--max-ip-groups', dest='max_ipgroups', action='store', type=int, default=50,
                    help='Optional, maximum number of IP groups that will be created in Azure')
parser.add_argument('--rule-id', dest='rule_id', action='store', type=int, default=None,
                    help='Optional, if specified the script will only convert a specific rule ID')
parser.add_argument('--output', dest='format', action='store',
                    default="none",
                    help='Output format. Possible values: json, none')
parser.add_argument('--ip-version', dest='ip_version', action='store',
                    default="ipv4",
                    help='WIP!!! - IP version of AzFW rules. Possible values: ipv4, ipv6, both. Default: ipv4')
parser.add_argument('--pretty', dest='pretty', action='store_true',
                    default=False,
                    help='Print JSON in pretty mode (default: False)')
parser.add_argument('--log-level', dest='log_level_string', action='store',
                    default='warning',
                    help='Logging level (valid values: error/warning/info/debug/all/none. Default: warning)')
args = parser.parse_args()

# Variables
az_app_rules = []
az_net_rules_allow = []
az_net_rules_deny = []
rcg_name = args.rcg_name
rcg_prio = args.rcg_prio
rc_app_name = 'from-pa-app'
rc_app_prio = "11000"
rc_net_name = 'from-pa-net'
rc_net_prio_allow = "10910"
rc_net_prio_deny = "10900"
# Returns true if the string is a number
def is_number(value):
    for character in value:
        if character.isdigit():
            return True
    return False

# Set log_level
if is_number(args.log_level_string):
    try:
        log_level = int(args.log_level_string)
    except:
        log_level = 4
else:
    if args.log_level_string == 'error':
        log_level = 3
    elif args.log_level_string == 'warning':
        log_level = 4
    elif args.log_level_string == 'notice':
        log_level = 5
    elif args.log_level_string == 'info':
        log_level = 6
    elif args.log_level_string == 'debug' or args.log_level_string == 'all':
        log_level = 7
    elif args.log_level_string == 'debugplus' or args.log_level_string == 'all':
        log_level = 8
    elif args.log_level_string == 'none':
        log_level = 0
    else:
        log_level = 4   # We default to 'error'

# Get file list from the specified folder
csv_file_list = []
if args.csv_folder == ".":
    csv_folder = os.getcwd()
else:
    csv_folder = args.csv_folder
if os.path.isdir(csv_folder):
    if log_level >= 7:
        print ("DEBUG: searching for CSV files in folder '{0}'...".format(csv_folder), file=sys.stderr)
    for file in os.listdir(csv_folder):
        file_path = os.path.join(csv_folder, file)
        if os.path.isfile(file_path) and os.path.splitext(file_path)[1] == ".csv":
            csv_file_list.append (file_path)
            if log_level >= 7:
                print ("DEBUG: CSV file {0} found".format(file_path), file=sys.stderr)
else:
    if log_level >= 3:
        print ("ERROR: {0} is not a directory".format(csv_folder), file=sys.stderr)
    sys.exit(1)

# Verify that we have at least 1 CSV file
if len(csv_file_list) == 0:
    if log_level >= 3:
        print ("ERROR: no CSV files could be found in directory {0}".format(csv_folder), file=sys.stderr)
    sys.exit(1)


# Global variables to contain the ruleset
svc_groups = []
address_groups = []
svcs = []
rules = []

# Corrects format of an element in the CSV
# If return_list=True, it makes sure that the returned value is a list
def right_format(text, return_list=False):
    text = str.replace(text, '"', '')
    if ';' in text:
        text = text.split(';')
    elif return_list:
        text = [ text ]
    return text

# Add CSV text (supplied as argument) to the service group list
# 'name,location,members,services,tags'
def add_lines_to_svc_groups(lines, svc_groups):
    for line in lines:
        line = line.split(',')
        new_svc_grp = {
            'name': right_format(line[0]),
            'members_count': right_format(line[2]),
            'services': right_format(line[3], return_list=True)
        }
        svc_groups.append(new_svc_grp)
    return svc_groups

# Add CSV text (supplied as argument) to the service list
# 'name,location,protocol,destinationport,tags'
def add_lines_to_svcs(lines, svcs):
    for line in lines:
        line = line.split(',')
        new_svc = {
            'name': right_format(line[0]),
            'protocol': right_format(line[2], return_list=True),
            'dst_port': right_format(line[3], return_list=True)
        }
        svcs.append(new_svc)
    return svcs

# Add CSV text (supplied as argument) to the address group list
# 'name,location,memberscount,addresses,tags'
def add_lines_to_address_groups(lines, address_groups):
    for line in lines:
        line = line.split(',')
        try:
            new_address_group = {
                'name': right_format(line[0]),
                'members_count': int(right_format(line[2])),
                'addresses': right_format(line[3], return_list=True),
                'keep_as_ip_group': False       # Control field to decide whether creating an Azure IP Group
        }
        except Exception as e:
            if log_level >= 3:
                print("ERROR: error when creating new address group item out of CSV line '{0}' - {1}".format(line, str(e)), file=sys.stderr)
        address_groups.append(new_address_group)
    return address_groups

# Add CSV text (supplied as argument) to the address group list
def add_lines_to_rules(lines, rules):
    for line in lines:
        line = line.split(',')
        # ',Name,Location,Tags,Type,Source Zone,Source Address,Source User,Source HIP Profile,Destination Zone,Destination Address,Application,Service,Action,
        # Profile,Options,Target,Rule Usage Rule Usage,Rule Usage Apps Seen,Rule Usage Days With No New Apps,Modified,Created'
        if len(line) > 15:
            try:
                new_rule = {
                    'id': right_format(line[0]),
                    'name': right_format(line[1]),
                    'type': right_format(line[2]),
                    'src_zone': right_format(line[5]),
                    'src_address': right_format(line[6], return_list=True),
                    'src_user': right_format(line[7]),
                    'src_hip_profile': right_format(line[8]),
                    'dst_zone': right_format(line[9]),
                    'dst_address': right_format(line[10], return_list=True),
                    'application': right_format(line[11]),
                    'service': right_format(line[12], return_list=True),
                    'action': right_format(line[13]),
                    'profile': right_format(line[14]),
                    'options': right_format(line[15]),
                    'target': right_format(line[16])
                }
                # if log_level >= 7:
                #     print("DEBUG: converting CSV line {0} to object {1}".format(line, str(new_rule)))
                rules.append(new_rule)
            except Exception as e:
                if log_level >= 3:
                    print("ERROR: error when processing rule '{0}', skipping this policy- Error message: {1}".format(str(line), str(e)), file=sys.stderr)
        else:
            if log_level >= 7:
                print("DEBUG: skipping line '{0}'".format(str(line)), file=sys.stderr)
    return rules

# Browse the service groups and services and expand the provided list of IP protocols and ports with the found results
def get_svc(svc_name, protocol_list, port_list):
    svc_found = next((x for x in svcs if x['name'] == svc_name), None)
    if svc_found:
        # if log_level >= 7:
        #     print('DEBUG: :) service {0} found in the existing list of services'.format(svc_name))
        protocol_list = list(set(protocol_list + svc_found['protocol']))
        port_list += svc_found['dst_port']
        return protocol_list, port_list
    else:       # If the service wasnt in the service list, it might still be in the service group list
        svc_grp_found = next((x for x in svc_groups if x['name'] == svc_name), None)
        svc_protocols = []
        svc_ports = []
        if svc_grp_found:
            for svc_grp_member in svc_grp_found['services']:
                svc_protocols, svc_ports = get_svc(svc_grp_member, svc_protocols, svc_ports)
            protocol_list = list(set(protocol_list + svc_protocols))
            port_list += svc_ports
            return protocol_list, port_list
        else:
            if log_level >= 4:
                print('WARNING: service {0} not found in the existing list of services'.format(svc_name), file=sys.stderr)
            # Return unchanged parameters
            return protocol_list, port_list

# Resolve IP addresses in text:
# - IP_ -> IPv4/IPv6
# - Search in IP groups
# THe last parameter is a way to override generic --verbose setting, to minimize output
def resolve_addresses (text_list, address_list, fqdn_list, ipgroup_list, function_debug=True, resolve_azipgroups=True):
    # If we got a scalar, transform to a list
    if hasattr(text_list, 'lower'):
        text_list = [ text_list ]
    # There are some errors suggesting address_list is a tuple, so making sure that it is a list here:
    address_list = list(address_list)
    fqdn_list = list(fqdn_list)
    # Go over each IP in the list
    try:
        for text in text_list:
            # If this is an IP address
            if text[:3].lower() == 'ip_':
                if args.ip_version in ('ipv4', 'both'):
                    ip_address = text[3:].replace('-', '/')
                    if is_ipv4(ip_address):
                        address_list.append(correct_cidr(ip_address))
            # If this is an IPv6 address
            elif text[:4].lower() == 'ipv6':
                if args.ip_version in ('ipv6', 'both'):
                    text = text[5:].replace('-', '/')
                    text = text.replace('.', ':')
                    address_list.append(text)
            # If it is a subnet
            elif text[:4].lower() in ('net_', 'blk_'):
                if args.ip_version in ('ipv4', 'both'):
                    cidr = text[4:].replace('-', '/')
                    if is_ipv4(cidr):
                        address_list.append(correct_cidr(cidr))
            elif text[:6].lower() == 'v6_net':
                if args.ip_version in ('ipv6', 'both'):
                    text = text[7:].replace('-', '/')
                    text = text.replace('.', ':')
                    address_list.append(text)
            # If it is a service tag
            elif text[:10].lower() == 'servicetag':
                if 'azurestorage' in text.lower():
                    address_list.append('Storage')
            # Special keywords
            elif text.lower() == 'all_ipv4':
                if args.ip_version in ('ipv4', 'both'):
                    address_list.append('0.0.0.0/0')
            elif text.lower() == 'all_ipv6':
                if args.ip_version in ('ipv6', 'both'):
                    address_list.append('::/0')
            # Maybe it is already an IP
            elif is_ipv4(text):
                if args.ip_version in ('ipv4', 'both'):
                    address_list.append(text)
            elif contains_ipv4(text):
                if args.ip_version in ('ipv4', 'both'):
                    address_list.append(correct_cidr(contains_ipv4(text)))
            # If it is an FQDN we update the fqdn_list
            elif text[:5].lower() == 'fqdn_':
                fqdn_list.append(text[5:])
            # We might want to check whether it is an address group with 'is_address_group' before the fqdn (address group names might be mistakingly taken for FQDNs...)
            # It could be an FQDN without the 'fqdn_' prefix
            elif is_fqdn(text):
                fqdn_list.append(text)
            # Otherwise we assume an IP address group
            else:
                ip_grp_found = next((x for x in address_groups if x['name'] == text), None)
                if ip_grp_found:
                    if not resolve_azipgroups and ip_grp_found['keep_as_ip_group']:
                        # ipgroup_list.append(text)       # If we are keeping the address group as an Azure IP Group, return the name of hte ipgroup
                        ipgroup_list.append("[resourceId('Microsoft.Network/ipGroups', '{0}')]".format(text))      # Add the IP group with its ARM ID format
                    else:
                        address_list, fqdn_list, ipgroup_list = resolve_addresses(ip_grp_found['addresses'], address_list, fqdn_list, ipgroup_list)
                else:
                    if log_level >= 4 and function_debug:
                        print('WARNING: IP address {0} could not be resolved)'.format(text), file=sys.stderr)
                    # Return unchanged parameters
                    return address_list, fqdn_list, ipgroup_list
    except Exception as e:
        if log_level >= 3:
            print("ERROR: error when resolving IP {0} in list {1} - Error message: {2}".format(text, str(text_list), str(e)), file=sys.stderr)
    return address_list, fqdn_list, ipgroup_list

# Analyze the found files looking for a match of the headers line
# TO DO: The header line comparison could be made less fragile
svc_group_file_list = []
svc_file_list = []
address_group_file_list = []
rule_file_list = []
address_group_header = 'name,location,memberscount,addresses,tags'
svc_group_header = 'name,location,members,services,tags'
svc_header = 'name,location,protocol,destinationport,tags'
rule_header = ',name,location,tags,type,sourcezone,sourceaddress,sourceuser,sourcehipprofile,destinationzone,destinationaddress,application,service,action,profile,options,target,ruleusageruleusage,ruleusageappsseen,ruleusagedayswithnonewapps,modified,created'
for file in csv_file_list:
    f = open(file,"r")
    lines = f.readlines()
    header_line = lines[0].rstrip().lower()
    header_line = str.replace(header_line, ' ', '')
    header_line = str.replace(header_line, '"', '')
    header_line = header_line[1:]   # The first character seems to be weird
    if header_line == svc_group_header:
        svc_group_file_list.append(file)
        svc_groups = add_lines_to_svc_groups (lines[1:], svc_groups)
        if log_level >= 7:
            print ("DEBUG: file {0} seems to contain service groups".format(file), file=sys.stderr)
    elif header_line == address_group_header:
        address_group_file_list.append(file)
        address_groups = add_lines_to_address_groups (lines[1:], address_groups)
        if log_level >= 7:
            print ("DEBUG: file {0} seems to contain address groups".format(file), file=sys.stderr)
    elif header_line == svc_header:
        svc_file_list.append(file)
        svcs = add_lines_to_svcs (lines[1:], svcs)
        if log_level >= 7:
            print ("DEBUG: file {0} seems to contain services".format(file), file=sys.stderr)
    elif header_line == rule_header:
        rule_file_list.append(file)
        rules = add_lines_to_rules (lines[1:], rules)
        if log_level >= 7:
            print ("DEBUG: file {0} seems to contain policies".format(file), file=sys.stderr)
    else:
        if log_level >= 4:
            print ("WARNING: ignoring file {0}, couldn't identify format of header line '{1}' (first character is '{2}')".format(file, header_line, header_line[0]), file=sys.stderr)

try:
    top = 2
    if log_level >= 6:
        print ("INFO: {0} services retrieved out of {1} files".format(str(len(svcs)), str(len(svc_file_list))), file=sys.stderr)
        if log_level >= 8:
            for i in range(0, top):
                print('DEBUG: - {0}: {1}'.format(str(i), str(svcs[i])), file=sys.stderr)
    if log_level >= 6:
        print ("INFO: {0} service groups retrieved out of {1} files".format(str(len(svc_groups)), str(len(svc_group_file_list))), file=sys.stderr)
        if log_level >= 8:
            for i in range(0, top):
                print('DEBUG: - {0}: {1}'.format(str(i), str(svc_groups[i])))
    if log_level >= 6:
        print ("INFO: {0} address groups retrieved out of {1} files".format(str(len(address_groups)), str(len(address_group_file_list))), file=sys.stderr)
        if log_level >= 8:
            for i in range(0, top):
                print('DEBUG: - {0}: {1}'.format(str(i), str(address_groups[i])), file=sys.stderr)
    if log_level >= 6:
        print ("INFO: {0} rules retrieved out of {1} files".format(str(len(rules)), str(len(rule_file_list))), file=sys.stderr)
        if log_level >= 8:
            for i in range(0, top):
                print('DEBUG: - {0}: {1}'.format(str(i), str(rules[i])), file=sys.stderr)
except:
    pass

# Now we have the IP groups, we can find out which ones are kept (minimum member count)
def get_member_count(e):
  return e['members_count']
address_groups.sort(reverse=True, key=get_member_count)
valid_ip_group_count = 0
max_ip_group = 0
min_ip_group = 0
for address_group in address_groups:
    ips, fqdns, ipgroups = resolve_addresses(address_group['addresses'], [], [], [], function_debug=False, resolve_azipgroups=True)
    address_group['resolved_ips'] = ips
    address_group['resolved_fqdns'] = ips
    if valid_ip_group_count < args.max_ipgroups and fqdns == []:
        try:
            address_group['members_count'] = int(address_group['members_count'])
        except:
            if log_level >= 3:
                print('ERROR: members count in IP group has a non-numeric value', file=sys.stderr)
        address_group['keep_as_ip_group'] = True
        valid_ip_group_count +=1
        min_ip_group = address_group['members_count']
        if max_ip_group < min_ip_group: max_ip_group = min_ip_group
if log_level >= 7:
    print('DEBUG: {0} IP groups would be kept, minimum member count of these groups is {1}, maximum is {2}'.format(valid_ip_group_count, min_ip_group, max_ip_group), file=sys.stderr)

# Go through the rules
cnt_allow = 0
cnt_deny = 0
cnt_disabledrules = 0
cnt_apprules = 0
cnt_netrules_ip = 0
cnt_netrules_fqdn = 0
cnt_pa_rules = 0
if args.rule_id and log_level >=7:
    print("DEBUG: looking for rule", str(args.rule_id), file=sys.stderr)
for rule in rules:
    cnt_pa_rules += 1
    # If a rule-id was specified as parameter, only do that one
    if not args.rule_id or (args.rule_id and rule['id'] == str(args.rule_id)):
        # Look out for disabled rules
        if rule['name'][:10] == '[Disabled]':
            cnt_disabledrules += 1
            # if log_level >= 7:
            #     print('DEBUG: ignoring disabled rule:', str(rule))
        else:
            if log_level >= 8:
                print("DEBUG: processing rule {0} - '{1}': {2}".format(rule['id'], rule['name'], str(rule)), file=sys.stderr)
            # Log  user / HIP profile
            if rule['src_user'] != 'any' and log_level >= 4:
                print("WARNING: rule '{0}' using identity source '{1}'".format(rule['name'], rule['src_user']), file=sys.stderr)
            if rule['src_hip_profile'] != 'any' and log_level >= 4:
                print("WARNING: rule '{0}' using source HIP profile '{1}'".format(rule['name'], rule['src_hip_profile']), file=sys.stderr)
            cnt_netrules_ip += 1
            new_rule = {
                'name': 'id' + str(rule['id']) + '-' + str(rule['name']).replace(' ', ''),
                'ruleType': 'NetworkRule',
                'sourceAddresses': [],
                'sourceIpGroups': [],
                'destinationAddresses': [],
                'destinationFqdns': [],
                'destinationIpGroups': []
            }
            # Sources
            if rule['src_address'] == [ 'any' ]:
                new_rule['sourceAddresses'] = '*',
                new_rule['sourceIpGroups'] = []
            else:
                if args.use_ipgroups:
                    src_ips, src_fqdns, src_ipgroups = resolve_addresses(rule['src_address'], [], [], [], resolve_azipgroups=False)
                else:
                    src_ips, src_fqdns, src_ipgroups = resolve_addresses(rule['src_address'], [], [], [], resolve_azipgroups=True)
                new_rule['sourceAddresses'] = src_ips
                new_rule['sourceIpGroups'] = src_ipgroups
            # Destinations
            if rule['dst_address'] == [ 'any' ]:
                new_rule['destinationAddresses'] = '*',
            else:
                if args.use_ipgroups:
                    dst_ips, dst_fqdns, dst_ipgroups = resolve_addresses(rule['dst_address'], [], [], [], resolve_azipgroups=False)
                else:
                    ips, fqdns, ipgroups = resolve_addresses(rule['dst_address'], [], [], [], resolve_azipgroups=True)
                new_rule['destinationAddresses'] = dst_ips
                new_rule['destinationFqdns'] = dst_fqdns
                new_rule['destinationIpGroups'] = dst_ipgroups
            # Service
            if rule['service'] == [ 'any' ]:
                new_rule['ipProtocols'] = [ 'Any' ]
                new_rule['destinationPorts'] = [ '*' ]
            elif rule['service'] == [ 'application-default' ]:
                new_rule['ipProtocols'] = [ 'Any' ]
                new_rule['destinationPorts'] = [ '*' ]
            else:
                # If 'service' can only be an array
                for rule_svc in rule['service']:
                    new_rule_protocols, new_rule_ports = get_svc(rule_svc, [], [])
                # Application
                # if hasattr(rule['application'], 'lower'):  # If rule['application'] is a string
                #     new_rule_protocols, new_rule_ports = get_svc(rule['application'], new_rule_protocols, new_rule_ports)
                # else:                                      # If rule['application'] is a list of strings
                #     for rule_svc in rule['application']:
                #         new_rule_protocols, new_rule_ports = get_svc(rule_svc, new_rule_protocols, new_rule_ports)
                new_rule['ipProtocols'] = new_rule_protocols
                new_rule_ports = list(set(new_rule_ports))
                new_rule['destinationPorts'] = new_rule_ports
            # DEBUG: print built up rule
            if log_level >= 8:
                print("DEBUG: this is the JSON built for rule {0} - {1}: '{2}'".format(rule['id'], rule['name'], str(new_rule)), file=sys.stderr)
            # Verify that there is at least a valid destination
            if not (len(new_rule['destinationAddresses']) > 0 or len(new_rule['destinationFqdns']) > 0 or len(new_rule['destinationIpGroups']) > 0):
                if log_level >= 3:
                    print("ERROR: For rule '{0} - {1}' it wasn't possible to derive any destination addresses/FQDNs/IPgroups from {2}. Note that the IP version to process is set to {3}".format(rule['id'], rule['name'], str(rule['dst_address']), args.ip_version), file=sys.stderr)
            # Verify that there is at least a valid source
            if not (len(new_rule['sourceAddresses']) > 0 or len(new_rule['sourceIpGroups']) > 0):
                if log_level >= 3:
                    print("ERROR: For rule '{0} - {1}' it wasn't possible to derive any source addresses/IPgroups from {2}. Note that the IP version to process is set to {3}".format(rule['id'], rule['name'], str(rule['src_address']), args.ip_version), file=sys.stderr)
            # # Verify that there are either sourceAddresses or sourceIpGroups but not both
            # elif len(new_rule['sourceAddresses']) > 0 and len(new_rule['sourceIpGroups']) > 0:
            #     if log_level >= 3:
            #         print("ERROR: For rule '{0} - {1}' there are both source IP addresses and IP groups, it needs to be split".format(rule['id'], rule['name']), file=sys.stderr)
            # Verify that there are no FQDNs for the sources
            elif len(src_fqdns) > 0:
                if log_level >= 3:
                    print("ERROR: For rule '{0} - {1}' there are FQDNs specified as source".format(rule['id'], rule['name']), file=sys.stderr)
            else:
                # Add new rule to the corresponding rule collection
                if rule['action'] == 'Allow':
                    cnt_allow += 1
                    az_net_rules_allow = append_rule(new_rule, az_net_rules_allow)
                elif rule['action'] == 'Deny':
                    cnt_deny += 1
                    az_net_rules_deny = append_rule(new_rule, az_net_rules_deny)
                else:
                    if log_level >= 3:
                        print ("ERROR: rule {0} - '{1}' has action other than Allow: {2}".format(str(rule['id']), rule['name'], rule['action']), file=sys.stderr)

##########
# Output #
##########

# Generate JSON would be creating an object and serialize it
if args.format == "json":
    api_version = "2021-08-01"
    azfw_policy_name = args.policy_name
    arm_template = {
        '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        'contentVersion': '1.0.0.0',
        'parameters': {},
        'variables': {
            'location': '[resourceGroup().location]'
        },
        'resources': []
    }
    if not args.dont_create_policy:
        resource_policy = {
            'type': 'Microsoft.Network/firewallPolicies',
            'apiVersion': api_version,
            'name': azfw_policy_name,
            'location': '[variables(\'location\')]',
            'properties': {
                'sku': {
                    'tier': args.policy_sku
                },
                'dnsSettings': {
                    'enableProxy': 'true'
                },
                'threatIntelMode': 'Alert'
            }
        }
        arm_template['resources'].append(resource_policy)
    resource_rcg = {
        'type': 'Microsoft.Network/firewallPolicies/ruleCollectionGroups',
        'apiVersion': api_version,
        'name': azfw_policy_name + '/' + rcg_name,
        'dependsOn': [],
        'location': '[variables(\'location\')]',
        'properties': {
            'priority': rcg_prio,
            'ruleCollections': []
        }
    }
    if not args.dont_create_policy:
        resource_rcg['dependsOn'].append('[resourceId(\'Microsoft.Network/firewallPolicies\', \'' + azfw_policy_name +'\')]'),

    resource_net_rc_allow = {
        'ruleCollectionType': 'FirewallPolicyFilterRuleCollection',
        'name': rc_net_name + '-allow',
        'priority': rc_net_prio_allow,
        'action': {
            'type': 'allow'
        },
        'rules': az_net_rules_allow
    }
    resource_net_rc_deny = {
        'ruleCollectionType': 'FirewallPolicyFilterRuleCollection',
        'name': rc_net_name + '-deny',
        'priority': rc_net_prio_deny,
        'action': {
            'type': 'deny'
        },
        'rules': az_net_rules_deny
    }
    resource_app_rc = {
        'ruleCollectionType': 'FirewallPolicyFilterRuleCollection',
        'name': rc_app_name,
        'priority': rc_app_prio,
        'action': {
            'type': 'allow'
        },
        'rules': az_app_rules
    }
    if args.use_ipgroups:
        for ip_grp in address_groups:
            if ip_grp['keep_as_ip_group']:
                # As additional check, we verify that the group is being used by a rule
                if ipgrp_used_by_rules(ip_grp['name'], az_net_rules_allow) or ipgrp_used_by_rules(ip_grp['name'], az_net_rules_deny):
                    resource_ipgroup = {
                        'type': 'Microsoft.Network/ipGroups',
                        'apiVersion': api_version,
                        'name': ip_grp['name'],
                        'location': '[variables(\'location\')]',
                        'properties': {
                            'ipAddresses': ip_grp['resolved_ips']
                        }
                    }
                    arm_template['resources'].append(resource_ipgroup)
                    resource_rcg['dependsOn'].append("[resourceId('Microsoft.Network/ipGroups', '{0}')]".format(ip_grp['name']))

    resource_rcg['properties']['ruleCollections'].append(resource_net_rc_allow)
    resource_rcg['properties']['ruleCollections'].append(resource_net_rc_deny)
    resource_rcg['properties']['ruleCollections'].append(resource_app_rc)
    arm_template['resources'].append(resource_rcg)
    if args.pretty:
        print(json.dumps(arm_template, indent=4, sort_keys=True))
    else:
        print(json.dumps(arm_template))

elif args.format == "none":
    if log_level >= 7:
        print('DEBUG: {0} rules analized: {1} app rules, {2} FQDN-based net rules and {3} IP-based net rules'.format(str(cnt_pa_rules), str(cnt_apprules), str(cnt_netrules_fqdn), str(cnt_netrules_ip)))
        print('DEBUG: {2} disabled rules, {0} allow rules and {1} deny rules'.format(str(cnt_allow), str(cnt_deny), str(cnt_disabledrules)))
        # print('DEBUG: Net rules:', str(net_rules))
        # print('DEBUG: App rules:', str(app_rules))
else:
    print ("Format", args.format, "not recognized!")
