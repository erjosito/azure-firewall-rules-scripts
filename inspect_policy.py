# To Do:
# - Skip IP groups that contain a single prefix
# - When evaluating savings, skip empty SourceIps/DestinationIps (already using IP groups)

import json
import argparse
import sys

# Constants
max_objects_per_group = 5000
max_ipgroups = 100

# Function to count objects for an array of IPs/subnets
def count_objects(prefix_list, count_subnets_as_one=True):
    if count_subnets_as_one:
        return len(prefix_list)
    else:
        count = 0
        for prefix in prefix_list:
            # If '/' is in prefix, we assume it is a subnet
            if '/' in prefix:
                prefix_mask = prefix.split('/')[1]
                # The mask could be in the /24 or in the /255.555.255.0 formats
                if '.' in prefix_mask:
                    prefix_length = convert_mask_to_int(prefix_mask)
                else:
                    prefix_length = int(prefix_mask)
                count += 2**(32-prefix_length)
            # If '/' not in prefix, we assume object count is 1
            else:
                count += 1
        return count

# Converts network mask to length. For example, for '255.255.255.0' it returns '24'
def convert_mask_to_int(network_mask):
    network_mask_dec = 0
    octets = network_mask.split('.')
    if len(octets) == 4:
        for i in range(4):
            network_mask_dec +=  int(octets[i]) * (256 ** i)
        network_mask_bin = bin(network_mask_dec).split('b')[1]
        mask_length = network_mask_bin.count('1')
    else:
        print("ERROR: not able to transform network mask {0} into an integer.".format(str(network_mask)))
        mask_length = 0
    return mask_length

# Tries to find an IP group that matches all prefixes
# The parameter 'larger_groups' True allows to return an IP Group that contains the prefixes in the first parameter, but some other prefixes too
def find_prefixes_in_ipgroups(prefix_list, ipgroups, larger_groups = False):
    # The prefix list should contain at least 2 prefixes, otherwise IP Groups make no sense
    if len(prefix_list) > 1:
        # Loop through all existing IP groups
        for ipgroup_name in ipgroups:
            # For each ipgroup, check if it contains all prefix in our prefix_list
            all_prefixes_found = True
            for prefix in prefix_list:
                if not prefix in ipgroups[ipgroup_name]['prefixes']:
                    all_prefixes_found = False
            # Optionally, check that the IP group contains ONLY the prefixes specified in the parameter prefix_list
            if not larger_groups:
                for prefix in ipgroups[ipgroup_name]['prefixes']:
                    if not prefix in prefix_list:
                        all_prefixes_found = False
            # If this specific IP group does the trick, return the IP group name
            if all_prefixes_found:
                return ipgroup_name
        # If we arrived down to here, we didnt find a matching IP Group
        return None
    else:
        return None

# Calculate IP object savings, given additional IP groups contained in the ipgroups dictionary
def ipobject_savings(policy, ipgroups):
    ipobjects_savings = 0
    for collection in policy['NetworkRuleCollections']:
        for rule in collection['Rules']:
            newsrcgroup_name = find_prefixes_in_ipgroups(rule['SourceIps'], ipgroups, larger_groups=allow_larger_groups)
            newsrcgroup = (newsrcgroup_name != None)
            newdstgroup_name = find_prefixes_in_ipgroups(rule['DestinationIps'], ipgroups, larger_groups=allow_larger_groups)
            newdstgroup = (newdstgroup_name != None)
            if newsrcgroup or newdstgroup:
                if rule_detail:
                    print("Collection {0}, rule name {1}".format(collection['Name'], rule['Name']))
                    if 'Description' in rule: print("  - Description: {0}".format(str(rule['Description'])))
                    if 'Direction' in rule: print("  - Direction: {0}".format(str(rule['Direction'])))
                    if 'Type' in rule: print("  - Type: {0}".format(str(rule['Type'])))
                    if 'SourceIps' in rule: print("  - Source IPs: {0}".format(str(rule['SourceIps'])))
                    if 'SourceIpGroups' in rule: print("  - Source IP Groups: {0}".format(str(rule['SourceIpGroups'])))
                    if 'SourcePorts' in rule: print("  - Source Ports: {0}".format(str(rule['SourcePorts'])))
                    if 'DestinationIps' in rule: print("  - Destination IPs: {0}".format(str(rule['DestinationIps'])))
                    if 'DestinationIpGroups' in rule: print("  - Destination IP Groups: {0}".format(str(rule['DestinationIpGroups'])))
                    if 'DestinationPorts' in rule: print("  - Destination Ports: {0}".format(str(rule['DestinationPorts'])))
                    if 'Protocols' in rule: print("  - Protocols: {0}".format(str(rule['Protocols'])))
                srcip_objects = count_objects (rule['SourceIps'])
                dstip_objects = count_objects (rule['DestinationIps'])
                if 'SourceIpGroups' in rule and rule['SourceIpGroups'] != None:
                    srcgroup_objects = len(rule['SourceIpGroups'])
                else:
                    srcgroup_objects = 0
                if 'DestinationIpGroups' in rule and rule['DestinationIpGroups'] != None:
                    dstgroup_objects = len(rule['DestinationIpGroups'])
                else:
                    dstgroup_objects = 0
                src_objects = srcip_objects + srcgroup_objects
                dst_objects = dstip_objects + dstgroup_objects
                if newsrcgroup and newdstgroup:
                    newsrc_objects = 1 + srcgroup_objects
                    newdst_objects = 1 + dstgroup_objects
                    ipobjects_savings += (src_objects * dst_objects - newsrc_objects * newdst_objects)
                    if rule_detail:
                        print("  * Through IP groups {0} and {1} (Source/Destination), IP objects can be consolidated from {2} into {3}".format(
                            newsrcgroup_name, newdstgroup_name, str(src_objects * dst_objects), str(newsrc_objects * newdst_objects)
                        ))
                        print("  * SRC IP group {0} prefixes: {1}".format(newsrcgroup_name, str(ipgroups[newsrcgroup_name]['prefixes'])))
                        print("  * DST IP group {0} prefixes: {1}".format(newdstgroup_name, str(ipgroups[newdstgroup_name]['prefixes'])))
                elif newsrcgroup:
                    newsrc_objects = 1 + srcgroup_objects
                    newdst_objects = dst_objects
                    ipobjects_savings += (src_objects * dst_objects - newsrc_objects * newdst_objects)
                    if rule_detail:
                        print("  * Through IP group {0} (Source), IP objects can be consolidated from {1} into {2}".format(
                            newsrcgroup_name, str(src_objects * dstip_objects), str(newsrc_objects * newdst_objects)
                        ))
                        print("  * SRC IP group {0} prefixes: {1}".format(newsrcgroup_name, str(ipgroups[newsrcgroup_name]['prefixes'])))
                elif newdstgroup:
                    newsrc_objects = src_objects
                    newdst_objects = 1 + dstgroup_objects
                    ipobjects_savings += (src_objects * dst_objects - newsrc_objects * newdst_objects)
                    if rule_detail:
                        print("  * Through IP group {0} (Destination), IP objects can be consolidated from {1} into {2}".format(
                            newdstgroup_name, str(srcip_objects * dst_objects), str(newsrc_objects * newdst_objects)
                        ))
                        print("  * DST IP group {0} prefixes: {1}".format(newdstgroup_name, str(ipgroups[newdstgroup_name]['prefixes'])))
                if src_objects == 0:
                    print("ERROR: source objects cannot be 0. Source IP objects is {0}, source group objects is {1}".format(str(srcip_objects), str(srcgroup_objects)))
                    sys.exit(1)
                if dst_objects == 0:
                    print("ERROR: destination objects cannot be 0. Destination IP objects is {0}, destination group objects is {1}".format(str(dstip_objects), str(dstgroup_objects)))
                    sys.exit(1)
    print("Overall potential savings of IP objects with {0} IP groups: {1} - from {2} to {3} ({4:.2%})".format(
        str(len(ipgroups)),
        str(ipobjects_savings),
        str(total_objects),
        str(total_objects - ipobjects_savings),
        (ipobjects_savings / total_objects)
    ))
    return ipobject_savings


# Arguments
parser = argparse.ArgumentParser(description='Analyze Azure Firewall Policy')
parser.add_argument('--file', dest='file_name', action='store',
                    help='you need to supply a file to analyze')
parser.add_argument('--rule-name', dest='rule_name', action='store',
                    help='you can supply a rule name to see the details of that rule')
parser.add_argument('--ip-group-detail', dest='ipgroup_detail', action='store_true',
                    default=False,
                    help='Display detailed info about potential new IP groups (default: False)')
parser.add_argument('--rule-detail', dest='rule_detail', action='store_true',
                    default=False,
                    help='Display detailed info about rules (default: False)')
parser.add_argument('--allow-larger-groups', dest='larger_groups', action='store_true',
                    default=False,
                    help='Display detailed info about rules (default: False)')
parser.add_argument('--verbose', dest='verbose', action='store_true',
                    default=False,
                    help='run in verbose mode (default: False)')
args = parser.parse_args()
file_name = args.file_name
rule_name = args.rule_name
ipgroup_detail = args.ipgroup_detail
rule_detail = args.rule_detail
allow_larger_groups = args.larger_groups
verbose = args.verbose

# Opening JSON file
f = open(file_name)
policy = json.load(f)
f.close()

# If a rule name was specified, just find that rule and show its details
if rule_name:
    for collection in policy['NetworkRuleCollections']:
        for rule in collection['Rules']:
            if rule['Name'] == rule_name:
                print("Collection {0}, rule name {1}".format(collection['Name'], rule['Name']))
                if 'Description' in rule: print("  - Description: {0}".format(str(rule['Description'])))
                if 'Direction' in rule: print("  - Direction: {0}".format(str(rule['Direction'])))
                if 'Type' in rule: print("  - Type: {0}".format(str(rule['Type'])))
                if 'SourceIps' in rule: print("  - Source IPs: {0}".format(str(rule['SourceIps'])))
                if 'SourceIpGroups' in rule: print("  - Source IP Groups: {0}".format(str(rule['SourceIpGroups'])))
                if 'SourcePorts' in rule: print("  - Source Ports: {0}".format(str(rule['SourcePorts'])))
                if 'DestinationIps' in rule: print("  - Destination IPs: {0}".format(str(rule['DestinationIps'])))
                if 'DestinationIpGroups' in rule: print("  - Destination IP Groups: {0}".format(str(rule['DestinationIpGroups'])))
                if 'DestinationPorts' in rule: print("  - Destination Ports: {0}".format(str(rule['DestinationPorts'])))
                if 'Protocols' in rule: print("  - Protocols: {0}".format(str(rule['Protocols'])))
    sys.exit()

# Print some info
print("Number of Network Rule Collections: {0}".format(str(len(policy['NetworkRuleCollections']))))
rules_no=0
max_rules_per_coll=0
for collection in policy['NetworkRuleCollections']:
    rules_no += len(collection['Rules'])
    if len(collection['Rules']) > max_rules_per_coll: max_rules_per_coll = len(collection['Rules']) 
print("Number of Rules: {0}".format(str(rules_no)))
print("Maximum number of Rules in a Collection: {0}".format(str(max_rules_per_coll)))

# Analyze rule per rule
total_objects = 0
max_objects_per_rule = 0
rule_counter = 0
rule_src_ipgroup_counter = 0
rule_dst_ipgroup_counter = 0
rule_too_many_objects = 0
ipgroup_counter = 0
ipgroups = {}  # Dictionary containing the defined/possible IP groups. Each entry is the IP addresses and an array of rule names that reference it

# Loop through collections and rules
for collection in policy['NetworkRuleCollections']:
    for rule in collection['Rules']:
        rule_counter += 1
        if rule['SourceIps']:
            srcip = rule['SourceIps']
            srcip_objects = count_objects (srcip)
            # Create a potential ipgroup in our ipgroups dict
            if srcip_objects > 1 and srcip_objects < max_objects_per_group:
                # Try to find if there is already an IP group matching the prefixes
                existing_ipgroup = find_prefixes_in_ipgroups(rule['SourceIps'], ipgroups, larger_groups=allow_larger_groups)
                if existing_ipgroup:    # A matching IP group was found!
                    if 'srcrules' in ipgroups[existing_ipgroup]:
                        ipgroups[existing_ipgroup]['srcrules'].append(rule['Name'])
                    else:
                        ipgroups[existing_ipgroup]['srcrules'] = [ rule['Name'] ]
                    rule['newsrcgroup'] = existing_ipgroup
                else:                   # Create new IP group
                    # Check that no other entry already exists with the name of this rule
                    ipgroup_counter += 1
                    ipgroup_name = 'ipgroup' + "{:05d}".format(ipgroup_counter)
                    # ipgroup_name = rule['Name'] + '@' + collection['Name'] + '_src'
                    if ipgroup_name in ipgroups:
                        print("ERROR: there is already an ipgroup with the name {0}".format(ipgroup_name))
                    else:
                        rule['newsrcgroup'] = ipgroup_name
                        ipgroups[ipgroup_name] = {
                            'prefixes': rule['SourceIps'],
                            'srcrules': [
                                rule['Name']
                            ]
                        }
            else:
                rule_too_many_objects += 1
        else:
            srcip_objects = 0
        if rule['DestinationIps']:
            dstip = rule['DestinationIps']
            dstip_objects = count_objects (dstip)
            # Create a potential ipgroup in our ipgroups dict
            if dstip_objects > 1 and dstip_objects < max_objects_per_group:
                # Try to find if there is already an IP group matching the prefixes
                existing_ipgroup = find_prefixes_in_ipgroups(rule['DestinationIps'], ipgroups, larger_groups=allow_larger_groups)
                if existing_ipgroup:    # A matching IP group was found!
                    if 'dstrules' in ipgroups[existing_ipgroup]:
                        ipgroups[existing_ipgroup]['dstrules'].append(rule['Name'])
                    else:
                        ipgroups[existing_ipgroup]['dstrules'] = [ rule['Name'] ]
                    rule['newdstgroup'] = existing_ipgroup
                else:                   # Create new IP group
                    # Check that no other entry already exists with the name of this rule
                    ipgroup_counter += 1
                    ipgroup_name = 'ipgroup' + "{:05d}".format(ipgroup_counter)
                    # ipgroup_name = rule['Name'] + '@' + collection['Name'] + '_dst'
                    if ipgroup_name in ipgroups:
                        print("ERROR: there is already an ipgroup with the name {0}".format(ipgroup_name))
                    else:
                        rule['newdstgroup'] = ipgroup_name
                        ipgroups[ipgroup_name] = {
                            'prefixes': rule['DestinationIps'],
                            'dstrules': [
                                rule['Name']
                            ]
                        }
        else:
            dstip_objects = 0
        # Add one object per IP group as src or dst
        if rule['SourceIpGroups']:
            srcgroup_objects = len(rule['SourceIpGroups'])
            # Update the ip groups dict
            for ipgroup in rule['SourceIpGroups']:
                # Reference to an IP group already in the dict
                if ipgroup in ipgroups:
                    if 'srcrules' in ipgroups[ipgroup]:
                        ipgroups[ipgroup]['srcrules'].append(rule['Name'])
                    else:
                        ipgroups[ipgroup]['srcrules'] = [ rule['Name'] ]
                # Create new entry in the ipgroups dict
                else:
                    ipgroups[ipgroup] = {
                        'prefixes': [],   # This is an IP group in the original policy, we dont know which IP prefixes it references
                        'srcrules': [
                            rule['Name']
                        ]
                    }
        else:
            srcgroup_objects = 0
        if rule['DestinationIpGroups']:
            dstgroup_objects = len(rule['DestinationIpGroups'])
            # Update the ip groups dict
            for ipgroup in rule['DestinationIpGroups']:
                # Reference to an IP group already in the dict
                if ipgroup in ipgroups:
                    if 'dstrules' in ipgroups[ipgroup]:
                        ipgroups[ipgroup]['dstrules'].append(rule['Name'])
                    else:
                        ipgroups[ipgroup]['dstrules'] = [ rule['Name'] ]
                # Create new entry in the ipgroups dict
                else:
                    ipgroups[ipgroup] = {
                        'prefixes': [],   # This is an IP group in the original policy, we dont know which IP prefixes it references
                        'rules': [
                            rule['Name']
                        ]
                    }
        else:
            dstgroup_objects = 0
        # The number of objects is the sum of objects from the IPs and the IP groups
        src_objects = srcip_objects + srcgroup_objects
        dst_objects = dstip_objects + dstgroup_objects
        # Total objects is the multiplication of source and destination objects
        rule_objects = src_objects * dst_objects
        total_objects += rule_objects
        if rule_objects > max_objects_per_rule: max_objects_per_rule = rule_objects
        if rule['SourceIpGroups'] and len(rule['SourceIpGroups']) > 0: rule_src_ipgroup_counter += 1
        if rule['DestinationIpGroups'] and len(rule['DestinationIpGroups']) > 0: rule_dst_ipgroup_counter += 1
print ("Total number of IP objects for the policy ({1} rules processed): {0}".format(str(total_objects), str(rule_counter)))
print ("Maximum number of IP objects per rule: {0}".format(str(max_objects_per_rule)))
print ("{0} rules using source IP groups, {1} rules using destination IP groups".format(str(rule_src_ipgroup_counter), str(rule_dst_ipgroup_counter)))
print ("{0} rules found with more than {1} IP objects".format(str(rule_too_many_objects), str(max_objects_per_group)))

# Look at the ipgroups dictionary
existing_ipgroup_count = 0
existing_ipgroup_used_max = 0
new_ipgroup_count = 0
new_ipgroup_used_max = 0
for ipgroup_name in ipgroups:
    # Count the number of rules (src and dst) that refer to this IP Group
    ipgroup_rule_no = 0
    if 'srcrules' in ipgroups[ipgroup_name]: ipgroup_rule_no += len(ipgroups[ipgroup_name]['srcrules'])
    if 'dstrules' in ipgroups[ipgroup_name]: ipgroup_rule_no += len(ipgroups[ipgroup_name]['dstrules'])
    # If there are no prefixes, it means that it was an IP Group reference by the original ruleset
    if len(ipgroups[ipgroup_name]['prefixes']) == 0:
        existing_ipgroup_count += 1
        if ipgroup_rule_no > existing_ipgroup_used_max: existing_ipgroup_used_max = ipgroup_rule_no
    # If there are defined prefixes, it is a potentially new IP group definition
    else:
        new_ipgroup_count += 1
        if ipgroup_rule_no > new_ipgroup_used_max: new_ipgroup_used_max = ipgroup_rule_no
print("{0} unique IP groups originally defined in the ruleset, maximum utilization of existing groups is {1}".format(str(existing_ipgroup_count), str(existing_ipgroup_used_max)))
print("{0} unique new IP groups could be added, maximum object count in these new groups is {1}".format(str(new_ipgroup_count), str(new_ipgroup_used_max)))
max_new_ipgroups = max_ipgroups - existing_ipgroup_count
print("Given the limit of {0} IP groups per policy, {1} new IP groups can still be defined".format(str(max_ipgroups), str(max_new_ipgroups)))

# Count the required IP groups
for ipgroup_name in ipgroups:
    if len(ipgroups[ipgroup_name]['prefixes']) > 0:
        ipobject_count = count_objects(ipgroups[ipgroup_name]['prefixes'])
        rule_count = 0
        if 'srcrules' in ipgroups[ipgroup_name]: rule_count += len(ipgroups[ipgroup_name]['srcrules'])
        if 'dstrules' in ipgroups[ipgroup_name]: rule_count += len(ipgroups[ipgroup_name]['dstrules'])
        ipgroups[ipgroup_name]['savings'] = ipobject_count * rule_count

# Get the top IP groups (max_new_ip_groups)
summary_ipgroups = {k: ipgroups[k]['savings'] for k in ipgroups if 'savings' in ipgroups[k]}
sorted_ipgroups = sorted(summary_ipgroups.items(), key=lambda x:x[1], reverse=True)
max_savings = 0
new_ipgroups = {}       # We will create a new dictionary only with the top IP groups
# print("Top potential new IP groups rated on their savings on IP objects")
for i in range(max_new_ipgroups):
    # print("  {0}: {1} IP objects".format(str(sorted_ipgroups[i][0]), str(sorted_ipgroups[i][1])))
    max_savings += sorted_ipgroups[i][1]
    new_ipgroups[sorted_ipgroups[i][0]] = ipgroups[sorted_ipgroups[i][0]]
# print("With the top {0} new IP groups, {1} IP objects could be saved ({2})".format(str(max_new_ipgroups), str(max_savings), "{0:.4%}".format(max_savings / total_objects)))

# Create a new dictionary with the top IP groups, and calculate the ipobject savings
savings = ipobject_savings(policy, new_ipgroups)
# Count the required IP groups
if ipgroup_detail:
    for ipgroup_name in new_ipgroups:
        print("New IP group {1} for prefixes {0}".format(str(ipgroups[ipgroup_name]['prefixes']), ipgroup_name))
        if 'srcrules' in ipgroups[ipgroup_name]: print("  Used by rules as source: {0}".format(str(ipgroups[ipgroup_name]['srcrules'])))
        if 'dstrules' in ipgroups[ipgroup_name]: print("  Used by rules as destination: {0}".format(str(ipgroups[ipgroup_name]['dstrules'])))
