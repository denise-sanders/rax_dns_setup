#!/usr/bin/python

from ansible.module_utils.basic import *
import pyrax
import socket
import pyrax.exceptions as exc
import json
import traceback
from time import sleep

DOCUMENTATION = '''  
---
module: rax_dns_setup  
short_description: Create DNS records for all hosts in the region. Debugging is optional, and outputs the log to a specified file.
'''

EXAMPLES = '''  
- name: Add Records for Sydney
  rax_dns_setup:
    region: SYD
    username: Shannon
    apikey: apikey 
    debugfile: filename.txt 

- name: Add Records for DFW
  rax_dns_setup:
    region: DFW
    credsfile: path/to/mycredentials.txt
    
'''

DNS_ENTRY = {"type": "A",
             "name": "None",
             "data": "None",
             "ttl": 6000}


# For debugging
debug = None

#pyrax.set_http_debug(True)


# Helper Function ###################

def make_entry(name, ip, region_lowercase):
    host_entry = DNS_ENTRY.copy()
    if ':' in ip:
        name = name +'-v6'
        host_entry['type'] = "AAAA"
    host_entry['name'] = str(name + '.' + region_lowercase + '.symetric.online')
    host_entry['data'] = str(ip)
    return host_entry
        
def send_record(record,dns,dom):
    try:
        print dns.add_records(dom, [record])
        if debug: 
            debug.write(record['name'] + " was successfully added.\n")
        return "success"
    except exc.DomainRecordAdditionFailed as e:
        if 'Record is a duplicate of another record' in str(e):
            if debug:
                debug.write(record['name'] + " preexisting record, no record added.\n")
            return "duplicate"
        if 'OverLimit Retry' in str(e):
            # Waits a second and then tries again
            sleep(1)
            try:
                send_record(record,dns,dom)
                debug.write("OverLimit Retry failed to reset\n")
                return "success"
            except:
                return "failure"
        if 'Validation failed' in str(e):
            if debug:
                debug.write(record['name'] + " validation failed\n")
            return 'validation'    
        if debug:
            debug.write(record['name'] + " failed:\n")
            debug.write(str(e) + "\n")
            return "failure"    
    except Exception as e:
        if debug:
            debug.write(record['name'] + " failed:\n")
            debug.write(str(e) + "\n")
    return "failure"


def find_region_in_list(region,dns):
    region_lowercase = region.lower()
    max = len(dns.list())
    x = 0
    while x < max:
         if region_lowercase in dns.list()[x].name:
             return dns.list()[x]
         x = x + 1
    return None

# Module Logic ##################
def set_up(data):       
    # Set up debugging, if specified
    global debug
    if data['debugfile'] is not None:    
        debug = open(data['debugfile'], 'w')
    else:
        debug = None    # Don't print things out if no file to print to
    result = {}
    module_error = False

    pyrax.set_setting("identity_type", "rackspace")

    if data['credsfile']:
        try:
            pyrax.set_credential_file(data['credsfile'])
            result['authentication'] = "sucess"
        except exc.AuthenticationFailed:
            result['authentication'] = "failed"
            module_error = True     
    elif data['username'] and data['apikey']:
        try:
            pyrax.set_credentials(data['username'], data['apikey'])
            result['authentication'] = "sucess"
        except exc.AuthenticationFailed:
            result['authentication'] = "failed"
            module_error = True 
    else:
        result['authentication'] = "failed"
        module_error = True 
        if debug:
            debug.write('No credentials specify. Either specify a credential file or a username and apikey.\n')        
    
    records = {
        'successfully added': 0,
        'already recorded': 0,
        'validation failed': 0,
        'failed': 0,
    }
    result['records'] = records

    cs_reg = pyrax.connect_to_cloudservers(region=data['region'])
    dns = pyrax.cloud_dns
    dom = find_region_in_list(data['region'],dns)
    region_lowercase = data['region'].lower()

    try:
        dom
    except NameError:
        module_error = True
    else:
        print "Found Region"   
    for host in cs_reg.list():
        name = host.name
        # Remove region name if it is part of hostname
        if name.endswith('.' + region_lowercase):
            name = name[:-4]
        networks = host.networks
        
        for network, address in networks.iteritems():
            if 'private' in network:
                fqdn = name + '.private'
                entry = make_entry(fqdn, address[0],region_lowercase)
                result_send = send_record(entry,dns,dom)
            elif 'skynet' in network:
                fqdn = name + '.skynet'
                entry = make_entry(fqdn, address[0],region_lowercase)
                result_send = send_record(entry,dns,dom)
            elif 'public' in network:
                for rec in address:
                    fqdn = name + '.public'    
                    entry = make_entry(fqdn, rec, region_lowercase)
                    result_send = send_record(entry,dns,dom)              

            # Process Result of Send Record
            if result_send == 'success':
                result['records']['successfully added'] += 1
            elif result_send == 'duplicate':     
                result['records']['already recorded'] += 1
            elif result_send == 'validation':
                result['records']['validation failed'] += 1
            else:
                result['records']['failed'] += 1

    json_results = json.dumps(result)

    if debug:
        debug.write("Records successfully added:" + str(result['records']['successfully added']) + "\n")
        debug.write("Duplicate records ignored:" + str(result['records']['already recorded']) + "\n")
        debug.write("Validation failed for records:" + str(result['records']['validation failed']) + "\n")
        debug.write("Records that failed to add:" + str(result['records']['failed']) + "\n")
    # Return is_error, has_changed, result
    return module_error, True, json_results 


def main():

    fields = {
        "region" : { "required": True, "type" : "str" },
	    "username" : { "required": False, "type" : "str"},
        "apikey": { "required": False, "type" : "str"},
        "debugfile": {"required": False, "type" : "str"},
        "credsfile": {"required": False, "type": "str"}
    }
    
   

    module = AnsibleModule(argument_spec=fields)
    
    is_error, has_changed, result = set_up(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module_fail_json(msg="Error running module", meta=result)

if __name__ == '__main__':  
    main()
