#!/usr/bin/env python
# Copyright (c) 2016 Pani Networks
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http: #www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from optparse import OptionParser
import subprocess
import logging
import simplejson
from mimetools import Message
from StringIO import StringIO
HTTP_Unprocessable_Entity = 422

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S')

addr_scheme = {}

parser = OptionParser(usage="%prog --port")
parser.add_option('--port', default=9630, dest="port", type="int",
                  help="Port number to listen for incoming requests")
(options, args) = parser.parse_args()

def filter_rules_idx(rules):
    """
    Returns 'sweet spot' in iptables rules, index in *filter table where chain
    definition ends and rules definition begins.
    """
    filter_idx = rules.index('*filter')
    for rule in rules[filter_idx + 1:]:
        if not rule.startswith(":"):
            return rules.index(rule) + 1

# We want to receive json object as a POST.
class AgentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """
        We do not have a storage so GET is not really supported.
        """
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write("Romana policy agent")

        return


    def route(self):
        if self.path=="/":
            self.do_NP_update()
        else:
	    self.send_header('Content-type','text/html')
	    self.end_headers()
            self.send_response(401)
            self.wfile.write(""" Not Found """)

        return


    def do_DELETE(self):
        self.http_method = "DELETE"
        self.decode_request()
        self.route()


    def do_POST(self):
        """
        Processes POST requests
        extracts romana policy definition objects and passes it down for implementation
    
        Expected structure: { "method" : "ADDED|DELETED", "policy_definition" : "NP" }
        """

        self.http_method = "POST"
        self.decode_request()
        self.route()

        return


    def do_NP_update(self):
        """
        Installs or deinstalls network policy rules from iptables
        """
        global addr_scheme

        # Namespace isolation update is a special case
        if self.is_ns_isolation(self.json_data):
            self.do_NS_update(self.json_data)
            return

        policy_def = self.json_data
        # if policy_def:
        #     policy_def_valid = self.validate_policy(policy_def)
        # else:
        #     policy_def_valid = self.json_data.get("name")
        #     policy_def = self.json_data
        policy_def_valid = self.validate_policy(policy_def)
        
        logging.warning("In do_NP_update : policy_def_valid = %s" % policy_def_valid)

        if policy_def_valid:
            addr_scheme = policy_def.get("datacenter")

            self.send_response(200)
            self.wfile.write("Policy definition accepted")
            logging.warning("Creating policy %s" % policy_def)

            if self.http_method == "DELETE":
                logging.warning("Deleting policy %s" % policy_def)
            else:
                logging.warning("Creating policy %s" % policy_def)

            policy_update(addr_scheme, policy_def, delete_policy = ( self.http_method == "DELETE" ))

            return
        else:
            self.send_response(HTTP_Unprocessable_Entity)
            self.wfile.write(""" Failed to validate policy definition """)




    def do_NS_update(self, policy_def):
        # TODO This endpoint shoud really go away, only used for prototyping
        # while new policy fromat being discussed.
        # TODO Now it will take a lot of refactoring to support for empty segment_ids
        # which are required to express network policy that selects all segments.
        # But still must be done.
		logging.info("Request for NS isolation update")

                applied_to = policy_def.get('applied_to')
                tid = applied_to[0].get('tenant_network_id')
		logging.info("tid is %s" % tid)

                # isolated flag in a policy spec can only be True.
                # In order to disable one need to send DELETE request with
		isolated = self.http_method == "POST"
		logging.info("isolated is %s" % isolated)

		iptables_rules = get_current_iptables()
		TENANT_POLICY_VECTOR_CHAIN = "ROMANA-T%s" % tid
		logging.info("TENANT_POLICY_VECTOR_CHAIN is %s" % TENANT_POLICY_VECTOR_CHAIN)

		# Parse a list of chain names out of current rules,
		# use it to avoid duplication when adding new chains.
		existing_chains = [ k.split(" ")[0][1:] for k in iptables_rules if k.startswith(":") ]

		tenant_vector_chain_exists = TENANT_POLICY_VECTOR_CHAIN in existing_chains
		logging.info("tenant_vector_chain_exists is %s" % tenant_vector_chain_exists)

		ALLOW_ANY_VECTOR = "-A %s -j ACCEPT" % TENANT_POLICY_VECTOR_CHAIN
		logging.info("ALLOW_ANY_VECTOR is %s" % ALLOW_ANY_VECTOR)

                DEFAULT_DROP_RULE = "-A %s -j DROP" % TENANT_POLICY_VECTOR_CHAIN
                default_drop_exists = DEFAULT_DROP_RULE in iptables_rules
		logging.info("DEFAULT_DROP_RULE is %s" % ALLOW_ANY_VECTOR)

		allow_any_vector_exists = ALLOW_ANY_VECTOR in iptables_rules
		logging.info("allow_any_vector_exists is %s" % allow_any_vector_exists)

		filter_idx = iptables_rules.index('*filter')

		if not tenant_vector_chain_exists:
			logging.info("Tenant policy vector chain does not exist - creating")
			iptables_rules.insert(filter_idx + 1, ":%s - [0:0]" % TENANT_POLICY_VECTOR_CHAIN)

                if not default_drop_exists:
			logging.info("Default drop rule for tenant does not exist - creating")
                        last_commit_index = iptables_rules.index('COMMIT',
                                iptables_rules.index('COMMIT',
                                    iptables_rules.index('COMMIT')+1
                                )+1
                            )
                        iptables_rules.insert(last_commit_index-1, DEFAULT_DROP_RULE)

		if allow_any_vector_exists:
			if isolated:
				logging.info("Enabling isolation")
				iptables_rules.remove(ALLOW_ANY_VECTOR)
		else:
			if not isolated:
				logging.info("Disabling isolation")
				iptables_rules.insert(filter_rules_idx(iptables_rules), ALLOW_ANY_VECTOR)
		apply_new_ruleset(iptables_rules)

		return


    def is_ns_isolation(self, policy_def):
        """
        Returns True if policy defenition is a Namespace policy defenition.
        """
        # NS isloation request must have tenant_id in applied_to
        # and must not have any segment_ids.
        applied_to = policy_def.get('applied_to')
        if applied_to and len(applied_to) > 0:
            tenant_id = applied_to[0].get('tenant_network_id')
            segment_id = applied_to[0].get('segment_network_id')
            if segment_id:
                # NS isolation must not have segment_network_id in applied_to
                return False

        # The only rule allowed for NS isolation rquest is 
        # { "isolated" : True }
        rules = policy_def.get('rules')
        if rules and len(rules) > 0:
            isolated = rules[0].get("isolated")
            if not isolated:
                return False

        return True


    def validate_policy(self, policy_def):
        """
        Checks that some top level sections are present in the policy.
        """
        policy_name = policy_def.get('name')
        applied_to = policy_def.get('applied_to')
        rules = policy_def.get('rules')
        peers = policy_def.get('peers')
        datacenter = policy_def.get('datacenter')
        if not policy_name or not applied_to or not rules or not peers or not datacenter:
            logging.warning("In validate_policy, policy invalid name=%s, applied_to=%s, Rules=%s, datacenter=%s" % (policy_name, applied_to, rules, datacenter))
            return False
        return True


    def decode_request(self):
        """
        Parses json from POST
        """
        self.send_header('Content-type','text/html')
        self.end_headers()
        headers = Message(StringIO(self.headers))
        self.raw_data = self.rfile.read(int(headers["Content-Length"]))
        try:
            self.json_data = simplejson.loads(self.raw_data)
        except Exception, e:
            logging.warning("Cannot parse %s" % self.raw_data)
            return


def policy_update(romana_address_scheme, policy_definition, delete_policy=False):
    """
    Using the romana address scheme and a policy definition as input,
    create a new set of iptables rules and apply them.

    NOTE! Since we do get/edit/write in separate steps, it would be possible
    for someone else to clobber the rules before we have a chance to write
    this. A lock of of some sort, or an otherwise atomic operation needs to be
    implemented here. TODO!

    """
    
    # PolicyId is a uniq tag that we are going to use to check if rule is applied already
    policy_id      = policy_definition['name']

    # Create the new rules, based on the Romana addressing scheme and the
    # policy definition.
    new_rules = make_rules(romana_address_scheme, policy_definition, policy_id)
    """
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(new_rules)
    """

    # LOCK SECTION SHOULD START HERE...
    # Get what iptables currently has
    iptables_rules = get_current_iptables()

    for rule in iptables_rules:
        if '"PolicyId=%s"' % policy_id in rule.split(" ") and not delete_policy:
            logging.info("Skipping policy %s - already applied" % policy_id)
            return


    # Remove ALL rules relating in any way to a policy of the specified name.
    clean_rules = \
        delete_all_rules_for_policy(iptables_rules,
                                    policy_definition['name'],
                                policy_definition['applied_to'][0]['tenant_network_id'])

    if delete_policy:
        apply_new_ruleset(clean_rules)
        return

    # Create a new rule set that can be applied to iptables
    rules = make_new_full_ruleset(clean_rules, new_rules)

    apply_new_ruleset(rules)


def make_new_full_ruleset(current_rules, new_rules):
    """
    Prepends the specified rules in the given chains, if they exist.

    If not, creates the chains.

    Return a new, augmented list of rules, ready to replace the old rules.

    """

    # Some dirty logs. No need to run all this loops if logging level less then DEBUG
    if logging.getLevelName(logging.getLogger().getEffectiveLevel()) == 'DEBUG':
        logging.debug("In make_new_full_ruleset")
        for i, line in enumerate(current_rules):
            logging.debug("Current rules --> line %3d : %s" % (i,line))

        for i, line in enumerate(new_rules):
            logging.debug("New rules --> chain %3d : %s" % (i,line))
            for j, rule in enumerate(new_rules[line]):
                logging.debug("New rules ----> rule %3d : %s" % (j,rule))

    # The goal here is to merge new rules with existing
    # iptables rules.

    # Parse out a list of chain names out of current rules,
    # use it to avoid duplication when adding new chains.
    existing_chains = [ k.split(" ")[0][1:] for k in current_rules if k.startswith(":") ]
    logging.debug("Existing chains %s "  %existing_chains)

    # In current rules find position in *filter table where chain
    # definition ends and rule definition begins.
    filter_idx = filter_rules_idx(current_rules)-1

    rules = []

    # We only care about *filter table, copy everything before it.
    for rule in current_rules[:filter_idx]:
        rules.append(rule)

    # Insert new chains if they don't exist already.
    for chain in new_rules.keys():
        if chain not in existing_chains:
            rules.append(":%s - [0:0]" % chain)

    # Insert all the rules from all new chains, if they don't exist already.
    for chain in new_rules.keys():
        for rule in new_rules[chain]:
            if rule not in current_rules:
                rules.append(rule)

    # Copy the rest of original *filter table.
    for rule in current_rules[filter_idx:]:
        rules.append(rule)

    # Skip the loop if logging less then DEBUG
    if logging.getLevelName(logging.getLogger().getEffectiveLevel()) == 'DEBUG':
        for j, rule in enumerate(rules):
            logging.debug("Result rules ----> rule %3d : %s" % (j,rule))

    return rules


def make_rules(addr_scheme, policy_def, policy_id):
    """
    Return dictionary with rules that should be pre-pended to given chains.

    The chain names are the keys to the dict, the values are lists of rules.

    """
    rules = {}
    tenant         = policy_def['applied_to'][0].get('tenant_network_id')
    target_segment = policy_def['applied_to'][0].get('segment_network_id')
    from_segment   = policy_def['peers'][0].get('segment_network_id')
    name           = policy_def['name']

    
    # TODO handle undefined segments here
    # if not target_segment:
    #    target_segment = "ALL"

    # Traffic flows through per-tenant policy chain into
    # per-segment policy chains and from there into policy chains.
    # Unless one of policy chains will ACCEPT the packet it will RETURN
    # to the per-tenant chain and will reach DROP at the end of the chain.

    # Per tenant policy chain name.
    tenant_policy_vector_chain = "ROMANA-T%s" % tenant

    # The name for the new policy's chain(s). Need to include the tenant ID to
    # avoid name conflicts.
    logging.warning("In make_rules with tenant = %s, target_segment_id = %s, from_segment = %s, name = %s" %
            (tenant, target_segment, from_segment, name))
    policy_chain_name = "ROMANA-T%dP-%s_" % \
        (tenant, name)

    # Per-segment policy chain names for both incoming and outgoing segments
    # that are involved.
    target_segment_forward_chain = "ROMANA-T%s-S%s" % \
        (tenant, target_segment)
    from_segment_forward_chain = "ROMANA-T%s-S%s" % \
        (tenant, from_segment)

    # Jump from per-tenant chain into per-segment chains and default DROP.
    rules[tenant_policy_vector_chain] = [
        _make_rule(tenant_policy_vector_chain, "-j %s" % target_segment_forward_chain),
        _make_rule(tenant_policy_vector_chain, "-j %s" % from_segment_forward_chain),
#        _make_rule(tenant_policy_vector_chain, "-j %s" % tenant_wide_policy_chain),
        _make_rule(tenant_policy_vector_chain, "-j DROP")
    ]

    # Jump from per-segment chain into policy chain
    rules[target_segment_forward_chain] = [
        _make_rule(target_segment_forward_chain, "-j %s" % policy_chain_name),
        _make_rule(target_segment_forward_chain, '-m comment --comment POLICY_CHAIN_HEADER -j RETURN')
    ]
    rules[from_segment_forward_chain] = [
        _make_rule(from_segment_forward_chain, "-j %s" % policy_chain_name),
        _make_rule(from_segment_forward_chain, '-m comment --comment POLICY_CHAIN_HEADER -j RETURN')
    ]
#    rules[tenant_wide_policy_chain] = [
#        _make_rule(from_segment_forward_chain, '-m comment --comment POLICY_CHAIN_HEADER -j RETURN')
#    ]

    # Assemble the rules for the top-level policy chain. These rules look at
    # the IP addresses (source and dest) and figure out whether this is
    # incoming our outgoing traffic.
    u32_in_match  = _make_u32_match(addr_scheme, tenant, from_segment,
                                    tenant, target_segment)
    u32_out_match = _make_u32_match(addr_scheme, tenant, target_segment,
                                    tenant, from_segment)

    in_chain_name  = policy_chain_name[:-1] + "-IN_"
    out_chain_name = policy_chain_name[:-1] + "-OUT_"

    rules[policy_chain_name] = [
        _make_rule(policy_chain_name, '-m u32 --u32 "%s" -j %s' %
                                           (u32_in_match, in_chain_name)),
        _make_rule(policy_chain_name, '-m u32 --u32 "%s" -j %s' %
                                           (u32_out_match, out_chain_name)),
        _make_rule(policy_chain_name, '-m comment --comment PolicyId=%s -j RETURN' % policy_id)
    ]

    rules = _make_rules(in_chain_name, out_chain_name, rules, policy_def.get('rules'))

    return rules


def _make_rules(in_chain_name, out_chain_name, iptables_rules, policy_rules):
    """
    For each rules in policy_rules creates in/out rules in iptables_rules.

    Returns updated list of iptables_rules
    """
    if not iptables_rules.get(in_chain_name):
        iptables_rules[in_chain_name] = []

    if not iptables_rules.get(out_chain_name):
        iptables_rules[out_chain_name] = []

    # For each rule in the policy create iptables rules.
    for r in policy_rules:
        if r['protocol'] == 'TCP':
            stateful = r.get("is_stateful")
            if stateful:
                in_rule = '-p tcp --dport %s --tcp-flags SYN SYN -j ACCEPT' % ':'.join(str(x) for x in r["ports"])
                out_rule = '-p tcp --sport %s --tcp-flags SYN,ACK SYN,ACK -j ACCEPT' % ':'.join(str(x) for x in r["ports"])
                state = '-m state --state ESTABLISHED -j ACCEPT'

                iptables_rules[in_chain_name].append(_make_rule(in_chain_name, in_rule))
                iptables_rules[in_chain_name].append(_make_rule(in_chain_name, state))
                iptables_rules[out_chain_name].append(_make_rule(out_chain_name, out_rule))
                iptables_rules[out_chain_name].append(_make_rule(out_chain_name, state))
            else:
                in_rule = '-p tcp --dport %s -j ACCEPT' % ':'.join(str(x) for x in r["ports"])
                out_rule = '-p tcp --sport %s  -j ACCEPT' % ':'.join(str(x) for x in r["ports"])

                iptables_rules[in_chain_name].append(_make_rule(in_chain_name, in_rule))
                iptables_rules[out_chain_name].append(_make_rule(out_chain_name, out_rule))

        elif r['protocol'] == 'UDP':
            in_rule = '-p udp --dport %s -j ACCEPT' % ':'.join(str(x) for x in r["ports"])
            out_rule = '-p udp --sport %s  -j ACCEPT' % ':'.join(str(x) for x in r["ports"])

            iptables_rules[in_chain_name].append(_make_rule(in_chain_name, in_rule))
            iptables_rules[out_chain_name].append(_make_rule(out_chain_name, out_rule))

        #TODO elif r['protocol'] == 'ICMP', current policy format doesn't allow for different
        # ICMP types on emitter and receiver. Do we allow specified types everywhere or apply
        # some heuristic ?

        else:
            rule = '-m comment --comment error_unknownProtocol -j LOG'
            state = '-m comment --comment error_unknownProtocol -j LOG'

    iptables_rules[in_chain_name].append(_make_rule(in_chain_name, '-j RETURN'))
    iptables_rules[out_chain_name].append(_make_rule(out_chain_name,  '-j RETURN'))

    return iptables_rules

def _make_rule(chain_name, text):
    """
    Returns "-A <chain_name> <text>"

    """
    return "-A %s %s" % (chain_name, text)

def _make_u32_match(addr_scheme,
                    from_tenant, from_segment, to_tenant, to_segment):
    """
    Creates the obscure u32 match string with bitmasks and all that's needed.

    Something like this:

    "0xc&0xff00ff00=0xa001200&&0x10&0xff00ff00=0xa001200"

    """
    mask = src = dst = 0

    # Take network bits from Romana CIDR. e.g. 10.0.0.0/8
    #                                                   ^
    network_width = int(addr_scheme["cidr"].split("/")[-1])

    # Take first octet of Romana network e.g. 10.0.0.0/8
    #                                         ^^
    network_value = int(addr_scheme["cidr"].split(".")[0])


    # Full match on net portion.
    mask = ((1<<network_width)-1) << 24
    src  = network_value << 24
    dst  = network_value << 24

    # Leaving the host portion empty...

    # Adding the mask and values for tenant
    shift_by = addr_scheme['segment_bits'] + addr_scheme['endpoint_bits']
    mask |= ((1<<addr_scheme['tenant_bits'])-1) << shift_by
    src  |= from_tenant << shift_by
    dst  |= to_tenant << shift_by

    # Adding the mask and values for segment
    shift_by = addr_scheme['endpoint_bits']
    mask |= ((1<<addr_scheme['segment_bits'])-1) << shift_by
    src  |= from_segment << shift_by
    dst  |= to_segment << shift_by

    return "0xc&0x%(mask)x=0x%(src)x&&0x10&0x%(mask)x=0x%(dst)x" % \
        { "mask" : mask, "src" : src, "dst" : dst }

def get_current_iptables():
    """
    Return the current iptables.

    """
    rules = subprocess.check_output(["iptables-save"]).split("\n")
    return rules

def delete_all_rules_for_policy(iptables_rules, policy_name, tenant_id):
    """
    Specify the policy name, such as 'foo'. This will delete all the rules that
    refer to anything related to this rule, such as 'ROMANA-P-foo_',
    'ROMANA-P-foo-IN_', etc.

    """
    full_names = [ 'ROMANA-T%dP-%s%s_' % (tenant_id, policy_name, p)
                        for p in [ "", "-IN", "-OUT" ] ]

    # Only transcribe those lines that don't mention any of the chains
    # related to the policy.
    clean_rules = [ r for r in iptables_rules if not
                            any([ p in r for p in full_names ]) ]

    return clean_rules

def apply_new_ruleset(rules):
    """
    Uses iptables-restore to apply a full, new ruleset.

    """
    p = subprocess.Popen(["iptables-restore"],
                         stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate('\n'.join(rules))
    if err:
        logging.info("@@@ ERROR applying these rules...")
        for i, r in enumerate(rules):
            logging.info("%3d: %s" % (i+1, r))
        logging.info("@@@ ERROR applying iptables: %s ", err)
        return False
    else:
        logging.info("@@@ iptables rules successfully applied.")
        return True

def run_agent():
    server = HTTPServer(('', options.port), AgentHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_agent()
