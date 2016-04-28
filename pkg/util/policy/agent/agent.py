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
        """

        self.http_method = "POST"
        self.decode_request()
        self.route()


    def do_NP_update(self):
        """
        Installs or deinstalls network policy rules from iptables
        """
        global addr_scheme

        policy_def = self.json_data
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
                                policy_definition['applied_to'])

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

    # Parse a list of chain names out of current rules,
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

    # We really need a list of chains but using dict here
    # to avoid extra checks for item in list.
    policy_chains = {}

    # Create chain names for each target and stuff them with default rules
    name = policy_def['name']
    for target in policy_def.get('applied_to'):
        tenant         = target.get('tenant_network_id')
        target_segment = target.get('segment_network_id')

        logging.warning("In make_rules with tenant = %s, target_segment_id = %s, name = %s" %
                (tenant, target_segment, name))

        # Traffic flows through per-tenant policy chain into
        # per-segment policy chains and from there into policy chains.
        # Unless one of policy chains will ACCEPT the packet it will RETURN
        # to the per-tenant chain and will reach DROP at the end of the chain.

        # Per tenant policy chain name.
        tenant_policy_vector_chain = "ROMANA-T%s" % tenant

        # Tenant wide policy vector chain hosts jumps to the policies
        # applied to att tenant traffic as well as default rules.
        tenant_wide_policy_vector_chain = "ROMANA-T%s-W" % tenant

        # The name for the new policy's chain(s). Need to include the tenant ID to
        # avoid name conflicts.
        policy_chain_name = "ROMANA-T%dP-%s_" % \
            (tenant, name)

        # Policy chain only hosts match conditions, rules themselves are
        # applied in this auxiliary chain
        in_chain_name  = policy_chain_name[:-1] + "-IN_"

        # Per segment policy chain to host jumps to the actuall policy chains.
        if target_segment:
            target_segment_forward_chain = "ROMANA-T%s-S%s" % \
                (tenant, target_segment)
        else:
            # If segment_network_id not provided in the policy,
            # consider policy to be tenant wide.
            target_segment_forward_chain = tenant_wide_policy_vector_chain

        # Chain names are going to be used later to fill in the rules. Store them.
        policy_chains[in_chain_name] = True

        # Jump from per-tenant chain into per-segment chains and default DROP.
        rules[tenant_policy_vector_chain] = [
            _make_rule(tenant_policy_vector_chain, "-j %s" % target_segment_forward_chain),
            _make_rule(tenant_policy_vector_chain, "-j %s" % tenant_wide_policy_vector_chain),
            _make_rule(tenant_policy_vector_chain, "-j DROP")
        ]

        # Jump from per-segment chain into policy chain
        if target_segment_forward_chain not in rules:
            rules[target_segment_forward_chain] = []
            rules[target_segment_forward_chain].append(
                    _make_rule(target_segment_forward_chain, '-m comment --comment POLICY_CHAIN_HEADER -j RETURN'))
        rules[target_segment_forward_chain].insert(0,
                _make_rule(target_segment_forward_chain, "-j %s" % policy_chain_name))

        # Default rules per tenant.
        if tenant_wide_policy_vector_chain not in rules:
            rules[tenant_wide_policy_vector_chain] = []
            rules[tenant_wide_policy_vector_chain].append(
                _make_rule(tenant_wide_policy_vector_chain, '-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'))
            rules[tenant_wide_policy_vector_chain].append(
                _make_rule(tenant_wide_policy_vector_chain, '-m comment --comment POLICY_CHAIN_HEADER -j RETURN'))

        # Loop over peers and fill top level policy chains with source matching rules
        for peer in policy_def.get('peers'):
            # Possible peers are
            # CIDR - detected by cidr field
            # peer - detected by peer type
            # tid/sid - detected by tenant_network_id and segment_network_id
            pr = peer.get('peer')
            cidr = peer.get('cidr')
            from_tenant = peer.get('tenant_network_id')
            from_segment = peer.get('segment_network_id')

            if pr:
                if pr == "any":
                    jump_rules = [ _make_rule(policy_chain_name, "-j %s") % in_chain_name ]
                else:
                    raise Exception("Unsupported value of peer %s" % pr)

            elif cidr:
                jump_rules = [ _make_rule(policy_chain_name, "-s %s -j %s") % (cidr, in_chain_name) ]

            elif from_segment and from_tenant:
                u32_in_match = _make_u32_match(addr_scheme, tenant, from_segment)
                jump_rules = [
                    _make_rule(policy_chain_name, '-m u32 --u32 "%s" -j %s' %
                                                       (u32_in_match, in_chain_name))
                ]

            else:
                raise Exception("Unknown peer type %s" % pr)

            if not policy_chain_name in rules:
                rules[policy_chain_name] = []
                rules[policy_chain_name].append(
                    _make_rule(policy_chain_name, '-m comment --comment PolicyId=%s -j RETURN' % policy_id))

            for r in jump_rules:
                rules[policy_chain_name].insert(0,r)

    # Loop over rules and render protocol + action part of each rules
    for r in _make_rules(policy_def.get('rules')):
        for pc in policy_chains:
            if not pc in rules:
                rules[pc] = []
        # and stuff copy of the rule into each policy chain
        rules[pc].append(_make_rule(pc,r))

    return rules


def _make_rules(policy_rules):
    """
    For each rules in policy_rules creates in/out rules in iptables_rules.

    Returns updated list of iptables_rules
    """
    # For each rule in the policy create iptables rules.
    for r in policy_rules:
        if r['protocol'] == 'TCP':
            stateful = r.get("is_stateful")
            if stateful:
                raise Exception("Flag is_stateful not implemented")
            else:
                in_rules = [ '-p tcp --dport %s -j ACCEPT' % ':'.join(str(x) for x in r["ports"]) ]

        elif r['protocol'] == 'UDP':
            in_rules =[ '-p udp --dport %s -j ACCEPT' % ':'.join(str(x) for x in r["ports"]) ]

        elif r['protocol'] == 'ICMP':
            icmp_types = r.get('icmp_type_code')
            in_rules = []
            if icmp_types:
                for icmp_type in icmp_types:
                    in_rules.append('-p icmp --icmp-type %s -j ACCEPT' % icmp_type)
            in_rules.append('-p icmp -j ACCEPT')

        elif r['protocol'] == 'any':
            in_rules = [ '-j ACCEPT' ]

        else:
            in_rules = [ '-m comment --comment error_unknownProtocol -j LOG' ]

        for in_rule in in_rules:
            yield in_rule


def _make_rule(chain_name, text):
    """
    Returns "-A <chain_name> <text>"

    """
    return "-A %s %s" % (chain_name, text)


def _make_u32_match(addr_scheme,
                    from_tenant, from_segment, to_tenant=None, to_segment=None):
    """
    Creates the obscure u32 match string with bitmasks and all that's needed.

    Something like this if all parameters are given:

    "0xc&0xff00ff00=0xa001200&&0x10&0xff00ff00=0xa001200"

    and something like this if to_tenant and to_segment are missing

    "0xc&0xff00ff00=0xa001200"

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
    if to_tenant:
        dst  |= to_tenant << shift_by

    # Adding the mask and values for segment
    shift_by = addr_scheme['endpoint_bits']
    mask |= ((1<<addr_scheme['segment_bits'])-1) << shift_by
    src  |= from_segment << shift_by
    if to_segment:
        dst  |= to_segment << shift_by

    res = "0xc&0x%(mask)x=0x%(src)x" % { "mask" : mask, "src" : src }

    if to_tenant and to_segment:
        res += "&&0x10&0x%(mask)x=0x%(dst)x" % { "mask" : mask, "dst" : dst }

    return res

def get_current_iptables():
    """
    Return the current iptables.

    """
    rules = subprocess.check_output(["iptables-save"]).split("\n")
    return rules

def delete_all_rules_for_policy(iptables_rules, policy_name, tenants):
    """
    Specify the policy name, such as 'foo'. This will delete all the rules that
    refer to anything related to this rule, such as 'ROMANA-P-foo_',
    'ROMANA-P-foo-IN_', etc.

    """
    full_names = []

    for tenant in tenants:
        tenant_id = tenant.get('tenant_network_id')
        full_names += [ 'ROMANA-T%dP-%s%s_' % (tenant_id, policy_name, p)
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
