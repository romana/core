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
import netaddr
from mimetools import Message
from StringIO import StringIO
HTTP_Unprocessable_Entity = 422

addr_scheme = {}

parser = OptionParser(usage="%prog --port --debug --dry-run")
parser.add_option('--port', default=9630, dest="port", type="int",
                  help="Port number to listen for incoming requests")
parser.add_option('--debug', default=False, dest="debug", action="store_true",
                  help="Enable debug output in the log")
parser.add_option('--dry-run', default=False, dest="dry_run", action="store_true",
                  help="Enable dry run instead of applying iptable rules.")
(options, args) = parser.parse_args()


"""
how to use dry-run:
* download policy json file using:
    wget https://raw.githubusercontent.com/romana/core/master/policy/examples/policy-service-agent.json
* run agent using following command:
    sudo agent.py --dry-run
* use curl to post using following command:
    curl -X POST -H 'Content-Type: application/json' -d @policy-service-agent.json localhost:9630
* This shows all the rules which are supposed to be installed if it wasn't a dry-run.
"""
if options.dry_run:
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S')

if options.debug:
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S')
else:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S')


# TODO errors check
def get_romana_gw_ip ():
    res = subprocess.check_output(["ip", "a", "show", "romana-gw"])
    return res.split("\n")[2].split(" ")[5]

def filter_rules_idx(rules):
    """
    Returns index of the commit rule in *filter table
    """
    filter_idx = rules.index('*filter')
    for rule_num in range(filter_idx, rules.__len__()):
        if rules[rule_num].startswith("-A") or rules[rule_num] == "COMMIT":
            return rule_num

def filter_commit_idx(rules):
    """
    Returns index of the COMMIT statement in the *filter table
    """
    filter_idx = rules.index('*filter')
    for rule_num in range(filter_idx, rules.__len__()):
        if rules[rule_num] == "COMMIT":
            return rule_num

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
            addr_scheme = policy_def["datacenter"]

            self.send_response(202)
            self.wfile.write("Policy definition accepted")

            if self.http_method == "DELETE":
                logging.warning("Deleting policy %s" % policy_def)
            else:
                logging.warning("Creating policy %s" % policy_def)

            policy_update(addr_scheme, policy_def,
                          delete_policy=(self.http_method == "DELETE"),
                          dry_run=options.dry_run)

            return
        else:
            self.send_response(HTTP_Unprocessable_Entity)
            self.wfile.write(""" Failed to validate policy definition """)


    def validate_policy(self, policy_def):
        """
        Checks that some top level sections are present in the policy.
        """
        expected_fields = [ "name", "applied_to", "ingress", "datacenter" ]
        if not all([ policy_def.get(k) for k in expected_fields ]):
            logging.warning("In validate_policy, policy is invalid - some of expected fields are missing, %s" % expected_fields)
            return False


        # Validating compatibility across applied_to and peers list.
        valid = {
                "full_tenant" : [ "peer_any", "full_tenant", "cidr" ],
                "only_tenant" : [ "peer_any", "full_tenant", "cidr" ],
                "dest_host"        : [ "peer_local", "peer_any" ],
                "dest_local"       : [ "peer_host", "peer_any"  ],
                }

        target_types = []
        peer_types = []
        for target in policy_def['applied_to']:
            tenant         = target.get('tenant_network_id')
            target_segment = target.get('segment_network_id')
            dest           = target.get('dest')

            if not None in [ tenant, target_segment ]:
                target_type = "full_tenant"
            elif tenant is not None:
                target_type = "only_tenant"
            elif dest is not None:
                target_type = "dest_%s" % dest
            else:
                raise Exception("Unsupported value of applied_to %s" % target)

            target_types.append(target_type)

        for ingress in policy_def['ingress']:
          for peer in ingress['peers']:
              tenant  = peer.get('tenant_network_id')
              segment = peer.get('segment_network_id')
              peer_t  = peer.get('peer')
              cidr    = peer.get('cidr')
  
              if not None in [ tenant, segment ]:
                  peer_type = "full_tenant"
              elif tenant is not None:
                  peer_type = "only_tenant"
              elif peer_t is not None:
                  peer_type = "peer_%s" % peer_t
              elif cidr is not None:
                  peer_type = "cidr"
              else:
                  # supported peer types are local, host and any as in L543-L553
                  raise Exception("Unsupported value of peers %s" % peer)

              peer_types.append(peer_type)

        logging.info("In validate_policy with applied_to %s and peers %s" % (target_types, peer_types))
        for target in target_types:
            for peer in peer_types:
                if peer not in valid[target]:
                    raise Exception("Unsupported value of peer type %s with applied_to type %s" % (peer, target))

        return True


    def decode_request(self):
        """
        Parses json from POST
        """
        self.send_header('Content-type','text/html')
        self.end_headers()
        headers = Message(StringIO(self.headers))
        try:
            self.raw_data = self.rfile.read(int(headers["Content-Length"]))
            self.json_data = simplejson.loads(self.raw_data)
        except Exception, e:
            logging.warning("Cannot parse %s" % self.raw_data)
            return


def policy_update(romana_address_scheme,
                  policy_definition,
                  delete_policy=False,
                  dry_run=False):
    """
    Using the romana address scheme and a policy definition as input,
    create a new set of iptables rules and apply them.

    NOTE! Since we do get/edit/write in separate steps, it would be possible
    for someone else to clobber the rules before we have a chance to write
    this. A lock of of some sort, or an otherwise atomic operation needs to be
    implemented here. TODO!

    """

    # PolicyId is a uniq tag that we are going to use to check if rule is applied already
    policy_id      = policy_definition['external_id']

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
                                policy_id,
                                policy_definition['applied_to'])

    if delete_policy:
        if not dry_run:
            apply_new_ruleset(clean_rules)
        return

    # Create a new rule set that can be applied to iptables
    rules = make_new_full_ruleset(clean_rules, new_rules)

    if not dry_run:
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

    # In current rules find "sweet spot" position in *filter table
    # where chain definition ends.
    filter_idx = filter_rules_idx(current_rules)
    sweet_spot_offset = 0

    rules = []
    backlog_rules = []
    top_rules = []

    # We only care about *filter table, copy everything before it.
    for rule in current_rules[:filter_idx]:
        rules.append(rule)

    # Insert new chains if they don't exist already.
    for chain in new_rules.keys():
        if chain not in existing_chains:
            rules.append(":%s - [0:0]" % chain)

            # Maintain filter_idx to be pointing
            # at the sweet spot as it moves with
            # new chains added
            sweet_spot_offset += 1


    # Insert all the rules from all new chains, if they don't exist already.
    for chain in new_rules.keys():
        for rule in new_rules[chain]:
            # Special handling for DefaultDrop rules
            if 'DefaultDrop' in rule:
                backlog_rules.append(rule)
                continue

            # Special handling for the rules that
            # must go on top of the chains
            if 'ESTABLISHED' in rule:
                top_rules.append(rule)
                continue

            if rule not in current_rules:
                rules.append(rule)

    # Copy the rest of original *filter table.
    for rule in current_rules[filter_idx:]:
        # Special handling for DefaultDrop rules.
        if 'DefaultDrop' in rule:
            backlog_rules.append(rule)
            continue

        # Special handling for the rules that
        # must go on top of the chains.
        if 'ESTABLISHED' in rule:
            top_rules.append(rule)
            continue

        rules.append(rule)

    # Insert top_rules in to the sweet spot.
    for rule in set(top_rules):
        rules.insert(filter_idx + sweet_spot_offset, rule)

    # Add 'DefaultDrop' rules to the end of the list to ensure they go last.
    for rule in set(backlog_rules):
        rules.insert(filter_commit_idx(rules), rule)

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
    name = policy_def['external_id']
    for target in policy_def['applied_to']:
        tenant         = target.get('tenant_network_id')
        target_segment = target.get('segment_network_id')
        dest           = target.get('dest')

        logging.warning("In make_rules with tenant = %s, target_segment_id = %s, name = %s" %
                (tenant, target_segment, name))

        # Traffic flows through per-tenant policy chain into
        # per-segment policy chains and from there into policy chains.
        # Unless one of policy chains will ACCEPT the packet it will RETURN
        # to the per-tenant chain and will reach DROP at the end of the chain.


        if tenant is not None:
            # Per tenant policy chain name.
            tenant_policy_vector_chain = "ROMANA-FW-T%s" % tenant

            # Tenant wide policy vector chain hosts jumps to the policies
            # applied to a tenant traffic as well as default rules.
            tenant_wide_policy_vector_chain = "ROMANA-T%s-W" % tenant

            # Ingress chain for traffic between VMs
            ingress_chain = "ROMANA-FORWARD-IN"

        elif dest == 'local':
            # Top level chain for ingress traffic between VMs, applied to all tenants.
            tenant_wide_policy_vector_chain = "ROMANA-OP"

            # Ingress chain for traffic between VMs
            ingress_chain = "ROMANA-FORWARD-IN"

        elif dest == 'host':
            # Top level chain for ingress traffic between host and VMs
            tenant_wide_policy_vector_chain = "ROMANA-OP-IN"

            # Ingress chain for traffic between VMs
            ingress_chain = "ROMANA-INPUT"

        else:
            raise Exception("Unsupported value of applied_to %s" % target)


        # Per segment policy chain to host jumps to the actual policy chains.
        if target_segment is not None:
            target_segment_forward_chain = "ROMANA-T%s-S%s" % \
                (tenant, target_segment)
        else:
            # If segment_network_id not provided in the policy,
            # consider policy to be tenant wide.
            target_segment_forward_chain = tenant_wide_policy_vector_chain



        # The name for the new policy's chain(s).
        policy_chain_name = "ROMANA-P-%s_" % \
            name

        # There could be either 1 or 2 jumps.
        # When crating a policy for tenant there will be a jump from ingress chain
        # into tenant chains followed by jump from tenant chain into the segment chains
        # or into tenant-wide chain if policy is applied to all the segments.
        # However, when creating a policy for host-VM traffic (aka operator policy)
        # there will be only one jump - from ingress chain into operator chain.
        if tenant is not None:
            # Jump from ingress VM chain into per-tenant chain
            u32_tenant_match = _make_u32_match(addr_scheme, to_tenant=tenant)
            rules[ingress_chain] = [
                _make_rule(ingress_chain, '-m u32 --u32 "%s" -j %s' % (u32_tenant_match, tenant_policy_vector_chain)),
                _make_rule(ingress_chain, "-m comment --comment DefaultDrop -j %s" % "DROP")
            ]

            # Jump from per-tenant chain into per-segment chains.
            if target_segment is not None:
                # NOTE: We are adding a segment-specific address check to the
                # rule, which jumps into the segment-specific policy chain.
                # This works as long as we have ingress rules, where the
                # segment in question is identified by the destination address.
                # Once we add egress rules, this needs to be revisited!
                u32_segment_match = _make_u32_match(addr_scheme, to_tenant=tenant, to_segment=target_segment)
                u32_match_str     = '-m u32 --u32 "%s" ' % u32_segment_match
            else:
                u32_match_str     = ""

            rules[tenant_policy_vector_chain] = [
                _make_rule(tenant_policy_vector_chain, "%s-j %s" % (u32_match_str, target_segment_forward_chain)),
                _make_rule(tenant_policy_vector_chain, "-j %s" % tenant_wide_policy_vector_chain),
            ]
        else:
            # Jump from ingress chain into operator chain.
            rules[ingress_chain] = [
                _make_rule(ingress_chain, "-j %s" % target_segment_forward_chain),
                _make_rule(ingress_chain, "-m comment --comment DefaultDrop -j %s" % "DROP")
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

        ingress_count = 0
        for ingress in policy_def['ingress']:
          ingress_count += 1

          # Policy chain only hosts match conditions, rules themselves are
          # applied in this auxiliary chain
          in_chain_name  = policy_chain_name[:-1] + "-IN_" + str(ingress_count)
  
          # Chain names are going to be used later to fill in the rules. Store them.
          policy_chains[in_chain_name] = True
  
  
          # Loop over peers and fill top level policy chains with source matching rules
          for peer in ingress['peers']:
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
  
                  elif pr == "host":
                      jump_rules = [ _make_rule(policy_chain_name, "-s %s -j %s") % (get_romana_gw_ip().split('/')[0], in_chain_name) ]
  
                  elif pr == "local":
                      jump_rules = [ _make_rule(policy_chain_name, "-j %s") % (in_chain_name) ]
  
                  else:
                      raise Exception("Unsupported value of peer %s" % pr)
  
              elif cidr:
                  jump_rules = [ _make_rule(policy_chain_name, "-s %s -j %s") % (cidr, in_chain_name) ]
  
              elif not None in [ from_segment, from_tenant ]:
                  u32_in_match = _make_u32_match(addr_scheme, from_tenant=from_tenant, from_segment=from_segment)
                  jump_rules = [
                      _make_rule(policy_chain_name, '-m u32 --u32 "%s" -j %s' %
                                                         (u32_in_match, in_chain_name))
                  ]
  
              else:
                  raise Exception("Unknown peer type %s" % peer)
  
              if not policy_chain_name in rules:
                  rules[policy_chain_name] = []
                  rules[policy_chain_name].append(
                      _make_rule(policy_chain_name, '-m comment --comment PolicyId=%s -j RETURN' % policy_id))
  
              for r in jump_rules:
                  rules[policy_chain_name].insert(0,r)
  
          # peer loop above filled policy_chains with chain names,
          # for each name in policy_chains there need to be a list in rules.
          for pc in policy_chains:
            if not pc in rules:
              rules[pc] = []

          # Loop over rules and render protocol + action part of each rule
          for r in _make_rules(ingress['rules']):
          # and stuff copy of the rule into each policy chain
            rules[in_chain_name].append(_make_rule(in_chain_name,r))
  
    return rules


def _make_rules(policy_rules):
    """
    For each rule in policy_rules creates in/out rules in iptables_rules.

    Returns updated list of iptables_rules
    """
    # For each rule in the policy create iptables rules.
    in_rules = []
    for r in policy_rules:
        if r['protocol'].upper() == 'TCP':
            stateful = r.get("is_stateful")
            if stateful:
                raise Exception("Flag is_stateful not implemented")

            if r.get('ports'):
                for port in r.get("ports"):
                    in_rules += [ '-p tcp --dport %s -j ACCEPT' % port ]

            if r.get('port_ranges') and (len(r.get('port_ranges')) > 0):
                # TODO: Multiple port ranges should be supported here
                #       as policy service does, temporarily use the first
                #       in the range provided.
                port_range = r.get('port_ranges')[0]
                if len(port_range) == 2:
                    in_rules += [ '-p tcp --dport %s:%s -j ACCEPT' % (port_range[0], port_range[1]) ]
                else:
                    raise Exception("Protocol option port_range must be a list of 2 elements - got %s" % port_range)

            if not(r.get('ports') or r.get('port_ranges')):
                in_rules += [ '-p tcp -j ACCEPT' ]

        elif r['protocol'].upper() == 'UDP':
            if r.get('ports'):
                for port in r.get("ports"):
                    in_rules += [ '-p udp --dport %s -j ACCEPT' % port ]

            if r.get('port_ranges') and (len(r.get('port_ranges')) > 0):
                # TODO: Multiple port ranges should be supported here
                #       as policy service does, temporarily use the first
                #       in the range provided.
                port_range = r.get('port_ranges')[0]
                if len(port_range) == 2:
                    in_rules += [ '-p udp --dport %s:%s -j ACCEPT' % (port_range[0], port_range[1]) ]
                else:
                    raise Exception("Protocol option port_range must be a list of 2 elements - got %s" % port_range)

            if not(r.get('ports') or r.get('port_ranges')):
                in_rules += [ '-p udp -j ACCEPT' ]

        elif r['protocol'].upper() == 'ICMP':
            icmp_type = r.get('icmp_type')
            icmp_code = r.get('icmp_code')
            in_rules = []
            if icmp_type and icmp_code:
                in_rules.append('-p icmp --icmp-type %s/%s -j ACCEPT' % (icmp_type, icmp_code))
            elif icmp_type:
                in_rules.append('-p icmp --icmp-type %s -j ACCEPT' % icmp_type)
            else:
                in_rules.append('-p icmp -j ACCEPT')

        elif r['protocol'].upper() == 'ANY':
            in_rules = [ '-j ACCEPT' ]

        else:
            raise Exception("Unknown protocol - known protocols are UDP,TCP,ICMP,ANY - got %s" % r['protocol'])

        for in_rule in in_rules:
            yield in_rule


def _make_rule(chain_name, text):
    """
    Returns "-A <chain_name> <text>"

    """
    return "-A %s %s" % (chain_name, text)


def _make_u32_match(addr_scheme,
                    from_tenant=None, from_segment=None,
                    to_tenant=None, to_segment=None):
    """
    Creates the obscure u32 match string with bitmasks and all that's needed.

    Something like this if all parameters are given:

    "0xc&0xff00ff00=0xa001200&&0x10&0xff00ff00=0xa001200"

    and something like this if to_tenant and to_segment are missing

    "0xc&0xff00ff00=0xa001200"

    """
    src_mask = dst_mask = src = dst = 0

    # Take network bits from Romana CIDR. e.g. 10.0.0.0/8
    #                                                   ^
    network_width = int(addr_scheme["cidr"].split("/")[-1])

    # Full match on net portion.
    # NOTE: 'port_bits' are the equivalent of 'host bits'. This value comes
    # from the 'datacenter' structure, which uses port-bits as identifiers
    # for ports in ToRs. Therefore, the port and host bits are in fact the
    # same.
    shift_by = ( addr_scheme['tenant_bits']
               + addr_scheme['segment_bits']
               + addr_scheme['endpoint_bits']
               + addr_scheme['port_bits'] )
    net_portion_mask    = ((1<<network_width)-1) << shift_by
    src_mask = dst_mask = net_portion_mask  # both start out the same

    cidr_as_num = int(netaddr.IPAddress(addr_scheme["cidr"].split("/")[0]))

    # Take first bits of the address to get the network
    # value from the IP address: e.g. 10.128.0.0/9 -> just the first 9 bits
    # src and dst start out the same and will subsequently be modified.
    src = dst = cidr_as_num & net_portion_mask

    # Leaving the host portion empty...

    # Adding the mask and values for tenant
    shift_by = addr_scheme['segment_bits'] + addr_scheme['endpoint_bits']
    if from_tenant is not None:
        src_mask |= ((1<<addr_scheme['tenant_bits'])-1) << shift_by
        src  |= from_tenant << shift_by
    if to_tenant is not None:
        dst_mask |= ((1<<addr_scheme['tenant_bits'])-1) << shift_by
        dst  |= to_tenant << shift_by

    # Adding the mask and values for segment
    shift_by = addr_scheme['endpoint_bits']
    if from_segment is not None:
        src_mask |= ((1<<addr_scheme['segment_bits'])-1) << shift_by
        src  |= from_segment << shift_by
    if to_segment is not None:
        dst_mask |= ((1<<addr_scheme['segment_bits'])-1) << shift_by
        dst  |= to_segment << shift_by

    from_rule = "0xc&0x%(mask)x=0x%(src)x"  % { "mask" : src_mask, "src" : src }
    to_rule   = "0x10&0x%(mask)x=0x%(dst)x" % { "mask" : dst_mask, "dst" : dst }

    if not None in [ to_tenant, from_tenant ]:
        res = "%(from)s&&%(to)s" % { "from" : from_rule, "to" : to_rule }
    elif to_tenant is not None:
        res = to_rule
    elif from_tenant is not None:
        res = from_rule
    else:
        raise "At least one of from_tenant or to_tenant must be provided"

    return res

def get_current_iptables():
    """
    Return the current iptables.

    """
    rules = subprocess.check_output(["iptables-save"]).split("\n")
    return rules

def delete_all_rules_for_policy(iptables_rules, policy_name, tenants):
    """
    Specify the policy name, such as 'foo' and a list of tenants.
    This will delete all the rules that refer to anything related
    to this rule, such as 'ROMANA-P-foo_', 'ROMANA-P-foo-IN_' for each tenant.

    """

    # Some dirty logs. No need to run all this loops if logging level less then DEBUG
    if logging.getLevelName(logging.getLogger().getEffectiveLevel()) == 'DEBUG':
        logging.debug("In delete_all_rules_for_policy")
        for i, line in enumerate(iptables_rules):
            logging.debug("Current rules --> line %3d : %s" % (i,line))

    full_names = []

    full_names += [ 'ROMANA-P-%s%s_' % (policy_name, p)
                        for p in [ "", "-IN", "-OUT" ] ]

    logging.debug("In delete_all_rules_for_policy -> deleteing policy chains %s" % full_names)

    # Only transcribe those lines that don't mention any of the chains
    # related to the policy.
    clean_rules = [ r for r in iptables_rules if not
                            any([ p in r for p in full_names ]) ]

    # Some dirty logs. No need to run all this loops if logging level less then DEBUG
    if logging.getLevelName(logging.getLogger().getEffectiveLevel()) == 'DEBUG':
        logging.debug("In delete_all_rules_for_policy")
        for i, line in enumerate(clean_rules):
            logging.debug("Clean rules --> line %3d : %s" % (i,line))


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
        logging.info("@@@ ERROR applying iptables: %s " % err)
        return False
    else:
        logging.info("@@@ iptables rules successfully applied.")
        return True

def run_agent():
    server = HTTPServer(('', options.port), AgentHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_agent()
