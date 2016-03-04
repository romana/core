#
# Execution flow chart
#
#
# +------------+    +----------+    +---------------+
# | Namespaces |<---| Kube API |--->|NetworkPolicies|
# +------------+    +----------+    +---------------+
#     |                                     |
#     |   <------   HTTP GET  ------->      |
#     v                                     v
# +------------------+     +------------------------+
# | watch_namespaces |---->| watch_network_policies*|
# +------------------+     +------------------------+
#     ^      |                              |        
#     |      |                        on add/delete NP
#     |      |                              |        
#     |      |                              v        
#     |      |  on delete NS             +----------+
#     |      +-------------------------->| np_queue |
#     |                                  +----------+
#     |                                     |       
#     |                                     |        
#     |                                     v        
# +--------+             +--------------------------+
# |listener|             | network_policy_processor*|
# +--------+             +--------------------------+
#
# Legend:
# * - subprocess
#
import httplib
import requests
import sys
import simplejson
import subprocess
from optparse import OptionParser
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from mimetools import Message
from StringIO import StringIO
import logging
from multiprocessing import Process, Lock, Queue
PORT_NUMBER = 9630
HTTP_Unprocessable_Entity = 422
np_queue = Queue()

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S')

url = 'http://192.168.0.10:8080/apis/romana.io/demo/v1/namespaces/default/networkpolicys/?watch=true'
ns_url = 'http://192.168.0.10:8080/api/v1/namespaces/?watch=true'
tenant_url = 'http://192.168.0.10:9602/tenants'
topology_url = "http://192.168.0.10:9603/hosts"

# For each namespace discovered in kubernetes we need to fire up
# a subprocess. This dict is to keep account in suborocesses which
# are running. k = namespacename, v = proc
listen_pool = {}

parser = OptionParser(usage="%prog --agent")
parser.add_option('--agent', default=False, dest="agent", action="store_true",
                  help="Act as agent for the Kubernetes listener")
(options, args) = parser.parse_args()

def network_policy_url(ns_name):
    return 'http://192.168.0.10:8080/apis/romana.io/demo/v1/namespaces/' + ns_name + '/networkpolicys/?watch=true'

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

    # Full match on net portion.
    mask = ((1<<addr_scheme['network_width'])-1) << 24
    src  = addr_scheme['network_value'] << 24
    dst  = addr_scheme['network_value'] << 24

    # Leaving the host portion empty...

    # Adding the mask and values for tenant
    shift_by = addr_scheme['segment_width'] + addr_scheme['endpoint_width']
    mask |= ((1<<addr_scheme['tenant_width'])-1) << shift_by
    src  |= from_tenant << shift_by
    dst  |= to_tenant << shift_by

    # Adding the mask and values for segment
    shift_by = addr_scheme['endpoint_width']
    mask |= ((1<<addr_scheme['segment_width'])-1) << shift_by
    src  |= from_segment << shift_by
    dst  |= to_segment << shift_by

    return "0xc&0x%(mask)x=0x%(src)x&&0x10&0x%(mask)x=0x%(dst)x" % \
        { "mask" : mask, "src" : src, "dst" : dst }


def make_rules(addr_scheme, policy_def, policy_id):
    """
    Return dictionary with rules that should be pre-pended to given chains.

    The chain names are the keys to the dict, the values are lists of rules.

    """
    rules = {}
    tenant         = policy_def['owner_tenant_id']
    target_segment = policy_def['target_segment_id']
    from_segment   = policy_def['allowFrom']['segment_id']

    # The name for the new policy's chain(s). Need to include the tenant ID to
    # avoid name conflicts.
    policy_chain_name = "ROMANA-T%dP-%s_" % \
        (policy_def['owner_tenant_id'], policy_def['policy_name'])

    # This policy needs to be processed in the forward chain of both interfaces
    # that are involved.
    target_segment_forward_chain = "ROMANA-T%sS%s-FORWARD" % \
        (tenant, target_segment)
    from_segment_forward_chain = "ROMANA-T%sS%s-FORWARD" % \
        (tenant, from_segment)

    rules[target_segment_forward_chain] = [
        _make_rule(target_segment_forward_chain, "-j %s" % policy_chain_name)
    ]
    rules[from_segment_forward_chain] = [
        _make_rule(from_segment_forward_chain, "-j %s" % policy_chain_name)
    ]

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

    # Assemble the rules for the port/protocol portion of the policy.
    # Note! We currently only support TCP with a given port. No ICMP and no
    # UDP!

    rules[in_chain_name] = [
        _make_rule(in_chain_name,
                   '-p tcp --dport %d --tcp-flags SYN SYN -j ACCEPT' %
                   policy_def['allowFrom']['port']),
        _make_rule(in_chain_name,
                   '-m state --state ESTABLISHED -j ACCEPT'),
        _make_rule(in_chain_name, '-j RETURN')
    ]

    rules[out_chain_name] = [
        _make_rule(out_chain_name,
                   '-p tcp --sport %d --tcp-flags SYN,ACK SYN,ACK -j ACCEPT' %
                   policy_def['allowFrom']['port']),
        _make_rule(out_chain_name,
                   '-m state --state ESTABLISHED -j ACCEPT'),
        _make_rule(out_chain_name, '-j RETURN')
    ]

    return rules

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


def make_new_full_ruleset(current_rules, new_rules):
    """
    Prepends the specified rules in the given chains, if they exist.

    If not, creates the chains.

    Return a new, augmented list of rules, ready to replace the old rules.

    """
    # Start by creating the chains. They are all in the 'filter' section.  The
    # only rules we need to define are the policy rules, which all end with a
    # '_'. The other entries are for existing chains (such as
    # 'ROMANA-T1S2-FORWARD'), so we don't need to define them again.
    new_chains_to_declare = [ k for k in new_rules.keys() if k.endswith('_') ]
    existing_chains = [ k for k in new_rules.keys() if not k.endswith('_') ]

    rules = []
    new_chains_declared = False
    new_rules_defined   = False

    for r in current_rules:
        # The definition of the new chains happens first, towards the top of
        # the rules in the '*filter' section.
        if not new_chains_declared:
            rules.append(r)
            if r == "*filter":
                for c in new_chains_to_declare:
                    rules.append(":%s - [0:0]" % c)
                new_chains_declared = True
            continue

        # Now continue and find the entries of those rules that
        # existed already (such as 'ROMANA-T1S2-FORWARD').
        for i, c in enumerate(existing_chains):
            if r.startswith("-A %s" % c):
                # This is a good place to define the rules for the new chains,
                # if this wasn't done already.
                if not new_rules_defined:
                    for nc in new_chains_to_declare:
                        # For each of the new chains we have a list of rules we
                        # need to define.
                        for nr in new_rules[nc]:
                            rules.append(nr)
                    new_rules_defined = True
                # We pre-pend the rules we have for the existing rule.
                for nr in new_rules[c]:
                    rules.append(nr)
                # We only need to perform any rule insertion at the first
                # occurrence of the chain, so we keep track of whether we
                # dealt with it already or not and skip if we have.
                existing_chains.pop(i)  # We dealt with this chain already
                break

        rules.append(r)

    return rules


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
        logging.info("@@@ ERROR applying iptables: ", err)
        return False
    else:
        logging.info("@@@ iptables rules successfully applied.")
        return True



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
    policy_id      = "%s/%s" % ( policy_definition['policy_name'], policy_definition['policy_namespace'] )

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
                                    policy_definition['policy_name'],
                                    policy_definition['owner_tenant_id'])

    if delete_policy:
        apply_new_ruleset(clean_rules)
        return


    # Create a new rule set that can be applied to iptables
    rules = make_new_full_ruleset(clean_rules, new_rules)

    apply_new_ruleset(rules)

    # LOCK SECTION SHOULD END HERE...


def parse_rule_specs(obj):
    """
    Parse out data from kubernetes original policy specification
    """
    try:
        rule = {}
        rule["src_tenant"] = obj["object"]["metadata"]["labels"]["owner"]
        rule["dst_tenant"] = rule["src_tenant"]
        rule["dst_segment"] = obj["object"]["spec"]["podSelector"]["tier"]
        rule["src_segment"] = obj["object"]["spec"]["allowIncoming"]["from"][0]["pods"]["tier"]
        rule["port"] = obj["object"]["spec"]["allowIncoming"]["toPorts"][0]["port"]
        rule["protocol"] = obj["object"]["spec"]["allowIncoming"]["toPorts"][0]["protocol"]
        return rule
    except Exception, e:
        logging.info("Cannot parse %s: %s" % (obj, e))
        return None

def get_tenants():
    """
    Returns romana tenants description

    Example:
        [{"Id":1,"Name":"t1","Segments":null,"Seq":1},{"Id":2,"Name":"t2","Segments":null,"Seq":2}]
    """
    try:
        r = requests.get(tenant_url)
        logging.info('Tenants service returned %s' % r.content)
        tenants = simplejson.loads(r.content)
    except Exception as e:
        logging.info("Failed to fetch romana tenants %s" % e)
        return None
    return tenants

def get_tenant_id_by_name(name, tenants):
    """
    Returns romana tenant id
    Example : 1
    """
    for tenant in tenants:
        if tenant['Name'] == name:
            return tenant['Id']
    return None

def get_segments(tenant_id):
    """
    Returns a list of romana segments for particular tenant

    Example:
    [{"Id":1,"TenantId":1,"Name":"default","Seq":1},{"Id":3,"TenantId":1,"Name":"frontend","Seq":2},{"Id":4,"TenantId":1,"Name":"backend","Seq":3}]
    """
    try:
        r = requests.get(tenant_url + '/' + str(tenant_id) + '/segments')
        segments = simplejson.loads(r.content)
    except Exception as e:
        logging.info("Failed to fetch romana segments %s" % e)
        return None
    return segments

def get_segment_id_by_name(name, segments):
    """
    Returns romana segment id
    Example : 1
    """
    for segment in segments:
        if segment['Name'] == name:
            return segment['Seq']

# TODO should probably discover this from romana root
addr_scheme = {
    "network_width" : 8,
    "host_width" : 8,
    "tenant_width" : 4,
    "segment_width" : 4,
    "endpoint_width" : 8,

    "network_value" : 10,
}

def process_namespaces(s):
    """
    Processing kubernetes namespace ADD/DELETE events
    Firing up subprocess for each ADD event or terminating
    subprocess already running on DELETE
    """

    try:
        obj = simplejson.loads(s)
    except Exception as e:
        logging.warning("Failed to parse %s as json %s" %(s,e))
        return

    op = obj.get("type")
    if not op:
        logging.warning("Failed to parse event type from out of %s" % obj)
        return

    resource = obj.get("object")
    if not resource:
        logging.warning("Failed to parse object out of %s" % obj)
        return

    meta = resource.get("metadata")
    if not meta:
        logging.warning("Failed to parse metadata from out of %s" % resource)
        return

    ns_name = meta.get("name")
    if not ns_name:
        logging.warning("Failed to parse namespace name out of %s" % obj)
        return

    ns_uid = meta.get("uid")
    if not ns_uid:
        logging.warning("Failed to parse namespace uid out of %s" % obj)
        return

    logging.debug("In process_namespace:: operation=%s" % op)
    if op == 'ADDED':
        ensure_ns_watcher_running(ns_uid, ns_name)
    elif op == 'DELETED':
        ensure_ns_watcher_stopped(ns_uid, ns_name)
        np_processor_send_cleanup(ns_name)
    else:
        # Ignore MODIFIED event
        pass

def np_processor_send_cleanup(ns_name):
    """
    Used to notify policy processor of deleted namespace
    so it could delete outdated policies
    """
    message = { "type" : "NS_CLEANUP", "namespace": ns_name }
    np_queue.put_nowait(simplejson.dumps(message))

def start_new_np_watcher(ns_uid, ns_name):
    logging.debug("In start_new_np_watcher:: with ns_uid = %s, ns_name = %s ... begin" % (ns_uid, ns_name))
    # np_queue available globally in this context
    new_ns_proc = Process(target=watch_network_policies, args=(ns_name,np_queue,))
    new_ns_proc.start()
    listen_pool[ns_uid] = new_ns_proc
    logging.debug("In start_new_np_watcher:: with ns_uid = %s, ns_name = %s ... finishing" % (ns_uid, ns_name))

def ensure_ns_watcher_running(ns_uid, ns_name):
    """
    Starting new subprocess to process network policies for
    given namespace.
    List of known active subprocesses is stored in global
    listen_pool dictionary.
    """

    logging.debug("In ensure_ns_watcher_running:: ")
    ns_proc = listen_pool.get(ns_uid)

    logging.debug("In ensure_ns_watcher_running:: ns_proc=%s" % ns_proc)
    if ns_proc:
        if not ns_proc.is_alive():
            ns_proc.terminate()
            start_new_np_watcher(ns_uid, ns_name)
            logging.debug("In ensure_ns_watcher_running:: ns_proc is not alive")
        else:
            logging.debug("In ensure_ns_watcher_running:: ns_proc is alive")
            # all good - do nothing
            return
    else:
        logging.debug("In ensure_ns_watcher_running:: there is no such process in process pool - starting new one")
        start_new_np_watcher(ns_uid, ns_name)

def ensure_ns_watcher_stopped(ns_uid, ns_name):
    """
    Terminating subprocess for given namespace.
    Removing subprocess object from global listen_pool
    """

    logging.debug("In ensure_ns_watcher_stopped:: ")
    ns_proc = listen_pool.get(ns_uid)
    logging.debug("In ensure_ns_watcher_stopped:: ns_proc=%s" % ns_proc)
    if ns_proc:
        if ns_proc.is_alive():
            logging.debug("In ensure_ns_watcher_stopped:: ns_proc is alive - terminating")
            ns_proc.terminate()
        del listen_pool[ns_uid]

# Processing kubernetes events coming from api
def process(s, uid_by_ns, pd_by_uid):

    # Kube api listener is a GET request which will timeout eventually
    # producing empty request.
    try:
        obj = simplejson.loads(s)
    except Exception as e:
        logging.info("====== could not parse:")
        logging.info(s)
        logging.info("@@@@ Error: %s" % str(e))
        return
    op = obj.get("type")
    if not op:
        logging.warning("Failed to parse event type from out of %s" % obj)
        return

    if op == 'NS_CLEANUP':
        ns = obj.get("namespace")
        for uid in uid_by_ns[ns]:
            dispatch_orders('DELETED', pd_by_uid[uid])
            del pd_by_uid[uid]
            uid_by_ns[ns].remove(uid)
        return

    rule = parse_rule_specs(obj)
    if not rule:
        logging.warning("Failed to parse network policy rules out of %s" % obj)
        return

    # Resolving romana tags found in original policy request
    # into values known to romana
    tenants = get_tenants()
    if not tenants:
        logging.warning("Failed to to process even %s - skipping" % obj)
        return
    logging.info("Discovered tenants = %s" % tenants)
    tenant_id = get_tenant_id_by_name(rule['src_tenant'], tenants)
    if not tenant_id:
        logging.warning("Failed to resolve tenant_id for tenant %s - skipping event %s" % (rule['src_tenant'], obj))
        return
    logging.info("Discovered tenant_id = %s" % tenant_id)
    segments = get_segments(tenant_id)
    if not segments:
        logging.warning("Failed to resolve segments for tenant %s - skipping event %s" % (rule['src_tenant'], obj))
        return
    logging.info("Discovered segments = %s" % segments)
    src_segment_id = get_segment_id_by_name(rule['src_segment'], segments)
    logging.info("Discovered src_segment_id = %s" % src_segment_id)
    dst_segment_id = get_segment_id_by_name(rule['dst_segment'], segments)
    logging.info("Discovered dst_segment_id = %s" % dst_segment_id)

    # That should be a romana policy object.
    policy_definition = {
        "policy_name" : obj['object']['metadata']['name'],
        "policy_namespace" : obj['object']['metadata']['namespace'],
        "owner_tenant_id" : tenant_id,
        "target_segment_id" : dst_segment_id,
        "allowFrom" : {
            "segment_id" : src_segment_id,
            "protocol" : "tcp",
            "port" : obj['object']['spec']['allowIncoming']['toPorts'][0]['port']
        }
    }

    ns = obj['object']['metadata']['namespace']
    uid = obj['object']['metadata']['uid']
    if op == 'ADDED':
        if not uid_by_ns.get(ns):
            uid_by_ns[ns]=[]
        if uid not in uid_by_ns[ns]:
            uid_by_ns[ns].append(uid)
        if uid not in pd_by_uid.keys():
            pd_by_uid[uid]=policy_definition
    elif op == 'DELETED':
        if uid in uid_by_ns[ns]:
            uid_by_ns[ns].remove(uid)
        if uid in pd_by_uid.keys():
            del pd_by_uid[uid]

    dispatch_orders(op, policy_definition)

def dispatch_orders(method, policy_definition):
    """
    Kicks listener agents on every romana host
    Expects:
      method as a string ADDED|DELETED
      policy_definition as a dict
    """
    for host in get_romana_hosts():
        data = {}
        data["method"] = method
        data["policy_definition"] = policy_definition
        logging.info("Attempting to send %s to %s" % (data, host))
        try:
            requests.post("http://" + host + ":" + str(PORT_NUMBER), data=simplejson.dumps(data))
        except Exception, e:
            logging.info("Cannot sontact host %s: %s" % (host, e))

def listen_chunked_stream(watch_url, submit_type, submit_object):
    r = requests.get(watch_url, stream=True, timeout=300)
    iter = r.iter_content(1)
    while True:
        len_buf = ""
        while True:
            c = iter.next()
            if c == "\r":
                c2 = iter.next()
                if c2 != "\n":
                    raise "Unexpected %c after \\r" % c2
                break
            else:
                len_buf += c
        len = int(len_buf, 16)
        #        logging.info("Chunk %s" % len)
        buf = ""
        for i in range(len):
            buf += iter.next()
        if submit_type == 'callback':
            submit_object(buf)
        elif submit_type == 'queue':
            submit_object.put_nowait(buf)
        c = iter.next()
        c2 = iter.next()
        if c != '\r' or c2 != '\n':
            raise "Expected CRLF, got %c%c" % (c, c2)

def watch_namespaces():
    """
    This function watches for events in kubernetes regarding namespaces
    and passes the events for processing

    Never exits
    """
    while True:
        try:
            submit_type = 'callback'
            submit_object = process_namespaces
            listen_chunked_stream(ns_url, submit_type, submit_object)
        except Exception, e:
            logging.info("Kube api namespace listener terminated with: %s keep going" % str(e))

def watch_network_policies(ns_name, np_queue):
    while True:
        try:
            ns_url = network_policy_url(ns_name)
            submit_type = 'queue'
            submit_object = np_queue
            listen_chunked_stream(ns_url, submit_type, submit_object)
        except Exception, e:
            logging.info("Kube api listener terminated with: %s " % str(e))

def network_policy_processor(np_queue):
    uid_by_ns = {}
    pd_by_uid = {}
    while True:
        try:
            process(np_queue.get(), uid_by_ns, pd_by_uid)
        except Exception, e:
            logging.info("Network policy processor error: %s " % str(e))

# Watch kubernetes events, they come as chunks
# so we need to process them chunk by chink
def main():
    np_processor = Process(target=network_policy_processor, args=(np_queue,))
    np_processor.start()
    watch_namespaces()

def get_romana_hosts():
    """
    returns a list of romana host IPs
    
    Example: ["10.0.0.1", 10.1.0.1" ]
    """

    romana_hosts = []
    try:
        r = requests.get(topology_url)
        logging.info('Topology service returned %s' % r.content)
        hosts = simplejson.loads(r.content)
    except Exception, e:
        logging.info("Failed to fetch romana hosts %s" % e)
        return None

    # romana_ip is a CIDR like 10.0.0.1/16
    # we only want ip part
    for host in hosts:
        mask_idx = host["romana_ip"].index("/")
        romana_hosts.append(host["romana_ip"][:mask_idx])
    return romana_hosts

# We want to receive json object as a POST.
class AgentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        # Send the html message
        self.wfile.write("Romana kubernetes listener")
        return

    def do_POST(self):
        """
        Processes POST requests
        extracts romana policy definition objects and passes it down for implementation
    
        Expected structure: { "method" : "ADDED|DELETED", "policy_definition" : "NP" }
        """

        self.send_header('Content-type','text/html')
        self.end_headers()
        # Send the html message
        headers = Message(StringIO(self.headers))
        raw_data = self.rfile.read(int(headers["Content-Length"]))
        try:
            json_data = simplejson.loads(raw_data)
        except Exception, e:
            logging.warning("Cannot parse %s" % raw_data)
            return

        # Values of `method` are inherited directly from kubernetes create/delete policy event.
        method = json_data.get('method')
        policy_def = json_data.get('policy_definition')
        if method not in [ 'ADDED', 'DELETED' ] or not policy_def:
            # HTTP 422 - Unprocessable Entity seems to be relevant. We have verified that json is valid
            # but expected fields are missing
            self.send_response(HTTP_Unprocessable_Entity)
            self.wfile.write("""Expected { "method" : "ADDED|DELETED", "policy_definition" : "NP" } """)

        elif json_data['method'] == 'ADDED':
            self.send_response(200)
            self.wfile.write("Policy definition accepted")
            policy_update(addr_scheme, policy_def)

        elif json_data['method'] == 'DELETED':
            self.send_response(200)
            self.wfile.write("Policy definition deleted")
            policy_update(addr_scheme, policy_def, delete_policy=True)

        return

# Running in HTTP server mode
def run_agent():
    server = HTTPServer(('', PORT_NUMBER), AgentHandler)
    server.serve_forever()

if __name__ == "__main__":
    if options.agent:
        run_agent()
    else:
        main()
