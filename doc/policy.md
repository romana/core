### Romana Policy Service and Policy Examples

#### Sample Romana Policy
Sample Romana polices with various combinations of rules are shown [here](examples/).

#### Applying New Policy
Romana policies can be applied by calling the Policy API
directly or using the Romana CLI. An example of applying
a policy is shown below:
```bash
$ cat policy.json
{
    "securitypolicies": [{
        "name": "policy1",
        "description": "sample policy opening ssh, http and https ports",
        "direction": "ingress",
        "applied_to": [{
            "tenant": "demo",
            "segment": "default"
        }],
        "peers": [{
            "peer": "any"
        }],
        "rules": [{
            "protocol": "tcp",
            "ports": [22, 80, 443]
        }]
    }]
}

$ romana policy add policy.json 
New Policies Processed:
Id	 Policy Name	 Direction	 Successful Applied?	
1 	 policy1 	 ingress 	 true

$ romana policy list -f json
[{
	"direction": "ingress",
	"description": "sample policy opening ssh, http and https ports",
	"name": "policy1",
	"id": 1,
	"external_id": "policy1",
	"applied_to": [{
		"tenant": "demo",
		"segment": "default"
	}],
	"peers": [{
		"peer": "any"
	}],
	"rules": [{
		"protocol": "TCP",
		"ports": [
			22,
			80,
			443
		]
	}]
}]
```
