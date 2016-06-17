### Romana Policy Service and Policy Examples

#### Sample Romana Policy
A sample romana policy is shown below, a detailed version can be found [here](policy/policy.sample.json).

#### Applying New Policy
Romana policies can be applied by calling the Policy API
directly or using the Romana CLI. An example of applying
a policy is shown below:
```bash
$ cat policy.sample.json
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
            "cidr": "0.0.0.0/0"
        }],
        "rules": [{
            "protocol": "tcp",
            "ports": [22, 80, 443]
        }]
    }]
}

$ romana policy add policy.sample.json 
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
		"cidr": "0.0.0.0/0"
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
