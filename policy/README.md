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
	"SecurityPolicies": [{
		"Name": "policy1",
		"AppliedTo": [{
			"Tenant": "demo",
			"Segment": "frontend"
		}],
		"Direction": "Ingress",
		"Peers": [{
			"CidrBlock": "0.0.0.0/0"
		}],
		"Rules": [{
			"Protocol": "TCP",
			"Ports": [22, 80, 443],
			"IsStateful": true
		}],
		"Description": "sample policy opening ssh, http and https ports"
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
	"appliedto": [{
		"Tenant": "demo",
		"Segment": "frontend"
	}],
	"peers": [{}],
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
