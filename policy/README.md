### Romana Policy Service and Policy Examples

#### Sample Romana Policy
A sample romana policy is shown below, a detailed version can be found [here](policy/policy.sample.json).

#### Applying New Policy
Romana policies can be applied by calling the Policy API
directly or using Roman CLI. A example of applying policy
is show below:
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
```
