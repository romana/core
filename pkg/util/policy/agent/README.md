Romana policy agent
===================

This agent is a tool to apply romana policies on all hosts.
It accepts **Romana policy defenitions** which are not complete yet so current implementation is temporary.

This agent intended to be contacted directly by platform adaptors or later by *policy manager*.
In any case caller is responsible to convert policy from platform specific type to romana policy type.

# Roadmap
1. Update policy defenition.
2. Maintain per tenant "policy vector" chains with list of policies applied to current tenant.
3. Rewrite in Golang.
3.1. Multitherading and locking
