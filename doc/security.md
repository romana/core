Security
=========
Romana security consists of the following aspects:

 * Authentication (authN)
 * Authorization (authZ)

Authentication
---------------------
Currently, only username-password-based authentication is supported.

Authentication is handled by an authentication plugin which implements Authenticator interface (TBD). The plugin to use is specified in the Romana configuration file (TBD). Available plugins are:

 * rdbms - RDBMS-based reference plugin. 

In RESTful communications, Romana uses [JSon Web Tokens](https://jwt.io/).

Authentication plugin's responsibility is to:

 * Authenticate a user, and, if authenticated, hand out a token,
 * Given a token, validate it, and if valid, provide the following information about the user:
   * Roles (see below) the user belongs to.
   * Attributes of the user (e.g., tenant ID, etc)

Authorization
-------------------
Authorization is handled by Romana application. In general it is an RBAC/ABAC combination.

Permissions
-----------------
Permissions are defined in terms of methods and REST resources they operate on. 
Here is the current list of permissions (the Roles column is explained below).

| Description                  | Method and URL                   |Roles         |
|------------------------------|----------------------------------|--------------|
|List all tenants              |GET /tenants                      | Tenant       |
|List all segments for a tenant|GET /tenants/{id}                 | Tenant       |
|Add a tenant                  |POST /tenants                     |              |
|Delete a tenant               |DELETE /tenants/{id}              |              |
|Add a segment                 |POST /tenants/{id}/segments       | Tenant       |
|Delete a segment              |DELETE /tenants/{id}/segments/{id}|              |
|List all hosts                |GET /hosts                        | Agent        |
|Add a host                    |POST /hosts                       | Agent        |
|Show host information         |GET /host/{id}                    | Agent        |
|Show datacenter information   |GET /datacenter                   | Agent        |
|Delete a host                 |DELETE /hosts/{id}                | Agent        |
|Allocate an IP                |POST /endpoints                   | Agent        |
|Deallocate an IP              |DELETE /endpoints/{ip}            | Agent        |
|Add policy                    |POST /policies                    | Agent, Tenant|       
|Delete policy                 |DELETE /policies/{id}             | Agent, Tenant| 
|List policies                 |GET /policies                     | Tenant       |
|Retrieve particular policy    |GET /policies/{id}                | Agent, Tenant|
|Find last tenant              |GET /findLast/tenants             | Tenant       |
|Find first tenant             |GET /findLast/tenants             | Tenant       |
|Find exactly one tenant       |GET /findExactlyOne/tenants       | Tenant       |         
|Find all tenants              |GET /findAll/tenants              | Tenant       |                          
|Same 4 finds for segments     |See 4 lines above                 | Tenant       | 
|Same 4 finds for policies     |See above                         | Tenant       | 
|Same 4 finds for hosts        |See above                         | Tenant       | 
|Add a VM to agent             |POST /vm                          | Agent        |
|Delete a VM from agent        |DELETE /vm                        | Agent        |
|Add a pod to agent            |POST /pod                         | Agent        |
|Delete a pod from agent       |DELETE /pod                       | Agent        |
|Add a policy to agent         |POST /policy                      | Agent        |
|Delete a policy from agent    |DELETE /policy                    | Agent        |
|List policies on agent        |GET /policies                     | Agent        |
 
Users
--------
Users are handled by the Authentication plugin (see above). 

Roles
--------
Roles are defined in the backing store (RDBMS for now).  The following roles are pre-defined, and no mechanism for now (other than manual editing of the appropriate store) to add other roles:

* Admin  - all permissions (so admin is implied in every line of the above table)
* Agent - role for an automated user (e.g., IPAM plugin driver would run with this role)
* Tenant - permissions as in table above marked with "Tenant" role, as long as the user's tenant ID attribute matches the tenant ID:
   * in the URL, or 
   * in body of the request, or
  - in an augmented body of request. This means that if an external ID is used, the service would look up the actual Romana tenant ID and match it with the tenant making the request. 
This applies to /find{First,Last,ExactlyOne,All} methods. 
This also has implications for policies -- a tenant may not create purely CIDR-based policy for now (but an admin can). 

For this iteration, we will not provide:

 * Ability to restrict permissions to individual segments - that is, a tenant user is able to operate on all its segments. 
 * Ability for a user being able to manage multiple tenants






