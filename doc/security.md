# Security

Romana security consists of the following aspects:

 * Authentication (authN)
 * Authorization (authZ)

Transport security (e.g., TLS) is for now not in scope of this discussion. 

## Authentication

Currently, only username-password-based authentication is supported.

Authentication is handled by an authentication plugin which implements Authenticator interface (TBD). The plugin to use is specified in the Romana configuration file (TBD). Available plugins are:

 * rdbms - RDBMS-based reference plugin. 

In RESTful communications, Romana uses [JSon Web Tokens](https://jwt.io/).

Authentication plugin's responsibility is to:

 * Authenticate a user, and, if authenticated, hand out a token,
 * Given a token, validate it, and if valid, provide the following information about the user:
   * Roles (see below) the user belongs to.
   * Attributes of the user (e.g., tenant ID, etc)

## Authorization

Authorization is handled by Romana application. In general it is an RBAC/ABAC combination.

### Permissions

Permissions are defined in terms of methods and REST resources they operate on. 
Here is the current list of permissions (the Roles column is explained [below](#roles)).

| Description                  | Method and URL                   |Roles         |
|------------------------------|----------------------------------|--------------|
|List all tenants              |GET /tenants                      | Tenant[*](#tenant_list_find)      |
|List all segments for a tenant|GET /tenants/{id}                 | Tenant       |
|Add a tenant                  |POST /tenants                     | Agent        |
|Delete a tenant               |DELETE /tenants/{id}              | Agent        |
|Add a segment                 |POST /tenants/{id}/segments       | Agent, Tenant |
|Delete a segment              |DELETE /tenants/{id}/segments/{id}| Agent, Tenant |
|List all hosts                |GET /hosts                        | Agent         |
|Add a host                    |POST /hosts                       | Agent         |
|Show host information         |GET /host/{id}                    | Agent         |
|Show datacenter information   |GET /datacenter                   | Agent         |
|Delete a host                 |DELETE /hosts/{id}                | Agent         |
|Allocate an IP                |POST /endpoints                   | Agent         |
|Deallocate an IP              |DELETE /endpoints/{ip}            | Agent         |
|Add policy                    |POST /policies                    | Agent, Tenant |       
|Delete policy                 |DELETE /policies/{id}             | Agent, Tenant | 
|List policies                 |GET /policies                     | Tenant[*](#tenant_list_find)      |
|Retrieve particular policy    |GET /policies/{id}                | Agent, Tenant|
|Find last tenant              |GET /findLast/tenants             | Tenant[*](#tenant_list_find)      |       |
|Find first tenant             |GET /findLast/tenants             | Tenant[*](#tenant_list_find)      |       |
|Find exactly one tenant       |GET /findExactlyOne/tenants       | Tenant[*](#tenant_list_find)      |       |         
|Find all tenants              |GET /findAll/tenants              | Tenant[*](#tenant_list_find)      |       |                          
|Same 4 finds for segments     |See 4 lines above                 | Tenant[*](#tenant_list_find)      |       | 
|Same 4 finds for policies     |See above                         | Tenant[*](#tenant_list_find)      |       | 
|Same 4 finds for hosts        |See above                         |              | 
|Add a VM to agent             |POST /vm                          | Agent        |
|Delete a VM from agent        |DELETE /vm                        | Agent        |
|Add a pod to agent            |POST /pod                         | Agent        |
|Delete a pod from agent       |DELETE /pod                       | Agent        |
|Add a policy to agent         |POST /policy                      | Agent        |
|Delete a policy from agent    |DELETE /policy                    | Agent        |
|List policies on agent        |GET /policies                     | Agent        |
 
### Users

Users are handled by the Authentication plugin (see above). 

<a name="roles"></a>
#### Roles

Roles are defined in the backing store (RDBMS for now).  The following roles are pre-defined, and no mechanism for now (other than manual editing of the appropriate store) to add other roles:

##### Admin

All permissions (so admin is implied in every line of the above table).

##### Agent

Role for an automated user (e.g., [IPAM plugin driver](https://github.com/romana/networking-romana) would run with this role). 

<a name="role_tenant"></a>
##### Tenant

Permissions as in table above marked with "Tenant" role as follows:

 * For  as long as the user's tenant ID attribute matches the tenant ID:
   * in the URL, or 
   * in body of the request, or
   * in an augmented body of request. This means that if an external ID is used, the service would look up the actual Romana tenant ID and match it with the tenant making the request. 
 * <a name="tenant_list_find"></a>
When list/find operations may return multiple results, only entities belonging to the authenticated tenant are displayed with a 404 NOT FOUND error in case no entities belonging to the authenticated tenant are found. (This applies to /find{First,Last,ExactlyOne,All} methods)
 * This also has implications for creating policies -- a tenant may not create purely CIDR-based policy for now (but an Admin or Agent can). 


## Flow

This is how it works. Currently, Romana uses [Negroni](https://github.com/urfave/negroni) for its REST services, which allows for chaining of multiple middlewares. This chain is constructed in [InitializeService method](https://godoc.org/github.com/romana/core/common#InitializeService). The Authentication middleware is added [almost at the top of the chain](https://github.com/romana/core/blob/master/common/service.go#L229) - below only the content negotiation module. Authentication middleware will get the roles an authentication token represents and store it in the context. Thereafter the check for permissions will happen in [wrapHandler](https://github.com/paninetworks/core/blob/master/common/middleware.go#L220) method, which can compare the route (that is, the URL pattern) and roles that are allowed access to it with roles that are provided from the authorization backend.

## Out of scope

For this iteration, we will not provide:

 * Ability to restrict permissions to individual segments - that is, a tenant user is able to operate on all its segments. 
 * Ability for a user being able to manage multiple tenants

## Alternative

An alternative to keeping permissions in the application is to allow all requests to REST to go through. As ultimately operations equate to some operations in etcd, it is there that permissions can be set. A user can be created when the tenant is created, and can be given only permissions to read keys under that user's prefix. See [etcd Auth and Security](https://coreos.com/etcd/docs/latest/auth_api.html)




