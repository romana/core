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

<a name="perms"></a>
### Permissions

Permissions are defined in terms of methods and REST resources they operate on. 
Here is the current list of permissions (the Roles column is explained [below](#roles)).

| Description                  | Method and URL                   |Roles         |
|------------------------------|----------------------------------|--------------|
|List all tenants              |GET /tenants                      | Tenant[*](#tenant_list_find)      |
|List all segments for a tenant|GET /tenants/{id}                 | Tenant       |
|Add a tenant                  |POST /tenants                     | Service        |
|Delete a tenant               |DELETE /tenants/{id}              | Service        |
|Add a segment                 |POST /tenants/{id}/segments       | Service, Tenant |
|Delete a segment              |DELETE /tenants/{id}/segments/{id}| Service, Tenant |
|List all hosts                |GET /hosts                        | Service         |
|Add a host                    |POST /hosts                       | Service         |
|Show host information         |GET /host/{id}                    | Service         |
|Show datacenter information   |GET /datacenter                   | Service         |
|Delete a host                 |DELETE /hosts/{id}                | Service         |
|Allocate an IP                |POST /endpoints                   | Service         |
|Deallocate an IP              |DELETE /endpoints/{ip}            | Service         |
|Add policy                    |POST /policies                    | Service, Tenant |       
|Delete policy                 |DELETE /policies/{id}             | Service, Tenant | 
|List policies                 |GET /policies                     | Tenant[*](#tenant_list_find)      |
|Retrieve particular policy    |GET /policies/{id}                | Service, Tenant|
|Find last tenant              |GET /findLast/tenants             | Tenant[*](#tenant_list_find)      |       |
|Find first tenant             |GET /findLast/tenants             | Tenant[*](#tenant_list_find)      |       |
|Find exactly one tenant       |GET /findExactlyOne/tenants       | Tenant[*](#tenant_list_find)      |       |         
|Find all tenants              |GET /findAll/tenants              | Tenant[*](#tenant_list_find)      |       |                          
|Same 4 finds for segments     |See 4 lines above                 | Tenant[*](#tenant_list_find)      |       | 
|Same 4 finds for policies     |See above                         | Tenant[*](#tenant_list_find)      |       | 
|Same 4 finds for hosts        |See above                         |              | 
|Add a VM to Service             |POST /vm                          | Service        |
|Delete a VM from Service        |DELETE /vm                        | Service        |
|Add a pod to Service            |POST /pod                         | Service        |
|Delete a pod from Service       |DELETE /pod                       | Service        |
|Add a policy to Service         |POST /policy                      | Service        |
|Delete a policy from Service    |DELETE /policy                    | Service        |
|List policies on Service        |GET /policies                     | Service        |
 
### Users

Users are handled by the Authentication plugin (see above). 

<a name="roles"></a>
#### Roles

Roles are defined in the backing store (RDBMS for now).  The following roles are pre-defined, and no mechanism for now (other than manual editing of the appropriate store) to add other roles:

##### Admin

All permissions (so admin is implied in every line of the above table).

##### Service

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
 * This also has implications for creating policies -- a tenant may not create purely CIDR-based policy for now (but an Admin or Service can). 

<a name="flow"></a>
## Flow

### General information

 1. When the RestClient [is created](https://godoc.org/github.com/romana/core/common#NewRestClient), it uses [credential](https://godoc.org/github.com/romana/core/common#Credential) provided to it to authenticate to Root's [/auth](https://github.com/paninetworks/core/blob/gg/authz/root/root.go#L131) URL (as a JSON payload in the POST request). 
 2. Root calls the Authenticate method on its "store", which is currently available as a SQL database, but can be an interface to an LDAP server, etc. It checks whether the user exists, and if so, what roles and attributes it has. Attributes are defined as key-value pairs, and the only one key currently in use is "tenant" (value being tenant ID). Each user can have multiple roles and/or multiple attributes.
 3. Root creates a [JSon Web Token](https://jwt.io/) signed with its RSA private key containing the information about the user's roles and attributes (not user's credentials) and returns it to the client.
 4. Thereafter, client uses this token in the "Authorization" header of each request. (TODO: client should automatically check for the expiration of the token and re-authenticate).
 5. For any request to any service, [AuthMiddleware](https://godoc.org/github.com/romana/core/common#AuthMiddleware) checks the token for validity, and, if valid, retrieves user's roles and attribute information and checks the roles/attributes against permissions, as well as placing this information into [RestContext](https://godoc.org/github.com/romana/core/common#RestContext) for further use downstream. 
 6. If authentication is not turned on in the Root's configuration, none of this applies.
 
#### Implementation details

To elaborate on how item 5 from above works:

 1. Currently, Romana uses [Negroni](https://github.com/urfave/negroni) for its REST services, which allows for chaining of multiple middlewares. This chain is constructed in [InitializeService method](https://godoc.org/github.com/romana/core/common#InitializeService) and includes [AuthMiddleware](https://godoc.org/github.com/romana/core/common#AuthMiddleware) 
 2. AuthMiddleware receives the public key necessary to check the token's validity and get its claims during initialization of whatever service it is a part of. When initialized as part of the Root service, it reads the public key file location from the configuration file and reads the file from the local filesystem. When initialized as any other service, it requests it from the Root service, which serves it at [/publicKey URL](https://github.com/paninetworks/core/blob/gg/authz/root/root.go#L126).
 3. The following requests are exempt from checking token on Root: 
   * / (index)
   * /auth - this checks credentials
   * /publicKey 
 4. If the user's role includes "service" or "admin", the user is allowed anything for now (unless the route has AuthZChecker defined, see below, in which case the responsibility to let those roles do the operation lies in the AuthZChecker).
 5. Restrictions on user's access can be implemented by per each route. To do that, a function implementing [AuthZChecker]() is defined, which can check the user's roles/groups (available to it via [RestContext](https://godoc.org/github.com/romana/core/common#RestContext). If defined, it is automatically invoked by [RomanaHandler](https://godoc.org/github.com/romana/core/common#RomanaHandler). An example of such is [TenantIDChecker](https://github.com/paninetworks/core/blob/gg/authz/tenant/tenant.go#L39) which ensures that 
 6. If desired, a more flexible configuration can be easily built on top that makes this happen dynamically based on some configuration file. However, there does not seem to be a good use case for this at the moment.
 
### Notes

1. RSA keys are currently only allowed in PEM-encoded PKCS8 format. They can be produced from keys generated with ssh-keygen as follows:

```
 ssh-keygen -t rsa -f demo.rsa
 ssh-keygen -f demo.rsa -e -m pkcs8 > demo.rsa.pub.pkcs8
 openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in demo.rsa  -out demo.rsa.pkcs8
```
 
  The Authentication middleware is added [almost at the top of the chain](https://github.com/romana/core/blob/master/common/service.go#L229) - below only the content negotiation module. Authentication middleware will get the roles an authentication token represents and store it in the context. Thereafter the check for permissions will happen in [wrapHandler](https://github.com/paninetworks/core/blob/master/common/middleware.go#L220) method, which can compare the route (that is, the URL pattern) and roles that are allowed access to it with roles that are provided from the authorization backend.

## Out of scope

For this iteration, we will not provide:

 * Ability to restrict permissions to individual segments - that is, a tenant user is able to operate on all its segments. 
 * Ability for a user being able to manage multiple tenants

## Alternative

An alternative to keeping permissions in the application is to allow all requests to REST to go through. As ultimately operations equate to some operations in etcd, it is there that permissions can be set. A user can be created when the tenant is created, and can be given only permissions to read keys under that user's prefix. See [etcd Auth and Security](https://coreos.com/etcd/docs/latest/auth_api.html)




