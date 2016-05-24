// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

//Package ipam implements IPAM service.
//
//IPAM REST API provides the following functionality:
//
//1. Allocate an IP for an endpoint
//
//To allocate an IP, POST to /endpoints with the following body:
//
//    {
//        "tenant_id"  : "Tenant ID",
//        "segment_id" : "Segment ID",
//        "host_id"    : "Host ID"
//        "name"       : "Endpoint name",
//    }
//
//Where:
//
//  1. tenant_id: In case of OpenStack, this is the project's UUID.
//  2. segment_id: In case of OpenStack, this is the value of the metadata tag whose name is 'romanaSegment'
//  3. host_id: In case of OpenStack, this is the value of 'binding:host_id' field of port object.
//  4. name is optional.
//
//On success, the same structure is returned with two more fields:
//
//  1. id, containing the auto-generated ID of the newly allocated endpoint's IP
//  2. ip, containing the allocated IP:
//
//    {
//        "ip"         : "10.0.0.3",
//        "id"         : 37,
//        "tenant_id"  : "Tenant ID",
//        "segment_id" : "Segment ID",
//        "host_id"    : "Host ID"
//        "name"       : "Endpoint name",
//    }
//
//2. Deallocate an IP for an endpoint.
//
//To deallocate an IP, issue a DELETE request to /endpoints/<ip>.
package ipam
