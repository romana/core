// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// This file contains object definitions from http://swagger.io/specification/.

package tools

import (
	"github.com/romana/core/common"
)

// See http://swagger.io/specification/#externalDocumentationObject
type SwaggerExternalDocumentation struct {
	Description string `yaml:"description,omitempty"`
	URL         string `yaml:"url,omitempty"`
}

// See http://swagger.io/specification/#contactObject
type SwaggerContact struct {
	Name  string `yaml:"name,omitempty"`
	URL   string `yaml:"url,omitempty"`
	Email string `yaml:"email,omitempty"`
}

// See http://swagger.io/specification/#licenseObject
type SwaggerLicense struct {
	Name string `yaml:"name,omitempty"`
	URL  string `yaml:"url,omitempty"`
}

// See http://swagger.io/specification/#infoObject
type SwaggerInfo struct {
	Title          string         `yaml:"title,omitempty"`
	Description    string         `yaml:"description,omitempty"`
	TermsOfService string         `yaml:"termsOfService,omitempty"`
	Contact        SwaggerContact `yaml:"contact,omitempty"`
	License        SwaggerLicense `yaml:"license,omitempty"`
	Version        string         `yaml:"version,omitempty"`
}

const (
	SwaggerInBody     = "body"
	SwaggerInQuery    = "query"
	SwaggerInPath     = "path"
	SwaggerInFormData = "formData"
	SwaggerInHeader   = "header"
)

// This was intended for reuse but looks like it's not possible now
// with Go YAML: https://github.com/go-yaml/yaml/issues/183
//type SwaggerDef struct {
//	Type             string                     `yaml:"type,omitempty"`
//	Format           string                     `yaml:"format,omitempty"`
//	Default          interface{}                `yaml:"default,omitempty"`
//	MultipleOf       int                        `yaml:"multipleOf,omitempty"`
//	Maximum          int                        `yaml:"maximum,omitempty"`
//	ExclusiveMaximum bool                       `yaml:"exclusiveMaximum,omitempty"`
//	Minimum          int                        `yaml:"minimum,omitempty"`
//	ExclusiveMinimum bool                       `yaml:"exclusiveMinimum,omitempty"`
//	MaxLength        int                        `yaml:"maxLength,omitempty"`
//	MinLength        int                        `yaml:"minLength,omitempty"`
//	Pattern          string                     `yaml:"pattern,omitempty"`
//	MaxItems         int                        `yaml:"maxItems,omitempty"`
//	MinItems         int                        `yaml:"minItems,omitempty"`
//	UniqueItems      bool                       `yaml:"uniqueItems,omitempty"`
//	MaxProperties    int                        `yaml:"maxProperties,omitempty"`
//	MinProperties    int                        `yaml:"minProperties,omitempty"`
//	Required         bool                       `yaml:"required,omitempty"`
//	Enum             []interface{}              `yaml:"enum,omitempty"`
//	Items            *SwaggerItems              `yaml:"items,omitempty"`
//	Properties       map[string]SwaggerProperty `yaml:"properties,omitempty"`
//}

type SwaggerSchema struct {
	Ref              string        `yaml:"$ref,omitempty"`
	Title            string        `yaml:"title,omitempty"`
	Description      string        `yaml:"description,omitempty"`
	Type             string        `yaml:"type,omitempty"`
	Format           string        `yaml:"format,omitempty"`
	Default          interface{}   `yaml:"default,omitempty"`
	MultipleOf       int           `yaml:"multipleOf,omitempty"`
	Maximum          int           `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool          `yaml:"exclusiveMaximum,omitempty"`
	Minimum          int           `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool          `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int           `yaml:"maxLength,omitempty"`
	MinLength        int           `yaml:"minLength,omitempty"`
	Pattern          string        `yaml:"pattern,omitempty"`
	MaxItems         int           `yaml:"maxItems,omitempty"`
	MinItems         int           `yaml:"minItems,omitempty"`
	UniqueItems      bool          `yaml:"uniqueItems,omitempty"`
	MaxProperties    int           `yaml:"maxProperties,omitempty"`
	MinProperties    int           `yaml:"minProperties,omitempty"`
	Enum             []interface{} `yaml:"enum,omitempty"`
	Items            *SwaggerItems `yaml:"items,omitempty"`
	// See http://json-schema.org/latest/json-schema-validation.html#anchor61
	Required   []string                   `yaml:"required,omitempty"`
	Properties map[string]SwaggerProperty `yaml:"properties,omitempty"`
}

type SwaggerItems struct {
	Type             string                     `yaml:"type,omitempty"`
	Format           string                     `yaml:"format,omitempty"`
	Default          interface{}                `yaml:"default,omitempty"`
	MultipleOf       int                        `yaml:"multipleOf,omitempty"`
	Maximum          int                        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool                       `yaml:"exclusiveMaximum,omitempty"`
	Minimum          int                        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool                       `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int                        `yaml:"maxLength,omitempty"`
	MinLength        int                        `yaml:"minLength,omitempty"`
	Pattern          string                     `yaml:"pattern,omitempty"`
	MaxItems         int                        `yaml:"maxItems,omitempty"`
	MinItems         int                        `yaml:"minItems,omitempty"`
	UniqueItems      bool                       `yaml:"uniqueItems,omitempty"`
	MaxProperties    int                        `yaml:"maxProperties,omitempty"`
	MinProperties    int                        `yaml:"minProperties,omitempty"`
	Required         bool                       `yaml:"required,omitempty"`
	Enum             []interface{}              `yaml:"enum,omitempty"`
	Items            *SwaggerItems              `yaml:"items,omitempty"`
	Properties       map[string]SwaggerProperty `yaml:"properties,omitempty"`
}

type SwaggerProperty struct {
	Description      string      `yaml:"description,omitempty"`
	Type             string      `yaml:"type,omitempty"`
	Format           string      `yaml:"format,omitempty"`
	Default          interface{} `yaml:"default,omitempty"`
	MultipleOf       int         `yaml:"multipleOf,omitempty"`
	Maximum          int         `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool        `yaml:"exclusiveMaximum,omitempty"`
	Minimum          int         `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool        `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int         `yaml:"maxLength,omitempty"`
	MinLength        int         `yaml:"minLength,omitempty"`
	Pattern          string      `yaml:"pattern,omitempty"`
	MaxItems         int         `yaml:"maxItems,omitempty"`
	MinItems         int         `yaml:"minItems,omitempty"`
	UniqueItems      bool        `yaml:"uniqueItems,omitempty"`
	MaxProperties    int         `yaml:"maxProperties,omitempty"`
	MinProperties    int         `yaml:"minProperties,omitempty"`
	//	Required         bool                       `yaml:"required,omitempty"`
	Enum       []interface{}              `yaml:"enum,omitempty"`
	Items      *SwaggerItems              `yaml:"items,omitempty"`
	Properties map[string]SwaggerProperty `yaml:"properties,omitempty"`
	Ref        string                     `yaml:"$ref,omitempty"`
}

type SwaggerParam struct {
	Name             string                     `yaml:"name,omitempty"`
	In               string                     `yaml:"in,omitempty"`
	Description      string                     `yaml:"description,omitempty"`
	Required         bool                       `yaml:"required,omitempty"`
	Schema           SwaggerSchema              `yaml:"required,omitempty"`
	AllowEmptyValue  bool                       `yaml:"allowEmptyValue,omitempty"`
	Type             string                     `yaml:"type,omitempty"`
	Format           string                     `yaml:"format,omitempty"`
	Default          interface{}                `yaml:"default,omitempty"`
	MultipleOf       int                        `yaml:"multipleOf,omitempty"`
	Maximum          int                        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool                       `yaml:"exclusiveMaximum,omitempty"`
	Minimum          int                        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool                       `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int                        `yaml:"maxLength,omitempty"`
	MinLength        int                        `yaml:"minLength,omitempty"`
	Pattern          string                     `yaml:"pattern,omitempty"`
	MaxItems         int                        `yaml:"maxItems,omitempty"`
	MinItems         int                        `yaml:"minItems,omitempty"`
	UniqueItems      bool                       `yaml:"uniqueItems,omitempty"`
	MaxProperties    int                        `yaml:"maxProperties,omitempty"`
	MinProperties    int                        `yaml:"minProperties,omitempty"`
	Enum             []interface{}              `yaml:"enum,omitempty"`
	Items            *SwaggerItems              `yaml:"items,omitempty"`
	Properties       map[string]SwaggerProperty `yaml:"properties,omitempty"`
}

type SwaggerRef struct {
	Ref string `yaml:"$ref,omitempty"`
}

type SwaggerParamOrRef struct {
	Name             string                     `yaml:"name,omitempty"`
	In               string                     `yaml:"in,omitempty"`
	Description      string                     `yaml:"description,omitempty"`
	Required         bool                       `yaml:"required,omitempty"`
	Schema           SwaggerSchema              `yaml:"schema,omitempty"`
	AllowEmptyValue  bool                       `yaml:"allowEmptyValue,omitempty"`
	Type             string                     `yaml:"type,omitempty"`
	Format           string                     `yaml:"format,omitempty"`
	Default          interface{}                `yaml:"default,omitempty"`
	MultipleOf       int                        `yaml:"multipleOf,omitempty"`
	Maximum          int                        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool                       `yaml:"exclusiveMaximum,omitempty"`
	Minimum          int                        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool                       `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int                        `yaml:"maxLength,omitempty"`
	MinLength        int                        `yaml:"minLength,omitempty"`
	Pattern          string                     `yaml:"pattern,omitempty"`
	MaxItems         int                        `yaml:"maxItems,omitempty"`
	MinItems         int                        `yaml:"minItems,omitempty"`
	UniqueItems      bool                       `yaml:"uniqueItems,omitempty"`
	MaxProperties    int                        `yaml:"maxProperties,omitempty"`
	MinProperties    int                        `yaml:"minProperties,omitempty"`
	Enum             []interface{}              `yaml:"enum,omitempty"`
	Items            *SwaggerItems              `yaml:"items,omitempty"`
	Properties       map[string]SwaggerProperty `yaml:"properties,omitempty"`
	Ref              string                     `yaml:"$ref,omitempty"`
}

type SwaggerTag struct {
	Name         string                       `yaml:"name,omitempty"`
	Description  string                       `yaml:"description,omitempty"`
	ExternalDocs SwaggerExternalDocumentation `yaml:"externalDocs,omitempty"`
}

type SwaggerSecurityScheme struct {
	Type             string            `yaml:"type,omitempty"`
	Description      string            `yaml:"description,omitempty"`
	Name             string            `yaml:"name,omitempty"`
	In               string            `yaml:"in,omitempty"`
	Flow             string            `yaml:"flow,omitempty"`
	AuthorizationURL string            `yaml:"authorizationUrl,omitempty"`
	tokenURL         string            `yaml:"tokenUrl,omitempty"`
	Scopes           map[string]string `yaml:"scopes,omitempty"`
}

type SwaggerHeader struct {
	Type             string                     `yaml:"type,omitempty"`
	Format           string                     `yaml:"format,omitempty"`
	Default          interface{}                `yaml:"default,omitempty"`
	MultipleOf       int                        `yaml:"multipleOf,omitempty"`
	Maximum          int                        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool                       `yaml:"exclusiveMaximum,omitempty"`
	Minimum          int                        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool                       `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int                        `yaml:"maxLength,omitempty"`
	MinLength        int                        `yaml:"minLength,omitempty"`
	Pattern          string                     `yaml:"pattern,omitempty"`
	MaxItems         int                        `yaml:"maxItems,omitempty"`
	MinItems         int                        `yaml:"minItems,omitempty"`
	UniqueItems      bool                       `yaml:"uniqueItems,omitempty"`
	MaxProperties    int                        `yaml:"maxProperties,omitempty"`
	MinProperties    int                        `yaml:"minProperties,omitempty"`
	Required         bool                       `yaml:"required,omitempty"`
	Enum             []interface{}              `yaml:"enum,omitempty"`
	Items            *SwaggerItems              `yaml:"items,omitempty"`
	Properties       map[string]SwaggerProperty `yaml:"properties,omitempty"`
}

type SwaggerResponse struct {
	Description string                   `yaml:"description,omitempty"`
	Schema      SwaggerSchema            `yaml:"schema,omitempty"`
	Headers     map[string]SwaggerHeader `yaml:"headers,omitempty"`
	Examples    map[string]interface{}   `yaml:"examples,omitempty"`
}

type SwaggerOperation struct {
	Tags                []string                         `yaml:"tags,omitempty"`
	Summary             string                           `yaml:"summary,omitempty"`
	Description         string                           `yaml:"description,omitempty"`
	ExternalDocs        SwaggerExternalDocumentation     `yaml:"externalDocs,omitempty"`
	OperationId         string                           `yaml:"operationId,omitempty"`
	Consumes            []string                         `yaml:"consumes,omitempty"`
	Produces            []string                         `yaml:"produces,omitempty"`
	Parameters          []SwaggerParamOrRef              `yaml:"parameters,omitempty"`
	Responses           map[string]SwaggerResponse       `yaml:"responses,omitempty"`
	Schemes             []string                         `yaml:"schemes,omitempty"`
	Deprecated          bool                             `yaml:"deprecated,omitempty"`
	SecurityDefinitions map[string]SwaggerSecurityScheme `yaml:"securityDefinitions,omitempty"`
	Security            []map[string][]string            `yaml:"security,omitempty"`
}

type SwaggerPathItem struct {
	Ref        string              `yaml:"$ref,omitempty"`
	Get        SwaggerOperation    `yaml:"get,omitempty"`
	Put        SwaggerOperation    `yaml:"put,omitempty"`
	Post       SwaggerOperation    `yaml:"post,omitempty"`
	Delete     SwaggerOperation    `yaml:"delete,omitempty"`
	Options    SwaggerOperation    `yaml:"options,omitempty"`
	Head       SwaggerOperation    `yaml:"head,omitempty"`
	Patch      SwaggerOperation    `yaml:"patch,omitempty"`
	Parameters []SwaggerParamOrRef `yaml:"parameters,omitempty"`
}

type Swagger struct {
	Swagger     string                      `yaml:"swagger,omitempty"`
	Info        SwaggerInfo                 `yaml:"info,omitempty"`
	Host        string                      `yaml:"host,omitempty"`
	BasePath    string                      `yaml:"basePath,omitempty"`
	Schemes     []string                    `yaml:"schemes,omitempty"`
	Consumes    []string                    `yaml:"consumes,omitempty"`
	Produces    []string                    `yaml:"produces,omitempty"`
	Paths       map[string]*SwaggerPathItem `yaml:"paths,omitempty"`
	Definitions map[string]*SwaggerSchema   `yaml:"definitions,omitempty"`
}

func NewSwagger() Swagger {
	info := newSwaggerInfo()
	swagger := Swagger{
		Swagger:     SwaggerVersion,
		Info:        info,
		BasePath:    "/",
		Schemes:     []string{"http", "https"},
		Consumes:    common.SupportedContentTypes,
		Produces:    common.SupportedContentTypes,
		Definitions: make(map[string]*SwaggerSchema),
	}
	return swagger
}

func newSwaggerInfo() SwaggerInfo {
	contact := SwaggerContact{
		URL:   "http://romana.io",
		Email: "info@romana.io",
	}
	license := SwaggerLicense{
		Name: "Apache License 2.0",
		URL:  "https://github.com/romana/core/blob/master/LICENSE",
	}
	return SwaggerInfo{
		// TODO take from command line
		Version: "0.9.0",
		Contact: contact,
		License: license,
	}
}
