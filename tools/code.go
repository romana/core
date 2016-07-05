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

package tools

import (
	"errors"
	"fmt"
	"github.com/go-yaml/yaml"
	"go/types"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"regexp"
	"runtime"
	// TODO make even this dynamic
	"github.com/romana/core/common"
	"go/ast"
	"go/build"
	"go/doc"
	"go/parser"
	"go/token"
	//	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	SwaggerVersion = "2.0"
	ApiDomain      = "api.romana.io"
)

// Analyzer uses various reflection/introspection/code analysis methods to analyze
// code and store metadata about it, for various purposes. It works on a level of
// a Go "repository" (see https://golang.org/doc/code.html#Organization).
type Analyzer struct {
	// Path started with.
	path string
	// In Go convention, this is "src" directory under path (above). Saved
	// here to avoid doing path + "/src" all the time.s
	srcDir string
	// List of paths that have already been analyzed
	analyzed []string
	// All the import paths that we have gone through.
	importPaths []string

	buildPackages []build.Package
	astPackages   []ast.Package
	docPackages   []doc.Package
	astFiles      []*ast.File

	conf          *loader.Config
	objects       []types.Object
	fullTypeDocs  map[string]string
	shortTypeDocs map[string]string
	fileSet       *token.FileSet
}

// NewAnalyzer creates a new Analyzer object for analysis of Go project
// in the provided path.
func NewAnalyzer(path string) *Analyzer {
	loaderConfig := loader.Config{ParserMode: parser.ParseComments, AllowErrors: true}
	a := &Analyzer{
		path:          path,
		srcDir:        path + "/src",
		analyzed:      make([]string, 0),
		conf:          &loaderConfig,
		fullTypeDocs:  common.MkMapStr(),
		shortTypeDocs: common.MkMapStr(),
		fileSet:       token.NewFileSet(),
	}
	return a
}

var pathVariableRegexp regexp.Regexp

func (a *Analyzer) Analyze() error {
	f, err := os.Open(a.srcDir)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	err = f.Close()
	if !info.IsDir() {
		return errors.New(fmt.Sprintf("Expected %s to be a directory", a.srcDir))
	}
	err = filepath.Walk(a.srcDir, a.walker)
	if err != nil {
		return err
	}
	log.Printf("Visited:\n%s", a.analyzed)

	lprog, err := a.conf.Load()
	if lprog == nil {
		return err
	}
	log.Printf("Loaded program: %s, Error: %T %v", lprog, err, err)

	for _, pkg := range lprog.InitialPackages() {
		for k, v := range pkg.Types {
			log.Printf("%v ==> %+v", k, v)
		}

		scope := pkg.Pkg.Scope()
		for _, n := range scope.Names() {
			obj := scope.Lookup(n)
			log.Printf("Type: Type: %s: %s ", obj.Type().String(), obj.Id())
			a.objects = append(a.objects, obj)
		}
	}

	ssaProg := ssautil.CreateProgram(lprog, ssa.BuilderMode(ssa.GlobalDebug))
	ssaProg.Build()

	for _, p := range a.docPackages {
		for _, t := range p.Types {
			log.Printf("\n****\n%+v\n****\n", t)
		}
	}
	return nil
}

func (a *Analyzer) walker(path string, info os.FileInfo, err error) error {
	if path == a.srcDir {
		return nil
	}
	name := info.Name()
	//	log.Printf("Entered walker(\"%s\", \"%s\", %+v)", path, name, err)
	firstChar := string(name[0])
	isDotFile := firstChar == "."
	//	log.Printf("Checking %v vs .: %v", firstChar, isDotFile)
	if isDotFile {
		log.Printf("Ignoring (dotfile): %s", name)
		if info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}

	if common.In(path, a.analyzed) {
		log.Printf("Ignoring (visited): %s in %+v", path, a.analyzed)
		return nil
	}
	a.analyzed = append(a.analyzed, path)
	if err != nil {
		log.Printf("Error in walking %s: %s", path, err)
		return err
	}
	if info.Name() == "vendor" {
		log.Printf("Ignoring (vendor): %s", path)
		return filepath.SkipDir
	}

	if info.IsDir() {
		err = a.analyzePath(path)
		if err != nil {
			log.Printf("Error in analyzePath(%s): %s", path, err)
			return filepath.SkipDir
		}
	}
	return nil
}

func (a *Analyzer) analyzePath(path string) error {
	importPath := path[len(a.path+"/src/"):]
	if importPath == "" {
		return nil
	}
	a.importPaths = append(a.importPaths, importPath)
	// bpkg -- build packages
	bpkg, err := build.Import(importPath, "", 0)
	// If no Go files are found, we can skip it - not a real error.
	_, nogo := err.(*build.NoGoError)
	if err != nil {
		if !nogo {
			log.Printf("Error in build.Import(\"%s\"): %+v %T", path, err, err)
			return err
		}
		log.Printf("%s", err)
		return nil
	}
	//log.Printf("build.Import(%s, \"\", 0) = %+v", path, bpkg)

	files := make(map[string]*ast.File)
	goFiles := bpkg.GoFiles
	cGoFiles := bpkg.CgoFiles
	for _, name := range append(goFiles, cGoFiles...) {
		goFileName := filepath.Join(bpkg.Dir, name)
		// log.Printf("Processing %s...", goFileName)
		file, err := parser.ParseFile(a.fileSet, goFileName, nil, parser.ParseComments)
		a.astFiles = append(a.astFiles, file)
		// TODO do we need to do anything with file.Scope?
		//		log.Printf("Processed %s: (%+v, %s)", goFileName, file, err)
		if err != nil {
			return err
		}
		files[name] = file
	}

	//	typeConfig := &types.Config{}
	//	info := &types.Info{}
	//	tpkg, err := typeConfig.Check(importPath, a.fileSet, a.astFiles, info)
	//	log.Printf("Types package info: %+v", info)

	// apkg - ast packages
	apkg := &ast.Package{Name: bpkg.Name, Files: files}
	// dpkg - doc packages
	dpkg := doc.New(apkg, bpkg.ImportPath, doc.AllDecls|doc.AllMethods)

	log.Printf("In AST package %s, Doc package %s, Build package %s", apkg.Name, dpkg.Name, bpkg.Name)

	for _, t := range dpkg.Types {
		// fullName is full import path (github.com/romana/core/tenant) DOT name of type
		fullName := fmt.Sprintf("%s.%s", importPath, t.Name)
		a.fullTypeDocs[fullName] = t.Doc
		// shortName is just package.type
		shortName := fmt.Sprintf("%s.%s", dpkg.Name, t.Name)
		a.shortTypeDocs[shortName] = t.Doc
		log.Printf("\tType docs for %s (%s): %+v,", fullName, shortName, t.Doc)
		for _, m := range t.Methods {
			methodFullName := fmt.Sprintf("%s.%s", fullName, m.Name)
			a.fullTypeDocs[methodFullName] = m.Doc
			methodShortName := fmt.Sprintf("%s.%s", shortName, m.Name)
			a.shortTypeDocs[methodShortName] = m.Doc
			log.Printf("\tMethod docs for %s (%s): %+v", methodFullName, methodShortName, m.Doc)
		}
	}

	if apkg.Scope != nil && apkg.Scope.Objects != nil {
		for name, astObj := range apkg.Scope.Objects {
			log.Printf("AST Object %s.%s: %v", apkg.Name, name, astObj.Data)
		}
	}

	//	a.buildPackages = append(a.buildPackages, *bpkg)
	//	a.astPackages = append(a.astPackages, *apkg)
	a.docPackages = append(a.docPackages, *dpkg)
	//	log.Printf("Parsed %s:\nbuildPackage:\n\t%s\nastPackage\n\t%s\ndocPackage:\n\n%s", path, bpkg.Name, apkg.Name, dpkg.Name)

	a.conf.Import(importPath)
	return nil
}

func (a *Analyzer) FindImplementors(interfaceName string) []types.Type {
	ifc := a.getInterface(interfaceName)
	implementors := a.getImplementors(ifc)
	return implementors
}

func (a *Analyzer) getImplementors(ifc *types.Interface) []types.Type {
	retval := make([]types.Type, 0)
	for _, o := range a.objects {
		log.Printf("\t\tChecking if %s implements %s", o.Type(), ifc)
		fnc, wrongType := types.MissingMethod(o.Type(), ifc, true)
		if fnc == nil {
			retval = append(retval, o.Type())
			continue
		} else {
			log.Printf("%s (%s) does not implement %s: missing %s, wrong type: %s", o.Type(), ifc, fnc, wrongType)
		}
	}
	return retval
}

func (a *Analyzer) getInterface(name string) *types.Interface {
	for _, o := range a.objects {
		if o.Type().String() == name {
			return o.Type().Underlying().(*types.Interface)
		}
	}
	return nil
}

func (rd *Swaggerer) getSchemaDef(entityType reflect.Type) *SwaggerSchema {
	schema := SwaggerSchema{}
	schema.Type = "object"
	schema.Properties = make(map[string]SwaggerProperty)
	docString := rd.analyzer.shortTypeDocs[entityType.String()]
	schema.Description = docString
	log.Printf("getSchemaDef(): Docstring for %s: %s", entityType, docString)
	//	log.Printf("Will call NumFields() on %s", entityType)
	for i := 0; i < entityType.NumField(); i++ {
		propDetails := SwaggerProperty{}
		structField := entityType.Field(i)
		fieldTag := structField.Tag
		fieldName := structField.Name
		jsonFieldName := fieldName
		romanaTag := fieldTag.Get("romana")

		if romanaTag != "" {
			log.Printf("Found Romana tag: %s", romanaTag)
			romanaTagElts := strings.Split(romanaTag, ",")
			for _, romanaTagElt := range romanaTagElts {
				kv := strings.Split(romanaTagElt, "=")
				log.Printf("Found Romana tag key: %s %d", kv[0], len(kv))
				if len(kv) != 2 {
					continue
				}
				if kv[0] == "desc" {
					propDetails.Description = kv[0]
				}
			}
		}
		exclude := false
		jTag := fieldTag.Get("json")
		if jTag != "" {
			jTagElts := strings.Split(jTag, ",")
			// This takes care of ",omitempty"
			if len(jTagElts) > 1 {
				jsonFieldName = jTagElts[0]
			} else {
				jsonFieldName = jTag
			}
			required := true
			for _, jTagElt := range jTagElts {
				if jTagElt == "omitempty" {
					required = false
					break
				}
				if jTagElt == "-" {
					exclude = true
					required = false
				}
			}
			if required {
				schema.Required = append(schema.Required, jsonFieldName)
			}
		}
		rd.fillProperty(&propDetails, structField.Type)
		if !exclude {
			schema.Properties[jsonFieldName] = propDetails
		}
	}
	return &schema
}

// init initializes Swaggerer object, filling in common
// information such as Swagger version, etc.
func (rd *Swaggerer) init() {
	rd.swagger = NewSwagger()
	name := rd.service.Name()
	rd.swagger.Info.Title = fmt.Sprintf("Romana %s API", name)
	serviceType := reflect.TypeOf(rd.service).Elem().String()
	log.Printf("Looking for doc for %s", serviceType)
	rd.swagger.Info.Description = rd.analyzer.shortTypeDocs[serviceType]
	rd.addDef(reflect.TypeOf(common.HttpError{}))
}

// fillTypeInfo fills in the correct type information
// for the entity in the given place in the map. In other words,
// it can fill
// "type" : "integer", "format" : "int32"
// or
// "type" : "array", "items" { "type" : "integer" }
// or
// "$ref" : "#/definitions/Foo (and fill in definition of Foo if doesn't exist)

func (rd *Swaggerer) fillItems(m *SwaggerItems, entityType reflect.Type) {
	kind := entityType.Kind()
	//	kindStr := strings.ToLower(kind.String())
	switch kind {
	case reflect.Int:
		m.Type = "integer"
	case reflect.Int8:
		m.Type = "integer"
	case reflect.Int16:
		m.Type = "integer"
	case reflect.Int32:
		m.Type = "integer"
		m.Format = "int32"
	case reflect.Int64:
		m.Type = "integer"
		m.Format = "int64"
	case reflect.Uint:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint8:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint16:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint32:
		m.Type = "integer"
		m.Minimum = 0
		m.Format = "int32"
	case reflect.Uint64:
		m.Type = "integer"
		m.Minimum = 0
		m.Format = "int64"
	case reflect.Float32:
		m.Type = "number"
		m.Format = "number"
	case reflect.Float64:
		m.Type = "double"
		m.Format = "double"
	case reflect.Bool:
		m.Type = "boolean"
	case reflect.Array:
		m.Type = "array"
		items := SwaggerItems{}
		rd.fillItems(&items, entityType.Elem())
		m.Items = &items
		log.Printf("For array %s we have %v", entityType, m)
	case reflect.Slice:
		m.Type = "array"
		items := SwaggerItems{}
		rd.fillItems(&items, entityType.Elem())
		m.Items = &items
		log.Printf("For array %s we have %v", entityType, m)
	case reflect.String:
		m.Type = "string"
	case reflect.Ptr:
		rd.fillItems(m, entityType.Elem())
	case reflect.Map:
		m.Type = "object"
	case reflect.Interface:
		m.Type = "object"
	default:
		log.Printf("fillItems(%s) (%s): Not sure what to do here (%s)", entityType, entityType.Kind(), entityType)

	}
}

func (rd *Swaggerer) fillProperty(m *SwaggerProperty, entityType reflect.Type) {
	kind := entityType.Kind()
	kindStr := strings.ToLower(kind.String())
	switch kind {
	case reflect.Int:
		m.Type = "integer"
	case reflect.Int8:
		m.Type = "integer"
	case reflect.Int16:
		m.Type = "integer"
	case reflect.Int32:
		m.Type = "integer"
		m.Format = "int32"
	case reflect.Int64:
		m.Type = "integer"
		m.Format = "int64"
	case reflect.Uint:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint8:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint16:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint32:
		m.Type = "integer"
		m.Minimum = 0
		m.Format = "int43"
	case reflect.Uint64:
		m.Type = "integer"
		m.Minimum = 0
		m.Format = kindStr
	case reflect.Float32:
		m.Type = "number"
		m.Format = "number"
	case reflect.Float64:
		m.Type = "double"
		m.Format = "double"
	case reflect.Bool:
		m.Type = "boolean"
	case reflect.Array:
		m.Type = "array"
		items := SwaggerItems{}
		rd.fillItems(&items, entityType.Elem())
		m.Items = &items
		log.Printf("For array %s we have %v", entityType, m)
	case reflect.Slice:
		m.Type = "array"
		items := SwaggerItems{}
		rd.fillItems(&items, entityType.Elem())
		m.Items = &items
		log.Printf("For array %s we have %v", entityType, m)
	case reflect.String:
		m.Type = "string"
	case reflect.Ptr:
		rd.fillProperty(m, entityType.Elem())
	case reflect.Map:
		m.Type = "object"
	case reflect.Interface:
		m.Type = "object"
	default:
		log.Printf("fillTypeInfo(%s) (%s): Calling addDef(%s)", entityType, entityType.Kind(), entityType)
		m.Ref = rd.addDef(entityType)
	}
}

func (rd *Swaggerer) fillSchema(m *SwaggerSchema, entityType reflect.Type) {
	kind := entityType.Kind()
	kindStr := strings.ToLower(kind.String())
	switch kind {
	case reflect.Int:
		m.Type = "integer"
	case reflect.Int8:
		m.Type = "integer"
	case reflect.Int16:
		m.Type = "integer"
	case reflect.Int32:
		m.Type = "integer"
		m.Format = "int32"
	case reflect.Int64:
		m.Type = "integer"
		m.Format = kindStr
	case reflect.Uint:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint8:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint16:
		m.Type = "integer"
		m.Minimum = 0
	case reflect.Uint32:
		m.Type = "integer"
		m.Minimum = 0
		m.Format = "int32"
	case reflect.Uint64:
		m.Type = "integer"
		m.Minimum = 0
		m.Format = kindStr
	case reflect.Float32:
		m.Type = "number"
		m.Format = "number"
	case reflect.Float64:
		m.Type = "double"
		m.Format = "double"
	case reflect.Bool:
		m.Type = "boolean"
	case reflect.Array:
		m.Type = "array"
		items := SwaggerItems{}
		rd.fillItems(&items, entityType.Elem())
		m.Items = &items
		log.Printf("For array %s we have %v", entityType, m)
	case reflect.Slice:
		m.Type = "array"
		items := SwaggerItems{}
		rd.fillItems(&items, entityType.Elem())
		m.Items = &items
		log.Printf("For array %s we have %v", entityType, m)
	case reflect.String:
		m.Type = "string"
	case reflect.Ptr:
		rd.fillSchema(m, entityType.Elem())
	case reflect.Map:
		m.Type = "object"
	case reflect.Interface:
		m.Type = "object"
	default:
		log.Printf("fillTypeInfo(%s) (%s): Calling addDef(%s)", entityType, entityType.Kind(), entityType)
		m.Ref = rd.addDef(entityType)
	}
}
func (rd *Swaggerer) addDef(entityType reflect.Type) string {
	typeName := entityType.String()
	ref := fmt.Sprintf("#/definitions/%s", typeName)
	if rd.swagger.Definitions[typeName] != nil {
		log.Printf("addDef(): Definition for %s already exists: %v, use %s", typeName, *rd.swagger.Definitions[typeName], ref)
		return ref
	}
	rd.swagger.Definitions[typeName] = rd.getSchemaDef(entityType)
	log.Printf("addDef(): Added definition for %s: %v, use %s", typeName, *rd.swagger.Definitions[typeName], ref)
	return ref
}

func (rd *Swaggerer) getResponses(route common.Route) map[string]SwaggerResponse {
	responses := make(map[string]SwaggerResponse)
	errorRef := rd.addDef(reflect.TypeOf(common.HttpError{}))
	schema := SwaggerSchema{Ref: errorRef}
	responses["400"] = SwaggerResponse{Description: "Bad request", Schema: schema}
	responses["404"] = SwaggerResponse{Description: "Not found", Schema: schema}
	responses["500"] = SwaggerResponse{Description: "Unexpected error", Schema: schema}
	return responses
}

func (rd *Swaggerer) getParameters(route common.Route) []SwaggerParamOrRef {
	params := make([]SwaggerParamOrRef, 0)

	// Body
	if route.MakeMessage != nil {
		bodyStructPtr := route.MakeMessage()
		if bodyStructPtr != nil {
			param := SwaggerParamOrRef{}
			entityType := reflect.TypeOf(bodyStructPtr).Elem()
			typeName := entityType.String()
			param.Name = typeName
			param.In = SwaggerInBody
			param.Required = true
			// TODO - the doc string of the structure
			desc := rd.analyzer.shortTypeDocs[typeName]
			param.Description = desc
			schema := SwaggerSchema{}
			rd.fillSchema(&schema, entityType)
			param.Schema = schema
			params = append(params, param)
		}
	}

	// Path variables
	pattern := route.Pattern
	pathVars := rd.pathVarRegExp.FindAll([]byte(pattern), -1)
	if len(pathVars) > 0 {
		for _, pathVarByte := range pathVars {
			pathVar := string(pathVarByte)
			param := SwaggerParamOrRef{}
			param.In = SwaggerInPath
			param.Required = true
			param.Type = "string"
			param.Name = pathVar[1 : len(pathVar)-1]
			params = append(params, param)
		}
	}

	// TODO of course this should go over query vars (unclear how yet)
	log.Printf("Params for %s %s %s: %v", rd.service.Name(), route.Method, route.Pattern, params)
	return params
}

// getPaths
func (rd *Swaggerer) getPaths() map[string]*SwaggerPathItem {
	paths := make(map[string]*SwaggerPathItem)
	//	serviceType := reflect.TypeOf(rd.service)
	routes := rd.service.Routes()
	for _, route := range routes {
		method := route.Method
		pattern := route.Pattern
		path := paths[pattern]
		if path == nil {
			path = &SwaggerPathItem{}
			paths[pattern] = path
		}
		op := SwaggerOperation{}

		// Handler is usually referring to some function.
		handler := route.Handler
		handlerFuncPtr := reflect.ValueOf(handler).Pointer()
		handlerFunc := runtime.FuncForPC(handlerFuncPtr)
		handlerFuncName := handlerFunc.Name()

		log.Printf("getPaths(): Handler for %s %s: %s", method, pattern, handlerFuncName)
		// Ok now we have to parse it. It looks like:
		// github.com/romana/core/policy.(*PolicySvc).(github.com/romana/core/policy.findPolicyByName)-fm
		// from which we want
		// github.com/romana/core/policy.PolicySvc.findPolicyByName
		// See also https://play.golang.org/p/nfcBFaDxSL
		handlerFuncName = strings.Replace(handlerFuncName, "-fm", "", 1)
		handlerFuncName = strings.Replace(handlerFuncName, "github.com", "github_com", -1)
		handlerFuncName = strings.Replace(handlerFuncName, ")", "", -1)
		handlerFuncName = strings.Replace(handlerFuncName, "(", "", -1)
		handlerFuncName = strings.Replace(handlerFuncName, "*", "", -1)
		dotted := strings.Split(handlerFuncName, ".")
		op.Summary = dotted[len(dotted)-1]

		if len(dotted) > 3 {
			// TODO Deal with case when it is specified as an anonymous
			// function:
			// github.com/romana/core/common.CreateFindRoutes.func1
			handlerFullName := fmt.Sprintf("%s.%s.%s", strings.Replace(dotted[0], "github_com", "github.com", -1), dotted[1], dotted[3])
			handlerDoc := rd.analyzer.fullTypeDocs[handlerFullName]
			log.Printf("getPaths(): Looking up doc for handler %s: %s", handlerFullName, handlerDoc)
			//op.Summary = "SUMMARY: " + handlerDoc
			op.Description = handlerDoc
		} else {
			log.Printf("getPaths(): Found %s", handlerFunc.Name())
		}
		op.Responses = rd.getResponses(route)
		op.Parameters = rd.getParameters(route)

		method = strings.ToLower(method)

		switch method {
		case "get":
			path.Get = op
		case "post":
			path.Post = op
		case "put":
			path.Put = op
		case "delete":
			path.Delete = op
			// TODO
		}
		log.Printf("getPaths(): %s %s => %+v", method, pattern, *path)
	}
	return paths
}

// NewSwaggerer creates a new instance of Swaggerer.
func NewSwaggerer(analyzer *Analyzer, service common.Service) *Swaggerer {
	pathVarRegExp, _ := regexp.Compile("\\{[^{}]+\\}")
	return &Swaggerer{service: service, analyzer: analyzer, swagger: Swagger{Swagger: "2.0"}, pathVarRegExp: pathVarRegExp}
}

type Swaggerer struct {
	analyzer      *Analyzer
	service       common.Service
	swagger       Swagger
	pathVarRegExp *regexp.Regexp
}

// Process processes the code yielding a []byte of the YAML
// representation of the Swagger defintion. The processing rules are
// as follows:
// 1. For each common.Service found, go over its Routes (whatever Routes() method yields)
//    and based on that create the paths and operations.
// 2. For structs, field-level comments are taken from the description value of
//    "romana" structure tag. For example:
//      type Policy struct {
//          Direction string `json:"direction,omitempty" romana:"desc:Direction is one of 'ingress' or egress'."`
//          ...
//      }
func (rd *Swaggerer) Process() ([]byte, error) {
	rd.init()
	rd.swagger.Paths = rd.getPaths()
	json, err := yaml.Marshal(rd.swagger)
	return json, err
}
