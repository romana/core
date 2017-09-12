// Copyright (c) 2016 Pani Networks
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

package main

// +build ignore

import (
	"encoding/csv"
	"flag"
	"os"
	"text/template"
)

func main() {
	templatePath := flag.String("template", "", "template to render")
	dataFilePath := flag.String("data", "", "")
	outputPath := flag.String("out", "", "")
	flag.Parse()

	template, err := template.ParseFiles(*templatePath)
	if err != nil {
		panic(err)
	}

	data, err := os.Open(*dataFilePath)
	if err != nil {
		panic(err)
	}

	r := csv.NewReader(data)
	r.Comma = '\t'
	r.LazyQuotes = true

	records, err := r.ReadAll()
	if err != nil {
		panic(err)
	}

	out, err := os.OpenFile(*outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	err = template.Execute(out, records)
	if err != nil {
		panic(err)
	}

	err = out.Close()
	if err != nil {
		panic(err)
	}
}
