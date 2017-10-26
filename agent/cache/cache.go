// Copyright (c) 2017 Pani Networks
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

package cache

import "sync"

type Interface interface {
	Put(string, interface{})
	Get(string) (interface{}, bool)
	Delete(string)
	List() []interface{}
	Keys() []string
}

func New() Interface {
	items := make(map[string]interface{})
	m := &sync.Mutex{}
	return Cache{Items: items, Mutex: m}
}

// note: implementation here uses methods on struct
// instead of pointers because map itself is a pointer.

type Cache struct {
	Items map[string]interface{}
	*sync.Mutex
}

func (s Cache) Put(key string, item interface{}) {
	s.Lock()
	defer s.Unlock()
	s.Items[key] = item
}

func (s Cache) Get(key string) (interface{}, bool) {
	s.Lock()
	defer s.Unlock()
	item, ok := s.Items[key]
	return item, ok
}

func (s Cache) Delete(key string) {
	s.Lock()
	defer s.Unlock()
	delete(s.Items, key)
}

func (s Cache) List() []interface{} {
	s.Lock()
	defer s.Unlock()
	var result []interface{}

	for _, v := range s.Items {
		result = append(result, v)
	}

	return result
}

func (s Cache) Keys() []string {
	s.Lock()
	defer s.Unlock()
	var result []string

	for k, _ := range s.Items {
		result = append(result, k)
	}

	return result
}
