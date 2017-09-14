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
	return Cache{Items: items}
}

type Cache struct {
	Items map[string]interface{}
	sync.Mutex
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
