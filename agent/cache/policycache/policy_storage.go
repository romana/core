package policycache

import (
	"github.com/romana/core/agent/cache"
	"github.com/romana/core/common/api"
)

type Interface interface {
	Put(string, api.Policy)
	Get(string) (api.Policy, bool)
	Delete(string)
	List() []api.Policy
	Keys() []string
}

type PolicyStorage struct {
	store cache.Interface
}

func New() Interface {
	return &PolicyStorage{cache.New()}
}

func (p *PolicyStorage) Put(key string, policy api.Policy) {
	p.store.Put(key, policy)
}

func (p *PolicyStorage) Get(key string) (api.Policy, bool) {
	item, ok := p.store.Get(key)
	if !ok {
		return api.Policy{}, ok
	}

	policy, ok := item.(api.Policy)
	if !ok {
		return api.Policy{}, ok
	}

	return policy, ok
}

func (p *PolicyStorage) List() []api.Policy {
	var result []api.Policy
	items := p.store.List()
	for _, item := range items {
		policy, ok := item.(api.Policy)
		if !ok {
			continue
		}
		result = append(result, policy)
	}
	return result
}

func (p *PolicyStorage) Keys() []string {
	return p.store.Keys()
}

func (p *PolicyStorage) Delete(key string) {
	p.store.Delete(key)
}
