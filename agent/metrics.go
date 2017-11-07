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

package agent

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/romana/core/agent/enforcer"
	log "github.com/romana/rlog"
)

var (
	NumManagedRoutes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "romana_managed_routes",
			Help: "Number of routes managed by Romana agent on the host.",
		},
	)
)

func MetricStart(port int) error {
	if port <= 0 {
		return nil
	}

	registry := prometheus.NewRegistry()
	err := enforcer.MetricsRegister(registry)
	if err != nil {
		return err
	}

	err = registry.Register(NumManagedRoutes)
	if err != nil {
		return err
	}

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError})

	go func() {
		http.Handle("/", handler)
		log.Errorf("Metrics publishing stopped due to %s", http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
	}()

	return nil
}
