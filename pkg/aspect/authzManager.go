// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aspect

import (
	"fmt"

	rpc "github.com/googleapis/googleapis/google/rpc"

	"istio.io/mixer/pkg/adapter"
	aconfig "istio.io/mixer/pkg/aspect/config"
	"istio.io/mixer/pkg/attribute"
	"istio.io/mixer/pkg/config"
	"istio.io/mixer/pkg/config/descriptor"
	cpb "istio.io/mixer/pkg/config/proto"
	"istio.io/mixer/pkg/expr"
	"istio.io/mixer/pkg/status"
)

type (
	authzManager struct{}

	authzExecutor struct {
		aspect adapter.AuthzAspect
		params *aconfig.AuthzParams
	}
)

// newAuthzManager returns a manager for the authz aspect.
func newAuthzManager() CheckManager {
	return authzManager{}
}

// NewCheckExecutor creates a authz aspect.
func (authzManager) NewCheckExecutor(cfg *cpb.Combined, createAspect CreateAspectFunc, env adapter.Env,
	df descriptor.Finder, _ string) (CheckExecutor, error) {
	out, err := createAspect(env, cfg.Builder.Params.(config.AspectParams))
	if err != nil {
		return nil, err
	}
	asp, ok := out.(adapter.AuthzAspect)
	if !ok {
		return nil, fmt.Errorf("wrong aspect type returned after creation; expected AuthzAspect: %#v", out)
	}
	return &authzExecutor{
		aspect: asp,
		params: cfg.Aspect.Params.(*aconfig.AuthzParams),
	}, nil
}

func (authzManager) Kind() config.Kind {
	return config.AuthzKind
}

func (authzManager) DefaultConfig() config.AspectParams {
	return &aconfig.AuthzParams{}
}

func (authzManager) ValidateConfig(c config.AspectParams, tc expr.TypeChecker, df descriptor.Finder) (ce *adapter.ConfigErrors) {
	cfg := c.(*aconfig.AuthzParams)
	if cfg.TargetNamespace == "" {
		ce = ce.Appendf("targetNamespace", "not provided")
	} else if cfg.Service == "" {
		ce = ce.Appendf("service", "not provided")
	}
	return
}

func (a *authzExecutor) Execute(attrs attribute.Bag, mapper expr.Evaluator) rpc.Status {
	var request adapter.RequestContext
	request.TargetNamespace = a.params.TargetNamespace
	request.Service = a.params.Service
	request.Path = a.params.Path
	request.Verb = a.params.Verb
	request.SourceNamespace = a.params.SourceNamespace
	request.ServiceAccount = a.params.ServiceAccount
	request.User = a.params.User
	request.Groups = a.params.Groups
	var success bool
	var err error
	if success, err = a.aspect.CheckPolicy(request); err != nil {
		return status.WithError(err)
	}

	if success {
		return status.OK
	}

	return status.WithPermissionDenied("")
}

func (a *authzExecutor) Close() error { return a.aspect.Close() }
