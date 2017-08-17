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

package authz

import (
	"istio.io/mixer/adapter/authz/config"
	"istio.io/mixer/pkg/adapter"
)

const (
	cUnknown   = 0
	cNamespace = 1
	cService   = 2
	cMethod    = 3
)

type builder struct{ adapter.DefaultBuilder }

type access struct {
	resources  []string
	verbs      []string
	permission string
}

type policy struct {
	permissions []string
	members     []string
}

type authzChecker struct {
	kind      int
	namespace string
	service   string
	mappings  []*access
	policies  []*policy
}

var (
	name = "authz"
	desc = "Basic authorization check"
	conf = &config.Params{}
)

// Register records the builders exposed by this adapter.
func Register(r adapter.Registrar) {
	r.RegisterAuthzBuilder(newBuilder())
}

func newBuilder() builder {
	return builder{adapter.NewDefaultBuilder(name, desc, conf)}
}

func (builder) NewAuthzAspect(env adapter.Env, c adapter.Config) (adapter.AuthzAspect, error) {
	return newAuthzChecker(env, c.(*config.Params))
}

func newAuthzChecker(env adapter.Env, c *config.Params) (*authzChecker, error) {
	var ac authzChecker
	switch c.Kind {
	case config.UNKNOWN:
		ac.kind = cUnknown
	case config.NAMESPACE:
		ac.kind = cNamespace
	case config.SERVICE:
		ac.kind = cService
	case config.METHOD:
		ac.kind = cMethod
	}
	ac.namespace = c.Namespace
	ac.service = c.ServiceName
	ac.mappings = make([]*access, len(c.Mappings))
	for index, entry := range c.Mappings {
		resources := make([]string, len(entry.Resources))
		for i, r := range entry.Resources {
			resources[i] = r
		}
		verbs := make([]string, len(entry.Verbs))
		for j, v := range entry.Verbs {
			verbs[j] = v
		}
		ac.mappings[index] = &access{resources, verbs, entry.Permission}
	}
	ac.policies = make([]*policy, len(c.Policies))
	for index, entry := range c.Policies {
		permissions := make([]string, len(entry.Permissions))
		for i, p := range entry.Permissions {
			permissions[i] = p
		}
		members := make([]string, len(entry.Members))
		for j, m := range entry.Members {
			members[j] = m.Kind + ":" + m.Name
		}
		ac.policies[index] = &policy{permissions, members}
	}
	return &ac, nil
}

func (a *authzChecker) Close() error { return nil }

func (a *authzChecker) CheckPolicy(r adapter.RequestContext) (bool, error) {
	var res string
	if a.kind == cNamespace {
		res = r.TargetNamespace
	}
	if a.kind == cService {
		if a.namespace != r.TargetNamespace {
			return false, nil // the policy does not apply to the namespace
		}
		res = r.Service
	}
	if a.kind == cMethod {
		if a.namespace != r.TargetNamespace || a.service != r.Service {
			return false, nil // the policy does not apply to the namesapce or service
		}
		res = r.Path
	}

	var perms []string
	var matchRes bool
	for _, entry := range a.mappings {
		matchRes = false
		for _, r := range entry.resources {
			if r == "*" || r == res {
				matchRes = true
				break
			}
		}
		if matchRes {
			for _, v := range entry.verbs {
				if v == "*" || v == r.Verb {
					perms = append(perms, entry.permission)
				}
			}
		}
	}

	if len(perms) == 0 {
		return false, nil
	}

	var memList []string
	var matchPerm bool
	for _, po := range a.policies {
		matchPerm = false
		for _, perm := range perms {
			for _, policyPerm := range po.permissions {
				if perm == policyPerm {
					matchPerm = true
					break
				}
			}
		}
		if matchPerm {
			for _, mem := range po.members {
				memList = append(memList, mem)
			}
		}
	}

	if len(memList) == 0 {
		return false, nil
	}

	var id []string
	if len(r.SourceNamespace) > 0 {
		id = append(id, "Namespace:"+r.SourceNamespace)
	}
	if len(r.ServiceAccount) > 0 {
		id = append(id, "ServiceAccount:"+r.ServiceAccount)
	}
	if len(r.User) > 0 {
		id = append(id, "User:"+r.User)
	}
	if len(r.Groups) > 0 {
		id = append(id, "Group:"+r.Groups) // Groups needs extra handling. Let's leave it this way for now.
	}
	success := false
	for _, mem := range memList {
		for _, oneId := range id {
			if oneId == mem {
				success = true
				break
			}
		}
	}
	return success, nil
}
