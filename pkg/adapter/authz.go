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

package adapter

type (
	// AuthzAspect checks permissions for an incoming request.
	AuthzAspect interface {
		Aspect

		// CheckPolicy does permission check based on RequestContext.
		CheckPolicy(RequestContext) (bool, error)
	}

	// AuthzBuilder builds instances of the AuthzAspect.
	AuthzBuilder interface {
		Builder

		// AuthzAspect returns a new instance of the AuthzAspect.
		NewAuthzAspect(env Env, c Config) (AuthzAspect, error)
	}

	RequestContext struct {
		// Target namespace.
		TargetNamespace string

		// Target service.
		Service string

		// HTTP request path, or gRPC method.
		Path string

		// HTTP verb.
		Verb string

		// Source Namespace.
		SourceNamespace string

		// The client service account.
		ServiceAccount string

		// The end user.
		User string

		// The groups the client belongs to.
		Groups string
	}
)
