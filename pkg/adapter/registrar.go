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

// Registrar is used by adapters to register aspect builders.
type Registrar interface {
	// RegisterAuthzBuilder registers a new Authz builder.
	RegisterAuthzBuilder(AuthzBuilder)

	// RegisterListsBuilder registers a new ListChecker builder.
	RegisterListsBuilder(ListsBuilder)

	// RegisterDenialsBuilder registers a new DenyChecker builder.
	RegisterDenialsBuilder(DenialsBuilder)

	// RegisterApplicationLogsBuilder registers a new Logger builder.
	RegisterApplicationLogsBuilder(ApplicationLogsBuilder)

	// RegisterAccessLogsBuilder registers a new AccessLogger builder.
	RegisterAccessLogsBuilder(AccessLogsBuilder)

	// RegisterAttributesGeneratorBuilder registers a new builder for the
	// AttributeGenerators aspect.
	RegisterAttributesGeneratorBuilder(AttributesGeneratorBuilder)

	// RegisterQuotasBuilder registers a new Quota builder.
	RegisterQuotasBuilder(QuotasBuilder)

	// RegisterMetricsBuilder registers a new Metrics builder.
	RegisterMetricsBuilder(MetricsBuilder)
}

// RegisterFn is a function Mixer invokes to trigger adapters to register
// their aspect builders. It must succeed or panic().
type RegisterFn func(Registrar)
