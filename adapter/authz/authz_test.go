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
	//	"istio.io/mixer/adapter/authz/config"
	"testing"

	"istio.io/mixer/pkg/adapter/test"
)

func TestAll(t *testing.T) {
	b := newBuilder()

	a, err := b.NewAuthzAspect(nil, b.DefaultConfig())
	if err != nil {
		t.Errorf("Unable to create aspect: %v", err)
	}

	if err = a.Close(); err != nil {
		t.Errorf("a.Close failed: %v", err)
	}
}

func TestInvariants(t *testing.T) {
	test.AdapterInvariants(Register, t)
}
