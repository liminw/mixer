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

package config

import (
	"errors"
	"flag"
	"fmt"
	"reflect"
	"strings"
	"testing"

	multierror "github.com/hashicorp/go-multierror"

	"istio.io/mixer/pkg/attribute"
	pb "istio.io/mixer/pkg/config/proto"
)

type trueEval struct {
	err    error
	ncalls int
	ret    bool
}

func (t *trueEval) EvalPredicate(expression string, attrs attribute.Bag) (bool, error) {
	if t.ncalls == 0 {
		return t.ret, t.err
	}
	t.ncalls--
	return true, nil
}

type ttable struct {
	err    error
	ncalls int
	ret    bool
	nlen   int
	asp    []string
}

func TestGetScopes(t *testing.T) {
	table := []struct {
		target  string
		domain  string
		scopes  []string
		success bool
	}{
		{"my-svc.my-namespace.svc.cluster.local", "svc.cluster.local", []string{
			"global", "my-namespace.svc.cluster.local", "my-svc.my-namespace.svc.cluster.local"}, true},
		{"my-svc.my-namespace.svc.cluster.local", ".svc.cluster.local", []string{
			"global", "my-namespace.svc.cluster.local", "my-svc.my-namespace.svc.cluster.local"}, true},
		{"my-svc.my-namespace.corp", "corp", []string{
			"global", "my-namespace.corp", "my-svc.my-namespace.corp"}, true},
		{"my-svc", "cluster.local.", []string{
			"global", "my-namespace", "my-svc.my-namespace"}, false},
	}

	for _, tt := range table {
		t.Run(tt.target, func(t1 *testing.T) {
			got := make([]string, 0, 10)
			got, err := GetScopes(tt.target, tt.domain, got)
			if (err == nil) != tt.success {
				t1.Errorf("got %s\nwant %t", err, tt.success)
				return
			}
			if tt.success && !reflect.DeepEqual(got, tt.scopes) {
				t1.Errorf("got %s\nwant %s", got, tt.scopes)
			}
		})
	}

}

func buildServiceConfig(key string, kinds []string) *pb.ServiceConfig {
	aspects := make([]*pb.Aspect, len(kinds))
	for idx, kind := range kinds {
		aspects[idx] = &pb.Aspect{
			Kind: kind,
			Inputs: map[string]string{
				key: "true",
			},
		}
	}
	return &pb.ServiceConfig{
		Rules: []*pb.AspectRule{
			{
				Aspects: aspects,
			},
		},
	}
}

type fakeresolver struct {
	am           map[string]KindSet
	resolveError error
}

func newFakeResolver(kinds []string, kind KindSet, re error) *fakeresolver {
	am := make(map[string]KindSet)

	for _, k := range kinds {
		am[k] = kind
	}
	return &fakeresolver{am: am, resolveError: re}
}

func (fr *fakeresolver) rrf(bag attribute.Bag, kindSet KindSet, rules []*pb.AspectRule, path string,
	dlist []*pb.Combined, onlyEmptySelectors bool) ([]*pb.Combined, error) {
	if fr.resolveError != nil {
		return nil, fr.resolveError
	}
	for _, r := range rules {
		for _, a := range r.Aspects {
			if fr.am[a.Kind] == kindSet {
				dlist = append(dlist, &pb.Combined{Aspect: a})
			}
		}
	}
	return dlist, nil
}

func buildRule(rule []*fakeRule) map[rulesKey]*pb.ServiceConfig {
	rules := map[rulesKey]*pb.ServiceConfig{}

	for _, p := range rule {
		pk := rulesKey{p.scope, p.subject}
		rules[pk] = buildServiceConfig(fmt.Sprintf("%s", pk), p.kinds)
	}
	return rules
}

type fakeRule struct {
	scope   string
	subject string
	kinds   []string
}

func fP(scope string, subject string, kinds ...string) *fakeRule {
	return &fakeRule{scope, subject, kinds}
}

// TestResolve multi rules resolve
func TestResolve(t *testing.T) {
	table := []struct {
		target       string
		rule         []*fakeRule
		kinds        []string
		makebag      bool
		err          error
		resolveError error
		// check if the aspect is from the correct scope
		assertions map[string]string
	}{
		{"svc1.ns1.svc.cluster.local", []*fakeRule{
			fP("global", "global", "metric0", "metric1")},
			[]string{"metric0"},
			true,
			nil, nil,
			map[string]string{
				"metric0": "global/global",
			},
		},
		{"svc1.ns1.svc.cluster.local", []*fakeRule{
			fP("global", "global", "metric0", "metric1"),
			fP("global", "ns1.svc.cluster.local", "metric0", "metric1"),
		},
			[]string{"metric0"},
			true,
			nil, nil,
			map[string]string{
				"metric0": "global/ns1.svc.cluster.local",
			},
		},
		{"svc1.ns1.svc.cluster.local", []*fakeRule{
			fP("global", "global", "metric0", "metric1"),
			fP("global", "ns1.svc.cluster.local", "metric0"),
			fP("global", "svc1.ns1.svc.cluster.local", "metric1"),
		},
			[]string{"metric0", "metric1"},
			true,
			nil, nil,
			map[string]string{
				"metric0": "global/ns1.svc.cluster.local",
				"metric1": "global/svc1.ns1.svc.cluster.local",
			},
		},
		{"svc1.ns1.svc.cluster.local", []*fakeRule{
			fP("global", "global", "metric0", "metric1")},
			[]string{"metric0"},
			false,
			errors.New("attribute not found"), nil,
			map[string]string{
				"metric0": "global/global",
			},
		},
		{"svc1", []*fakeRule{
			fP("global", "global", "metric0", "metric1")},
			[]string{"metric0"},
			true,
			errors.New("interal error: scope"), nil,
			map[string]string{
				"metric0": "global/global",
			},
		},
		{"svc1.ns1.svc.cluster.local", []*fakeRule{
			fP("global", "global", "metric0", "metric1")},
			[]string{"metric0"},
			true,
			errors.New("unable to resolve"), errors.New("unable to resolve"),
			map[string]string{
				"metric0": "global/global",
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.target, func(t1 *testing.T) {
			rules := buildRule(tt.rule)
			attrs := map[string]interface{}{}
			if tt.makebag {
				attrs[keyTargetService] = tt.target
			}
			b := &bag{attrs}
			var ks KindSet = 0xff
			fr := newFakeResolver(tt.kinds, ks, tt.resolveError)
			dl, err := resolve(b, ks, rules, fr.rrf, false, keyTargetService, keyServiceDomain)
			if err != nil {
				if tt.err == nil {
					t1.Fatal("Unexpected Error", err)
				}
				if strings.Contains(err.Error(), tt.err.Error()) {
					return
				}
				t1.Fatalf("got %s\nwant %s", err, tt.err)
			}
			byKind := map[string][]*pb.Combined{}
			for _, dd := range dl {
				byKind[dd.Aspect.Kind] = append(byKind[dd.Aspect.Kind], dd)
			}
			// check if combined correctly
			for k, v := range tt.assertions {
				found := false
				for _, kl := range byKind[k] {
					if kl.Aspect.Inputs[v] != "" {
						found = true
						break
					}
				}
				if !found {
					t1.Fatalf("got %s\n want %s from %s", byKind[k], k, v)
				}
			}
		})
	}

}

func TestRuntime(t *testing.T) {
	table := []*ttable{
		{nil, 0, true, 4, []string{ListsKindName}},
		{nil, 1, false, 2, []string{ListsKindName}},
		{errors.New("predicate error"), 1, false, 2, []string{ListsKindName}},
		{nil, 0, true, 0, []string{}},
		{errors.New("predicate error"), 0, true, 0, []string{ListsKindName}},
	}

	LC := ListsKindName
	a1 := &pb.Adapter{
		Name: "a1",
		Kind: LC,
	}
	a2 := &pb.Adapter{
		Name: "a2",
		Kind: LC,
	}

	v := &Validated{
		adapterByName: map[adapterKey]*pb.Adapter{
			{ListsKind, "a1"}: a1,
			{ListsKind, "a2"}: a2,
		},
		rule: map[rulesKey]*pb.ServiceConfig{
			globalRulesKey: {
				Rules: []*pb.AspectRule{
					{
						Selector: "ok",
						Aspects: []*pb.Aspect{
							{
								Kind: LC,
							},
							{
								Adapter: "a2",
								Kind:    LC,
							},
						},
						Rules: []*pb.AspectRule{
							{
								Selector: "ok",
								Aspects: []*pb.Aspect{
									{
										Kind: LC,
									},
									{
										Adapter: "a2",
										Kind:    LC,
									},
								},
							},
						},
					},
				},
			},
		},
		numAspects: 1,
	}

	bag := &bag{attrs: map[string]interface{}{
		keyTargetService: "svc1.ns1.svc.cluster.local",
	}}

	for idx, tt := range table {
		fe := &trueEval{tt.err, tt.ncalls, tt.ret}
		var kinds KindSet
		for _, a := range tt.asp {
			k, _ := ParseKind(a)
			kinds = kinds.Set(k)
		}
		rt := newRuntime(v, fe, keyTargetService, keyServiceDomain)

		al, err := rt.Resolve(bag, kinds)

		if tt.err != nil {
			if err != tt.err {
				merr, _ := err.(*multierror.Error)
				if merr == nil {
					t.Fatalf("got %#v\nwant %#v", err, tt.err)
				}
				if merr.Errors[0] != tt.err {
					t.Error(idx, "expected:", tt.err, "\ngot:", merr.Errors[0])
				}
			}
		}

		if len(al) != tt.nlen {
			t.Errorf("%d Expected %d resolve got %d", idx, tt.nlen, len(al))
		}
	}
}

func TestRuntime_ResolveUnconditional(t *testing.T) {
	table := []*ttable{
		{nil, 0, true, 2, []string{AttributesKindName}},
		{nil, 0, true, 0, []string{}},
	}

	LC := ListsKindName
	a1 := &pb.Adapter{
		Name: "a1",
		Kind: LC,
	}
	a2 := &pb.Adapter{
		Name: "a2",
		Kind: LC,
	}
	ag := &pb.Adapter{
		Name: "ag",
		Kind: AttributesKindName,
	}

	v := &Validated{
		adapterByName: map[adapterKey]*pb.Adapter{
			{ListsKind, "a1"}:      a1,
			{ListsKind, "a2"}:      a2,
			{AttributesKind, "ag"}: ag,
		},
		rule: map[rulesKey]*pb.ServiceConfig{
			globalRulesKey: {
				Rules: []*pb.AspectRule{
					{
						Selector: "ok",
						Aspects: []*pb.Aspect{
							{
								Kind: LC,
							},
							{
								Adapter: "a2",
								Kind:    LC,
							},
						},
						Rules: []*pb.AspectRule{
							{
								Selector: "ok",
								Aspects: []*pb.Aspect{
									{
										Kind: LC,
									},
									{
										Adapter: "a2",
										Kind:    LC,
									},
								},
							},
						},
					},
					{
						Selector: "",
						Aspects: []*pb.Aspect{
							{
								Kind: AttributesKindName,
							},
							{
								Adapter: "ag",
								Kind:    AttributesKindName,
							},
						},
					},
				},
			},
		},
		numAspects: 2,
	}

	bag := &bag{attrs: map[string]interface{}{
		keyTargetService: "svc1.ns1.svc.cluster.local",
	}}

	for idx, tt := range table {
		fe := &trueEval{tt.err, tt.ncalls, tt.ret}
		var kinds KindSet
		for _, a := range tt.asp {
			k, _ := ParseKind(a)
			kinds = kinds.Set(k)
		}
		rt := newRuntime(v, fe, keyTargetService, keyServiceDomain)

		al, err := rt.ResolveUnconditional(bag, kinds)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(al) != tt.nlen {
			t.Errorf("[%d] Expected %d resolves got %d", idx, tt.nlen, len(al))
		}

		for _, cfg := range al {
			if cfg.Aspect.Kind != AttributesKindName {
				t.Errorf("Got aspect kind: %v, want %v", cfg.Aspect.Kind, AttributesKindName)
			}
		}
	}
}

func init() {
	// bump up the log level so log-only logic runs during the tests, for correctness and coverage.
	_ = flag.Lookup("v").Value.Set("99")
}

// fake bag
type bag struct {
	attrs map[string]interface{}
}

func (b *bag) Get(name string) (interface{}, bool) {
	c, found := b.attrs[name]
	return c, found
}

func (b *bag) Names() []string {
	return []string{}
}

func (b *bag) Done() {
}
