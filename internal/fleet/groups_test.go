package fleet

import (
	"reflect"
	"testing"
)

func TestGroupRepositoriesPartitionsByObservedEvidence(t *testing.T) {
	targets := []TargetResult{
		{Name: "z-inconclusive", Status: StatusInconclusive},
		{Name: "route-ok", Status: StatusOK, Complete: true, Routes: 3},
		{Name: "non-gin", Status: StatusOK, Complete: true, Modules: []ModuleResult{{Kind: ModuleGo, Status: StatusOK, Complete: true}}},
		{Name: "gin-zero", Status: StatusOK, Complete: true, Modules: []ModuleResult{{Kind: ModuleGinNoRoutes, Status: StatusOK, Complete: true}}},
		{Name: "partial-zero", Status: StatusOK, Modules: []ModuleResult{{Kind: ModuleGinNoRoutes, Status: StatusOK}}},
		{Name: "failed-with-routes", Status: StatusFailed, Routes: 2},
		{Name: "failed-zero", Status: StatusFailed},
		{Name: "not-go", Status: StatusNotGoModule, Complete: true},
		{Name: "legacy-zero", Status: StatusOK, Complete: true},
	}

	got := GroupRepositories(targets)
	want := &RepositoryGroups{
		WithRoutes: []string{"failed-with-routes", "route-ok"},
		Reference: []RepositoryReference{
			{Name: "failed-zero", Category: CategoryFailed},
			{Name: "gin-zero", Category: CategoryGinNoRoutes},
			{Name: "legacy-zero", Category: CategoryNoRoutesUnverified},
			{Name: "non-gin", Category: CategoryNonGin},
			{Name: "not-go", Category: CategoryNotGoModule},
			{Name: "partial-zero", Category: CategoryNoRoutesUnverified},
			{Name: "z-inconclusive", Category: CategoryInconclusive},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GroupRepositories() = %#v, want %#v", got, want)
	}
	if targets[0].Name != "z-inconclusive" {
		t.Fatal("GroupRepositories reordered the source targets")
	}
}

func TestRepositoryCategoryRequiresCompleteModuleEvidenceForZeroRoutes(t *testing.T) {
	tests := []struct {
		name   string
		target TargetResult
		want   string
	}{
		{
			name: "mixed complete Gin and Go modules",
			target: TargetResult{Status: StatusOK, Complete: true, Modules: []ModuleResult{
				{Kind: ModuleGinNoRoutes, Status: StatusOK, Complete: true},
				{Kind: ModuleGo, Status: StatusOK, Complete: true},
			}},
			want: CategoryGinNoRoutes,
		},
		{
			name: "incomplete target",
			target: TargetResult{Status: StatusOK, Complete: false, Modules: []ModuleResult{
				{Kind: ModuleGinNoRoutes, Status: StatusOK, Complete: true},
			}},
			want: CategoryNoRoutesUnverified,
		},
		{
			name: "incomplete module",
			target: TargetResult{Status: StatusOK, Complete: true, Modules: []ModuleResult{
				{Kind: ModuleGinNoRoutes, Status: StatusOK, Complete: false},
			}},
			want: CategoryNoRoutesUnverified,
		},
		{
			name:   "failed target with retained route evidence",
			target: TargetResult{Status: StatusFailed, Complete: false, Routes: 1},
			want:   CategoryGinRoutes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := RepositoryCategory(test.target); got != test.want {
				t.Fatalf("RepositoryCategory() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGroupRepositoriesEmptyUsesJSONArrays(t *testing.T) {
	groups := GroupRepositories(nil)
	if groups.WithRoutes == nil || groups.Reference == nil {
		t.Fatalf("empty groups must use non-nil slices: %#v", groups)
	}
}
