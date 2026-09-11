package fleet

import "sort"

// RepositoryGroups is a derived index, not a replacement for Targets. It
// keeps route-bearing repositories separate from reference outcomes without
// changing audit, discovery, coverage, or resume semantics.
type RepositoryGroups struct {
	WithRoutes []string              `json:"withRoutes"`
	Reference  []RepositoryReference `json:"reference"`
}

type RepositoryReference struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

const (
	CategoryGinRoutes          = "gin-routes"
	CategoryGinNoRoutes        = "gin-no-routes"
	CategoryNoRoutesUnverified = "no-routes-unverified"
	CategoryNonGin             = "non-gin"
	CategoryNotGoModule        = "not-go-module"
	CategoryFailed             = "failed"
	CategoryInconclusive       = "inconclusive"
)

// RepositoryCategory never equates process success or a Gin dependency with
// an application. A failed/partial scan can still carry real route evidence;
// retain that evidence in the main view with its failure/coverage visible.
func RepositoryCategory(target TargetResult) string {
	if target.Routes > 0 {
		return CategoryGinRoutes
	}
	switch target.Status {
	case StatusFailed:
		return CategoryFailed
	case StatusInconclusive:
		return CategoryInconclusive
	case StatusNotGoModule:
		if target.Complete {
			return CategoryNotGoModule
		}
		return CategoryInconclusive
	case StatusOK:
		if !target.Complete || len(target.Modules) == 0 {
			return CategoryNoRoutesUnverified
		}
		gin := false
		for _, module := range target.Modules {
			if module.Status != StatusOK || !module.Complete {
				return CategoryNoRoutesUnverified
			}
			switch module.Kind {
			case ModuleGinNoRoutes, ModuleGinApplication:
				gin = true
			case ModuleGo:
			default:
				return CategoryNoRoutesUnverified
			}
		}
		if gin {
			return CategoryGinNoRoutes
		}
		return CategoryNonGin
	default:
		return CategoryInconclusive
	}
}

func GroupRepositories(targets []TargetResult) *RepositoryGroups {
	groups := &RepositoryGroups{WithRoutes: []string{}, Reference: []RepositoryReference{}}
	for _, target := range targets {
		category := RepositoryCategory(target)
		if category == CategoryGinRoutes {
			groups.WithRoutes = append(groups.WithRoutes, target.Name)
		} else {
			groups.Reference = append(groups.Reference, RepositoryReference{Name: target.Name, Category: category})
		}
	}
	sort.Strings(groups.WithRoutes)
	sort.Slice(groups.Reference, func(i, j int) bool { return groups.Reference[i].Name < groups.Reference[j].Name })
	return groups
}
