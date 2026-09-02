package gin

import (
	"go/types"
	"testing"
)

func TestFindResolvesCoreGinTypes(t *testing.T) {
	_, api := loadFixture(t, "enforcement-shapes")
	if api.Engine == nil {
		t.Error("Engine not resolved")
	}
	if api.RouterGroup == nil {
		t.Error("RouterGroup not resolved")
	}
	if api.Context == nil {
		t.Error("Context not resolved")
	}
	if api.HandlerFunc == nil {
		t.Error("HandlerFunc not resolved")
	}
}

func TestFindReturnsFalseWhenGinNotImported(t *testing.T) {
	_, ok := Find(map[string]*types.Package{
		"fmt": types.NewPackage("fmt", "fmt"),
	})
	if ok {
		t.Error("Find() = true for an import set with no gin-gonic/gin, want false")
	}
}

func TestIsRouterValueDistinguishesEngineAndGroup(t *testing.T) {
	_, api := loadFixture(t, "enforcement-shapes")

	enginePtr := types.NewPointer(api.Engine)
	groupPtr := types.NewPointer(api.RouterGroup)

	if isEngine, isGroup := api.IsRouterValue(enginePtr); !isEngine || isGroup {
		t.Errorf("IsRouterValue(*Engine) = (%v, %v), want (true, false)", isEngine, isGroup)
	}
	if isEngine, isGroup := api.IsRouterValue(groupPtr); isEngine || !isGroup {
		t.Errorf("IsRouterValue(*RouterGroup) = (%v, %v), want (false, true)", isEngine, isGroup)
	}
	if isEngine, isGroup := api.IsRouterValue(types.Typ[types.String]); isEngine || isGroup {
		t.Errorf("IsRouterValue(string) = (%v, %v), want (false, false)", isEngine, isGroup)
	}
}

func TestIsHandlerFuncTypeAcceptsNamedAndStructural(t *testing.T) {
	_, api := loadFixture(t, "enforcement-shapes")

	named := api.HandlerFunc
	if !api.IsHandlerFuncType(named) {
		t.Error("IsHandlerFuncType(gin.HandlerFunc) = false, want true")
	}

	// func(*gin.Context) with no gin.HandlerFunc alias — structurally
	// identical, which real target code frequently uses (a middleware
	// variable typed as the bare signature rather than the named alias).
	structural := types.NewSignatureType(nil, nil, nil,
		types.NewTuple(types.NewVar(0, nil, "", types.NewPointer(api.Context))),
		nil, false)
	if !api.IsHandlerFuncType(structural) {
		t.Error("IsHandlerFuncType(func(*gin.Context)) = false, want true")
	}

	if api.IsHandlerFuncType(types.Typ[types.String]) {
		t.Error("IsHandlerFuncType(string) = true, want false")
	}
}
