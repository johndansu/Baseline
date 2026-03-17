package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestCLIEntrypointsUseTracedRunner(t *testing.T) {
	t.Helper()

	expected := map[string]map[string]bool{
		filepath.Clean("commands.go"): {
			"HandleVersion":        false,
			"HandleCheck":          false,
			"HandleEnforce":        false,
			"HandleScan":           false,
			"HandleInit":           false,
			"HandleReport":         false,
			"HandleGenerate":       false,
			"HandlePR":             false,
			"HandleExplain":        false,
			"HandleSecurityAdvice": false,
			"HandleAPI":            false,
		},
		filepath.Clean("ci.go"): {
			"HandleCI": false,
		},
		filepath.Clean("dashboard.go"): {
			"HandleDashboard": false,
		},
		filepath.Clean("dashboard_connect.go"): {
			"handleDashboardConnect":    false,
			"handleDashboardStatus":     false,
			"handleDashboardDisconnect": false,
		},
	}

	fset := token.NewFileSet()
	for filePath, funcs := range expected {
		file, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filePath, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, tracked := funcs[fn.Name.Name]; !tracked {
				continue
			}
			funcs[fn.Name.Name] = functionUsesRunTracedCommand(fn)
		}
	}

	for filePath, funcs := range expected {
		for fnName, found := range funcs {
			if !found {
				t.Fatalf("%s in %s does not use runTracedCommand; new CLI entrypoints must go through the traced runner", fnName, filePath)
			}
		}
	}
}

func functionUsesRunTracedCommand(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if ok && ident.Name == "runTracedCommand" {
			found = true
			return false
		}
		return true
	})
	return found
}
