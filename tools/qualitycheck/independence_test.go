package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Инструмент измеряет качество чужого кода и потому обязан быть от него
// независим: импорт ai-gateway превратил бы отчёт в сверку кода с самим собой
// (docs/spec/ACCEPTANCE.md §4). Сервис виден только через HTTP-контракт.
func TestNoGatewayImports(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		imports, ierr := importsOf(fset, path)
		for _, p := range imports {
			if p == "ai-gateway" || strings.HasPrefix(p, "ai-gateway/") {
				t.Errorf("%s импортирует %s", path, p)
			}
		}
		return ierr
	})
	if err != nil {
		t.Fatalf("обход исходников: %v", err)
	}
}

// importsOf возвращает пути импорта файла. При ошибке разбора пути возвращаются
// те, что прочитаны до неё.
func importsOf(fset *token.FileSet, path string) ([]string, error) {
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Модуль обязан быть отдельным и не тянуть зависимостей: чем меньше у
// измерительного инструмента общего с измеряемым, тем меньше поводов не верить
// его цифрам.
func TestModuleIsStandaloneWithoutDependencies(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("чтение go.mod: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "module qualitycheck") {
		t.Errorf("go.mod не объявляет отдельный модуль:\n%s", text)
	}
	for _, forbidden := range []string{"require", "replace", "ai-gateway"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("go.mod содержит %q:\n%s", forbidden, text)
		}
	}
	if _, err := os.Stat("go.sum"); err == nil {
		t.Error("у модуля появился go.sum: внешних зависимостей быть не должно")
	}
}
