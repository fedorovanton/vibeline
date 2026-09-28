package corpus

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

// AC-1: модуль не импортирует ai-gateway.
//
// Требование не формальное: корпус, собранный теми же грамматиками и
// справочниками, что и детектор, измеряет совпадение кода с самим собой, а не
// качество детекции (docs/spec/ACCEPTANCE.md §4). Тест сторожит границу.
func TestNoGatewayImports(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		files++
		return checkFileImports(t, fset, path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("не найдено ни одного файла модуля: тест ничего не проверил")
	}
	t.Logf("проверено файлов: %d", files)
}

// checkFileImports отмечает импорты ai-gateway и внешних модулей в одном файле.
func checkFileImports(t *testing.T, fset *token.FileSet, path string) error {
	t.Helper()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(p, "ai-gateway"):
			t.Errorf("%s импортирует %s: корпус не должен зависеть от детектора", path, p)
		case strings.HasPrefix(p, "corpusgen/"):
			// собственный модуль
		case strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
			t.Errorf("%s импортирует внешнюю зависимость %s: инструменту достаточно стандартной библиотеки", path, p)
		}
	}
	return nil
}

// Модуль обязан быть самостоятельным: свой go.mod без блока require.
func TestModuleIsStandalone(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "module corpusgen") {
		t.Fatalf("go.mod объявляет не тот модуль:\n%s", text)
	}
	if strings.Contains(text, "require") || strings.Contains(text, "replace") {
		t.Fatalf("go.mod содержит зависимости:\n%s", text)
	}
}
