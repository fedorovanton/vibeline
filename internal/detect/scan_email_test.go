package detect

import (
	"context"
	"strings"
	"testing"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Адреса в этом файле синтетические: реальные персональные данные в
// репозиторий не попадают (AGENTS.md, «Инварианты приватности»).

// Синтетические личные адреса, которые повторяются в нескольких проверках.
const (
	emailPersonal     = "ivan@mail.ru"
	emailPersonalFull = "ivan.petrov@mail.ru"
)

func emailDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	set, err := dict.Load()
	if err != nil {
		tb.Fatalf(msgDictLoad, err)
	}
	return set
}

// emailScan прогоняет сканер адресов по тексту и отдаёт накопитель целиком:
// вето — такой же результат работы сканера, как и кандидат.
func emailScan(tb testing.TB, dicts *dict.Set, text string) *Candidates {
	tb.Helper()
	cand := &Candidates{}
	emailScanner{}.Scan(lex.Tokenize(text, nil), dicts, cand)
	return cand
}

func TestEmailFormats(t *testing.T) {
	dicts := emailDicts(t)
	tests := []struct {
		name string
		text string
		span string
	}{
		{"простой", emailPersonalFull, emailPersonalFull},
		{"точка предложения", "напишите на ivan@mail.ru.", emailPersonal},
		{"в скобках", "контакт (ivan@mail.ru) для связи", emailPersonal},
		{"в кавычках", "адрес «ivan@mail.ru»", emailPersonal},
		{"перед запятой", "ivan@mail.ru, добавочный 12", emailPersonal},
		{"все допустимые знаки", "пишите: a.b-c_1+tag%x@sub.example.co.uk", "a.b-c_1+tag%x@sub.example.co.uk"},
		{"цифры в домене", "robot1@mail2.example.com", "robot1@mail2.example.com"},
		{"дефис в домене", "ivan@my-mail.example.com", "ivan@my-mail.example.com"},
		{"верхний регистр", "IVAN.PETROV@Mail.RU", "IVAN.PETROV@Mail.RU"},
		{"кириллица", "иван@почта.рф", "иван@почта.рф"},
		{"ведущий разделитель отброшен", "адрес:.ivan@mail.ru", emailPersonal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkEmailFormat(t, dicts, tt.text, tt.span) })
	}
}

// checkEmailFormat — один случай TestEmailFormats: ровно один достоверный
// кандидат email на ожидаемом участке и без вето.
func checkEmailFormat(t *testing.T, dicts *dict.Set, text, span string) {
	t.Helper()
	cand := emailScan(t, dicts, text)
	if len(cand.Spans) != 1 {
		t.Fatalf(msgOneCandidateGot, len(cand.Spans), cand.Spans)
	}
	s := cand.Spans[0]
	if got := text[s.Start:s.End]; got != span {
		t.Errorf(msgSpanWant, got, span)
	}
	if s.Type != pii.Email {
		t.Errorf("тип %v, ожидался %v", s.Type, pii.Email)
	}
	if s.Conf != Certain {
		t.Errorf(msgConfWant, s.Conf, Certain)
	}
	if len(cand.Vetos) != 0 {
		t.Errorf("вето не ожидалось, получено %d", len(cand.Vetos))
	}
}

func TestEmailRejected(t *testing.T) {
	dicts := emailDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"пробелы вокруг собаки", "цена 100 @ 5"},
		{"без локальной части", "пишите на @mail.ru"},
		{"пробел перед собакой", "ivan @mail.ru"},
		{"пробел после собаки", "ivan@ mail.ru"},
		{"без верхнего домена", "логин ivan@mail"},
		{"однобуквенный верхний домен", "ivan@mail.r"},
		{"без домена", "ivan@"},
		{"домен из цифр", "ivan@127.0.0.1"},
		{"смешанные алфавиты", "ivanиван@mail.ru"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if cand := emailScan(t, dicts, tt.text); len(cand.Spans) != 0 {
				t.Fatalf(msgNoCandidates,
					len(cand.Spans), tt.text[cand.Spans[0].Start:cand.Spans[0].End])
			}
		})
	}
}

func TestEmailSeveralInText(t *testing.T) {
	const text = "первый ivan@mail.ru, второй petr@example.com."
	cand := emailScan(t, emailDicts(t), text)
	if len(cand.Spans) != 2 {
		t.Fatalf("найдено %d кандидатов, ожидалось два", len(cand.Spans))
	}
	want := [2]string{emailPersonal, "petr@example.com"}
	for i, s := range cand.Spans {
		if got := text[s.Start:s.End]; got != want[i] {
			t.Errorf("спан %d — %q, ожидался %q", i, got, want[i])
		}
	}
}

// TestEmailOrgVeto проверяет, что адреса организаций регистрируются вместе с
// вето и до результата не доходят: решение принимает движок, а не сканер.
func TestEmailOrgVeto(t *testing.T) {
	dicts := emailDicts(t)
	engine := New(dicts, emailScanner{})
	tests := []emailVetoCase{
		{"служебный ящик и домен банка", "пишите на info@alfabank.ru", true, false},
		{"служебная локальная часть", "support@example.org", true, false},
		{"домен организации", "ivan@alfabank.ru", true, false},
		{"личный адрес", emailPersonalFull, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkEmailOrgVeto(t, dicts, engine, tt) })
	}
}

// emailVetoCase — адрес и ожидаемые вето сканера и присутствие типа email в
// результате движка.
type emailVetoCase struct {
	name    string
	text    string
	vetoed  bool
	inFound bool
}

// checkEmailOrgVeto — один случай TestEmailOrgVeto.
func checkEmailOrgVeto(t *testing.T, dicts *dict.Set, engine *Engine, tt emailVetoCase) {
	t.Helper()
	cand := emailScan(t, dicts, tt.text)
	if len(cand.Spans) != 1 {
		t.Fatalf(msgOneCandidate, len(cand.Spans))
	}
	if got := len(cand.Vetos) == 1; got != tt.vetoed {
		t.Fatalf("вето %v, ожидалось %v", got, tt.vetoed)
	}
	if tt.vetoed {
		checkEmailVetoCoversSpan(t, cand.Vetos[0], cand.Spans[0])
	}

	var engineCand Candidates
	var res Result
	_, _ = engine.Detect(context.Background(), lex.Tokenize(tt.text, nil), Options{}, &engineCand, &res)
	if got := res.Found.Has(pii.Email); got != tt.inFound {
		t.Errorf("тип email в результате: %v, ожидалось %v", got, tt.inFound)
	}
}

// checkEmailVetoCoversSpan — вето совпадает со спаном адреса и снимает тип
// email.
func checkEmailVetoCoversSpan(t *testing.T, v Veto, s Span) {
	t.Helper()
	if v.Start != s.Start || v.End != s.End {
		t.Errorf("вето [%d,%d) не совпало со спаном [%d,%d)", v.Start, v.End, s.Start, s.End)
	}
	if !v.Types.Has(pii.Email) {
		t.Errorf("вето на типы %v, ожидался %v", v.Types, pii.Email)
	}
}

// TestEmailSpanByteOffsets проверяет, что смещения спана байтовые: кириллица
// слева от адреса занимает по два байта на букву.
func TestEmailSpanByteOffsets(t *testing.T) {
	const text = "Почта: ivan@mail.ru."
	const want = emailPersonal
	cand := emailScan(t, emailDicts(t), text)
	if len(cand.Spans) != 1 {
		t.Fatalf(msgOneCandidate, len(cand.Spans))
	}
	// «Почта: » — семь символов, из них пять кириллических: 12 байт.
	if cand.Spans[0].Start != 12 {
		t.Errorf("начало спана %d, ожидалось 12", cand.Spans[0].Start)
	}
	if int(cand.Spans[0].Start) != strings.Index(text, want) {
		t.Errorf(msgSpanStartWant, cand.Spans[0].Start, strings.Index(text, want))
	}
	if int(cand.Spans[0].End) != strings.Index(text, want)+len(want) {
		t.Errorf(msgSpanEndWant, cand.Spans[0].End, strings.Index(text, want)+len(want))
	}
}

// emailBenchBlock — синтетический фрагмент со всеми ветками разбора.
const emailBenchBlock = "Контакты заявителя: ivan.petrov@example.com, запасной a.b-c_1+tag@sub.example.co.uk. " +
	"Дублирующий адрес иван@почта.рф, рабочий robot1@mail2.example.com. " +
	"Служебные ящики info@alfabank.ru и support@example.org персональными данными не являются. " +
	"Напишите на ivan@mail.ru. Неполные строки: @example.com, ivan@mail, ivan@mail.r, 100 @ 5.\n"

var emailBenchText = strings.Repeat(emailBenchBlock, 4096/len(emailBenchBlock)+1)

func BenchmarkScanEmail(b *testing.B) {
	if len(emailBenchText) < 4096 || len(emailBenchText) > 8192 {
		b.Fatalf(msgBenchTextSize, len(emailBenchText))
	}
	doc := lex.Tokenize(emailBenchText, nil)
	dicts := emailDicts(b)
	var cand Candidates
	s := emailScanner{}
	// Прогрев: накопитель набирает ёмкость, чтобы в измерении остался только
	// разбор. Аллокаций в Scan быть не должно.
	s.Scan(doc, dicts, &cand)
	if len(cand.Spans) == 0 || len(cand.Vetos) == 0 {
		b.Fatalf("в тексте бенчмарка %d адресов и %d вето", len(cand.Spans), len(cand.Vetos))
	}
	b.SetBytes(int64(len(emailBenchText)))
	b.ReportAllocs()
	for b.Loop() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}
}
