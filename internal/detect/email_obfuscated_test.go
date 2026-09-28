package detect

import (
	"testing"

	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Адреса в этом файле синтетические: реальные персональные данные в
// репозиторий не попадают (AGENTS.md, «Инварианты приватности»).

// TestEmailObfuscated — адрес со словом вместо «@» и точки (технический
// жюри 23.09, раунд 5, P5-8): кандидат Strong ровно по записи адреса, без
// слова-подписи и точки конца предложения.
func TestEmailObfuscated(t *testing.T) {
	dicts := emailDicts(t)
	tests := []struct {
		name string
		text string
		span string
	}{
		{"собака в скобках", "пишите ivan.petrov(собака)mail.ru", "ivan.petrov(собака)mail.ru"},
		{"at и dot через пробелы", "почта ivan (at) mail dot ru", "ivan (at) mail dot ru"},
		{"квадратные скобки", "ivan[at]mail[dot]ru", "ivan[at]mail[dot]ru"},
		{"dot в скобках и точка предложения", "адрес ivan (at) mail (dot) ru.", "ivan (at) mail (dot) ru"},
		{"точка словом", "ivan(собака)mail точка ru", "ivan(собака)mail точка ru"},
		{"поддомен", "ivan[at]corp.mail.example.com", "ivan[at]corp.mail.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cand := emailScan(t, dicts, tt.text)
			if len(cand.Spans) != 1 {
				t.Fatalf(msgOneCandidateGot, len(cand.Spans), cand.Spans)
			}
			s := cand.Spans[0]
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Type != pii.Email || s.Conf != Strong {
				t.Errorf("кандидат %v %v, ожидался email Strong", s.Type, s.Conf)
			}
		})
	}
}

// TestEmailObfuscatedRejected — скобки со словом «at» или «собака», которые
// адресом не являются.
func TestEmailObfuscatedRejected(t *testing.T) {
	dicts := emailDicts(t)
	for _, text := range []string{
		"Встреча (at) home",
		"Звони (at) 10.30",
		"Я (собака) дома",
		"ivan (at) mail",
		"ivan (at)mail dot",
		"ivan (at) mail dot r",
		"ivan at mail dot ru",
		"ivan (at)  mail.ru",
		"(at) mail.ru",
	} {
		t.Run(text, func(t *testing.T) {
			if cand := emailScan(t, dicts, text); len(cand.Spans) != 0 {
				t.Fatalf(msgNoCandidates, len(cand.Spans), text[cand.Spans[0].Start:cand.Spans[0].End])
			}
		})
	}
}

// TestEmailObfuscatedOrgVeto — служебный ящик организации в той же записи
// закрыт тем же контр-правилом, что и с «@».
func TestEmailObfuscatedOrgVeto(t *testing.T) {
	cand := emailScan(t, emailDicts(t), "info(at)bank.ru")
	if len(cand.Spans) != 1 || len(cand.Vetos) != 1 {
		t.Fatalf("кандидатов %d, вето %d; ожидалось по одному", len(cand.Spans), len(cand.Vetos))
	}
	checkEmailVetoCoversSpan(t, cand.Vetos[0], cand.Spans[0])
}

// TestEmailObfuscatedNoAllocs — разбор записи со скобками не аллоцирует.
func TestEmailObfuscatedNoAllocs(t *testing.T) {
	const text = "пишите ivan.petrov(собака)mail.ru или ivan (at) mail (dot) ru, встреча (at) home"
	doc := lex.Tokenize(text, nil)
	dicts := emailDicts(t)
	var (
		s    emailScanner
		cand Candidates
	)
	s.Scan(doc, dicts, &cand)
	if n := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}); n != 0 {
		t.Fatalf(msgScanAllocs, n)
	}
}
