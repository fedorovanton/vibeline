package detect

import (
	"context"
	"strings"
	"testing"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Все значения в этом файле синтетические: реальные персональные данные в
// репозиторий не попадают (AGENTS.md, «Инварианты приватности»). Контрольные
// суммы у них при этом верные — иначе тест проверял бы не то правило.

// Синтетические номера, которые повторяются в нескольких проверках файла.
const (
	docsOGRN      = "1027700132195"
	docsOGRNIP    = "304500116000157"
	docsVINMarked = "XTA21099052233445"
	docsVINValid  = "1HGCM82633A004352"
)

func docsDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	set, err := dict.Load()
	if err != nil {
		tb.Fatalf(msgDictLoad, err)
	}
	return set
}

// docsScan прогоняет сканер документов по тексту и отдаёт найденных кандидатов.
func docsScan(tb testing.TB, dicts *dict.Set, text string) []Span {
	tb.Helper()
	var cand Candidates
	docsScanner{}.Scan(lex.Tokenize(text, nil), dicts, &cand)
	return cand.Spans
}

// docsDetect прогоняет текст через движок со всеми зарегистрированными
// сканерами: только так видно, кто выигрывает спор за один и тот же участок.
func docsDetect(tb testing.TB, text string) []Span {
	tb.Helper()
	eng := New(docsDicts(tb), Registered()...)
	var (
		cand Candidates
		res  Result
	)
	out, err := eng.Detect(context.Background(), lex.Tokenize(text, nil), Options{Profile: Balanced}, &cand, &res)
	if err != nil {
		tb.Fatalf("детекция: %v", err)
	}
	return out.Spans
}

// docsSpanOf возвращает спан указанного типа. Второе значение — признак того,
// что такой спан нашёлся ровно один.
func docsSpanOf(spans []Span, t pii.Type) (Span, bool) {
	var found Span
	n := 0
	for _, s := range spans {
		if s.Type == t {
			found, n = s, n+1
		}
	}
	return found, n == 1
}

func TestDocsRecognized(t *testing.T) {
	dicts := docsDicts(t)
	tests := []struct {
		name string
		text string
		span string
		typ  pii.Type
		conf Confidence
	}{
		{"снилс с контрольной суммой", "СНИЛС 112-233-445 95", "112-233-445 95", pii.SNILS, Certain},
		{"снилс одной группой", "снилс 11223344595", "11223344595", pii.SNILS, Certain},
		{"снилс с неверной суммой", "снилс 112-233-445 96", "112-233-445 96", pii.SNILS, Strong},
		{"загранпаспорт", "загранпаспорт 75 1234567", "75 1234567", pii.ForeignPassport, Strong},
		{"полис омс", "полис ОМС 1234567890123456", "1234567890123456", pii.OMSPolicy, Strong},
		{"полис группами", "полис ОМС 1234 5678 9012 3456", "1234 5678 9012 3456", pii.OMSPolicy, Strong},
		{"огрн с контрольной суммой", "ОГРН 1027700132195", docsOGRN, pii.OGRN, Certain},
		{"огрнип с контрольной суммой", "ОГРНИП 304500116000157", docsOGRNIP, pii.OGRN, Certain},
		{"госномер кириллицей", "госномер А123ВС777", "А123ВС777", pii.VehicleReg, Certain},
		{"госномер без маркера", "машина А123ВС77 у подъезда", "А123ВС77", pii.VehicleReg, Certain},
		// T-59, строка 6: регион через пробел.
		{"госномер с регионом через пробел", "госномер А123ВС 77", "А123ВС 77", pii.VehicleReg, Certain},
		{"госномер строчными с регионом через пробел", "а123вс 77", "а123вс 77", pii.VehicleReg, Certain},
		{"госномер с трёхзначным регионом через пробел", "Автомобиль А123ВС 777 припаркован.", "А123ВС 777", pii.VehicleReg, Certain},
		{"госномер латиницей с регионом через пробел", "plate A123BC 77", "A123BC 77", pii.VehicleReg, Certain},
		{"госномер с регионом через неразрывный пробел", "госномер А123ВС 77", "А123ВС 77", pii.VehicleReg, Certain},
		{"vin с контрольной суммой", "VIN 1HGCM82633A004352", docsVINValid, pii.VIN, Certain},
		{"vin по маркеру", "VIN XTA21099052233445", docsVINMarked, pii.VIN, Strong},
		{"vin по форме", "в документе XTA21099052233445 указано", docsVINMarked, pii.VIN, Weak},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ok := docsSpanOf(docsScan(t, dicts, tt.text), tt.typ)
			if !ok {
				t.Fatalf("кандидат типа %v не найден ровно один", tt.typ)
			}
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Conf != tt.conf {
				t.Errorf(msgConfWant, s.Conf, tt.conf)
			}
		})
	}
}

func TestDocsRejected(t *testing.T) {
	dicts := docsDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"госномер с недопустимыми буквами", "госномер Ж123ЩЭ777"},
		{"госномер без региона", "госномер А123ВС"},
		{"полис без маркера", "счёт 1234567890123456"},
		{"загранпаспорт без маркера", "документ 75 1234567"},
		{"снилс без маркера и группировки", "номер 11223344596"},
		{"vin с недопустимой буквой O", "VIN XTO21099052233445"},
		{"семнадцать цифр подряд", "VIN 12345678901234567"},
		{"огрн с неверной суммой", "число 1027700132196"},
		{"короткое число", "код 123"},
		// T-59, строка 6: раздельная запись неоднозначна.
		{"госномер целиком через пробелы", "с 100 на 150"},
		{"госномер раздельно с буквами госномера", "А 123 ВС 77"},
		{"трёхзначный регион через пробел не на 1 и 7", "А123ВС 250"},
		{"регион, продолженный словом", "А123ВС 77км"},
		{"регион через два пробела", "А123ВС  77"},
		{"регион из одной цифры", "А123ВС 7 серии"},
		// T-59, строка 5: ОГРН организации.
		{"огрн банка", "ОГРН банка 1027700132195"},
		{"огрн рядом с ООО", "ООО «Ромашка», ОГРН 1027700132195"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if spans := docsScan(t, dicts, tt.text); len(spans) != 0 {
				t.Fatalf(msgNoCandidates, len(spans), tt.text[spans[0].Start:spans[0].End])
			}
		})
	}
}

// TestDocsWinOverCardNumber — главная проверка задачи. До T-17 шестнадцать
// цифр полиса, тринадцать цифр ОГРН и цифровой хвост VIN уходили в номер
// банковской карты: это и ложное отнесение, и бесполезная маска — буквенный
// префикс VIN оставался открытым.
func TestDocsWinOverCardNumber(t *testing.T) {
	tests := []docsWinCase{
		{"полис не карта", "Клиент Иванов Иван Иванович, полис ОМС 1234567890123456", "1234567890123456", pii.OMSPolicy},
		{"огрн не карта", "Клиент Иванов Иван Иванович, ОГРН 1027700132195", docsOGRN, pii.OGRN},
		{"vin не карта", "Клиент Иванов Иван Иванович, VIN XTA21099052233445", docsVINMarked, pii.VIN},
		{"госномер не cvv", "Клиент Иванов Иван Иванович, госномер А123ВС777", "А123ВС777", pii.VehicleReg},
		{"снилс не телефон", "Клиент Иванов Иван Иванович, снилс 764-736-402 00", "764-736-402 00", pii.SNILS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkDocWinsOverDigits(t, tt) })
	}
}

// docsWinCase — текст с документом, его значение и тип.
type docsWinCase struct {
	name string
	text string
	span string
	typ  pii.Type
}

// docsDigitsType сообщает, относится ли тип к тем, что сканер цифр мог бы
// поставить на цифры документа.
func docsDigitsType(t pii.Type) bool {
	return t == pii.CardNumber || t == pii.CVV || t == pii.Phone
}

// checkDocWinsOverDigits — один случай TestDocsWinOverCardNumber: документ
// найден ровно один, и на его участке нет спанов номера карты, CVV или
// телефона.
func checkDocWinsOverDigits(t *testing.T, tt docsWinCase) {
	t.Helper()
	spans := docsDetect(t, tt.text)
	s, ok := docsSpanOf(spans, tt.typ)
	if !ok {
		t.Fatalf("спан типа %v не найден ровно один среди %d", tt.typ, len(spans))
	}
	if got := tt.text[s.Start:s.End]; got != tt.span {
		t.Errorf(msgSpanWant, got, tt.span)
	}
	for _, other := range spans {
		if docsDigitsType(other.Type) && other.Start < s.End && other.End > s.Start {
			t.Errorf("на участке документа остался чужой тип %v", other.Type)
		}
	}
}

// TestDocsKeepsForeignTypesIntact проверяет, что запрет действует только на
// участке документа: ИНН и карта в том же предложении не страдают.
//
// До T-59 фраза начиналась словом «Организация». Теперь это маркер
// организации, и ИНН с ОГРН рядом с ним — реквизиты юрлица, которые не
// маскируются (TestDocsOrgOGRN), поэтому фраза сменила начало.
func TestDocsKeepsForeignTypesIntact(t *testing.T) {
	const text = "Анкета: ИНН 7707083893, ОГРН 1027700132195, оплата картой 4111 1111 1111 1111"
	spans := docsDetect(t, text)
	for _, want := range []pii.Type{pii.INN, pii.CardNumber, pii.OGRN} {
		if _, ok := docsSpanOf(spans, want); !ok {
			t.Errorf("тип %v не найден ровно один среди %d спанов", want, len(spans))
		}
	}
}

// TestDocsOrgOGRN — ОГРН организации не маскируется ни одним типом: запрет
// ставится на участок, и цифры не достаются номеру карты (T-59, строка 5).
// ОГРНИП предпринимателя — реквизит человека — по-прежнему маскируется.
func TestDocsOrgOGRN(t *testing.T) {
	t.Run("огрн банка не маскируется", func(t *testing.T) {
		const text = "Банк: ОГРН 1027700132195, оплата картой 4111 1111 1111 1111"
		spans := docsDetect(t, text)
		at := strings.Index(text, docsOGRN)
		for _, s := range spans {
			if int(s.Start) < at+13 && int(s.End) > at {
				t.Errorf("ОГРН организации замаскирован как %s (%s)", s.Type, s.Rule)
			}
		}
		if _, ok := docsSpanOf(spans, pii.CardNumber); !ok {
			t.Error("карта в том же предложении не найдена")
		}
	})
	t.Run("огрнип рядом с банком маскируется", func(t *testing.T) {
		const text = "ИП, счёт в банке, ОГРНИП 304500116000157"
		s, ok := docsSpanOf(docsDetect(t, text), pii.OGRN)
		if !ok || text[s.Start:s.End] != docsOGRNIP {
			t.Fatal("ОГРНИП не найден")
		}
	})
}

// TestDocsPlateSkipsRegion — код региона через пробел входит в спан госномера
// и не разбирается отдельно: ни ВУ старого образца, ни другой тип на «77».
func TestDocsPlateSkipsRegion(t *testing.T) {
	const text = "Клиент Иванов Иван Иванович, права 77 АВ 123456, госномер А123ВС 77."
	spans := docsDetect(t, text)
	s, ok := docsSpanOf(spans, pii.VehicleReg)
	if !ok || text[s.Start:s.End] != "А123ВС 77" {
		t.Fatalf("госномер не найден ровно один: %d спанов", len(spans))
	}
	for _, o := range spans {
		if o.Type != pii.VehicleReg && o.Start < s.End && o.End > s.Start {
			t.Errorf("на участке госномера чужой тип %s", o.Type)
		}
	}
}

// TestDocsChecksums проверяет контрольные суммы отдельно от разбора текста.
func TestDocsChecksums(t *testing.T) {
	t.Run("огрн", checkOGRNChecksum)
	t.Run("vin", checkVINChecksum)
	t.Run("снилс", checkSNILSChecksum)
}

// checkOGRNChecksum — контрольная сумма ОГРН и ОГРНИП.
func checkOGRNChecksum(t *testing.T) {
	valid := []string{docsOGRN, docsOGRNIP}
	invalid := []string{"1027700132196", "304500116000158", "102770013219", "", "10277001321a5"}
	for _, v := range valid {
		if !OGRN(v) {
			t.Errorf("ОГРН %q признан неверным", v)
		}
	}
	for _, v := range invalid {
		if OGRN(v) {
			t.Errorf("ОГРН %q признан верным", v)
		}
	}
}

// checkVINChecksum — контрольный символ VIN без учёта регистра.
func checkVINChecksum(t *testing.T) {
	if !VINCheck(docsVINValid) {
		t.Error("контрольный символ верного VIN не сошёлся")
	}
	if !VINCheck(strings.ToLower(docsVINValid)) {
		t.Error("проверка VIN зависит от регистра")
	}
	for _, v := range []string{"1HGCM82633A004353", "XTO21099052233445", "1HGCM82633A00435"} {
		if VINCheck(v) {
			t.Errorf("VIN %q признан верным", v)
		}
	}
}

// checkSNILSChecksum — контрольная сумма СНИЛС.
func checkSNILSChecksum(t *testing.T) {
	if !SNILS("11223344595") {
		t.Error("контрольная сумма верного СНИЛС не сошлась")
	}
	if SNILS("11223344596") {
		t.Error("неверная контрольная сумма СНИЛС принята")
	}
}

// docsBenchBlock — синтетический фрагмент со всеми ветками разбора.
const docsBenchBlock = "Анкета: СНИЛС 112-233-445 95, загранпаспорт 75 1234567, полис ОМС 1234 5678 9012 3456. " +
	"Транспорт: госномер А123ВС777, VIN 1HGCM82633A004352, второй VIN XTA21099052233445, второй госномер К456МН 750. " +
	"Банк: ОГРН 1027700132195. " +
	"Организация: ОГРН 1027700132195, ОГРНИП 304500116000157, ИНН 7707083893. " +
	"Посторонние числа: карта 4111 1111 1111 1111, телефон 8 916 123 45 67, код 123, счёт 40817810099910004312.\n"

var docsBenchText = strings.Repeat(docsBenchBlock, 4096/len(docsBenchBlock)+1)

func BenchmarkScanDocs(b *testing.B) {
	if len(docsBenchText) < 4096 || len(docsBenchText) > 8192 {
		b.Fatalf(msgBenchTextSize, len(docsBenchText))
	}
	doc := lex.Tokenize(docsBenchText, nil)
	dicts := docsDicts(b)
	var cand Candidates
	s := docsScanner{}
	s.Scan(doc, dicts, &cand)
	if len(cand.Spans) == 0 {
		b.Fatal("в тексте бенчмарка не найдено ни одного документа")
	}
	b.SetBytes(int64(len(docsBenchText)))
	b.ReportAllocs()
	for b.Loop() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}
}
