package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// stubScanner отмечает каждое вхождение заданного слова как ФИО.
// Сканеры детекции разрабатываются отдельно; автомат /process проверяется
// независимо от них.
type stubScanner struct {
	word string
}

func (stubScanner) Name() string { return "stub" }

func (s stubScanner) Scan(doc *lex.Doc, _ *dict.Set, out *detect.Candidates) {
	for i := range doc.Tokens {
		if doc.NormOf(i) != s.word {
			continue
		}
		t := doc.Tokens[i]
		out.Add(int(t.Start), int(t.End), pii.FullName, detect.Certain, "stub")
	}
}

func newTestService(t *testing.T, scanners ...detect.Scanner) *Service {
	t.Helper()
	st := store.NewMemory(store.Options{TTL: time.Hour})
	t.Cleanup(func() { _ = st.Close() })
	return New(detect.New(nil, scanners...), st)
}

func newTestConsumer(t *testing.T, demask bool) *policy.Consumer {
	t.Helper()
	c := mustConsumer(t, policy.Consumer{
		ID:             policy.DefaultConsumerID,
		Enabled:        true,
		Types:          pii.FullSet(),
		Demask:         demask,
		MaskingEnabled: true,
	}, strategyPlaceholder)
	return c
}

func TestProcessMaskThenUnmask(t *testing.T) {
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	c := newTestConsumer(t, true)
	const original = "Клиент Иванов обратился в банк"

	first := mustForward(t, svc, testID1, original, c)
	if first.Op != obs.OpMask {
		t.Fatalf("прямой шаг определён как %s", first.Op)
	}
	if strings.Contains(first.Result, surnameIvanov) {
		t.Fatal("исходное значение осталось в маске")
	}
	if !strings.Contains(first.Result, placeholderFIO1) {
		t.Fatalf("плейсхолдер не подставлен: %q", first.Result)
	}

	second := mustBackward(t, svc, testID1, first.Result, c)
	if second.Op != obs.OpUnmask {
		t.Fatalf("обратный шаг определён как %s", second.Op)
	}
	if second.Result != original {
		t.Fatalf(fmtRestoredAs, second.Result, original)
	}
}

func TestProcessForwardRetryIsIdempotent(t *testing.T) {
	// Проверяющая система повторяет запрос при ошибке или 429. Повтор прямого
	// шага обязан вернуть ту же маску, а не создать новую.
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	c := newTestConsumer(t, true)
	const original = "Клиент Иванов и клиент Иванов"

	first := mustForward(t, svc, testID1, original, c)
	retry, err := svc.Process(context.Background(), testID1, original, c)
	if err != nil {
		t.Fatalf("повтор прямого шага: %v", err)
	}
	if retry.Op != obs.OpMaskRetry {
		t.Fatalf("повтор определён как %s", retry.Op)
	}
	if retry.Result != first.Result {
		t.Fatalf("повтор дал другую маску: %q вместо %q", retry.Result, first.Result)
	}
}

func TestProcessMaskIsPureFunction(t *testing.T) {
	// Маскирование не должно зависеть от истории: два разных payload_id с
	// одним текстом дают побайтово одинаковый результат. На этом свойстве
	// держится безопасность параллельных повторов.
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	c := newTestConsumer(t, true)
	const original = "Иванов, Иванов и снова Иванов"

	a, err := svc.Process(context.Background(), "id-a", original, c)
	if err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	b, err := svc.Process(context.Background(), "id-b", original, c)
	if err != nil {
		t.Fatalf("второй вызов: %v", err)
	}
	if a.Result != b.Result {
		t.Fatalf("маски разошлись: %q и %q", a.Result, b.Result)
	}
	// Одинаковые значения получают один номер: текст остаётся связным.
	if n := strings.Count(a.Result, placeholderFIO1); n != 3 {
		t.Fatalf("одинаковые значения получили разные плейсхолдеры: %q", a.Result)
	}
}

func TestProcessIdentityMaskRoundTrip(t *testing.T) {
	// Случай mask(T) == T: персональных данных нет, маска равна оригиналу.
	// Обратный шаг обязан вернуть тот же текст, а не сломаться.
	svc := newTestService(t)
	c := newTestConsumer(t, true)
	const original = "Погода сегодня хорошая"

	first := mustForward(t, svc, testID1, original, c)
	if first.Result != original {
		t.Fatalf("текст без ПД изменён: %q", first.Result)
	}
	second := mustBackward(t, svc, testID1, first.Result, c)
	if second.Result != original {
		t.Fatalf(fmtRestoredAs, second.Result, original)
	}
}

func TestProcessNewTextSameIDStartsNewPair(t *testing.T) {
	// Известный payload_id с другим текстом — новая пара: проверяющая система
	// может повторить набор с теми же идентификаторами. Обратный шаг второй
	// пары обязан вернуть её исходник, а не маску и не исходник первой пары.
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	c := newTestConsumer(t, true)
	const first, second = clientIvanovShort, "Абонент Иванов"

	if _, err := svc.Process(context.Background(), testID1, first, c); err != nil {
		t.Fatalf("прямой шаг первой пары: %v", err)
	}
	fwd, err := svc.Process(context.Background(), testID1, second, c)
	if err != nil {
		t.Fatalf("прямой шаг второй пары: %v", err)
	}
	if fwd.Op != obs.OpMaskConflict {
		t.Fatalf("повтор идентификатора определён как %s", fwd.Op)
	}
	back, err := svc.Process(context.Background(), testID1, fwd.Result, c)
	if err != nil {
		t.Fatalf("обратный шаг второй пары: %v", err)
	}
	if back.Result != second {
		t.Fatalf(fmtRestoredAs, back.Result, second)
	}
}

func TestProcessSameMaskDifferentTextDoesNotLeakFirst(t *testing.T) {
	// Маски двух текстов совпадают («Клиент [ФИО_1]»): обратный шаг второй
	// пары не должен отдать исходник первой.
	svc := newTestService(t, stubScanner{word: stubWordIvanov}, stubScanner{word: "петров"})
	c := newTestConsumer(t, true)
	a, err := svc.Process(context.Background(), testID1, clientIvanovShort, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Process(context.Background(), testID1, "Клиент Петров", c)
	if err != nil {
		t.Fatal(err)
	}
	if a.Result != b.Result {
		t.Skipf("маски различаются (%q, %q) — сценарий совпадения не воспроизведён", a.Result, b.Result)
	}
	back, err := svc.Process(context.Background(), testID1, b.Result, c)
	if err != nil {
		t.Fatal(err)
	}
	if back.Result != "Клиент Петров" {
		t.Fatalf("обратный шаг второй пары вернул %q", back.Result)
	}
}

func TestProcessRejectsEmptyID(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Process(context.Background(), "", "текст", newTestConsumer(t, true)); err != ErrEmptyID {
		t.Fatalf("ожидалась ErrEmptyID, получено: %v", err)
	}
}

func TestProcessDemaskDeniedReturnsMask(t *testing.T) {
	// Потребителю без права демаскирования оригинал не выдаётся, даже если
	// он знает payload_id: идентификатор корреляции не является авторизацией.
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	c := newTestConsumer(t, false)
	const original = clientIvanovShort

	first := mustForward(t, svc, testID1, original, c)
	second := mustBackward(t, svc, testID1, first.Result, c)
	if second.Result != first.Result {
		t.Fatalf("оригинал выдан потребителю без права демаскирования: %q", second.Result)
	}
}

func TestProcessIsolatesConsumers(t *testing.T) {
	// Запись, созданная одним потребителем, не восстанавливается другим.
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	owner := newTestConsumer(t, true)

	other := mustConsumer(t, policy.Consumer{
		ID: consumerOther, Enabled: true, Types: pii.FullSet(), Demask: true, MaskingEnabled: true,
	}, strategyPlaceholder)

	const original = clientIvanovShort
	first := mustForward(t, svc, testID1, original, owner)
	res, err := svc.Process(context.Background(), testID1, first.Result, other)
	if err != nil {
		t.Fatalf(fmtForeignRestoreErr, err)
	}
	if res.Result == original {
		t.Fatal("чужой потребитель получил исходную строку по известному payload_id")
	}
}

func TestMaskFullTextHidesEverything(t *testing.T) {
	res := MaskFullText("Иванов Иван Иванович, паспорт 4509 123456")
	if strings.Contains(res.Text, surnameIvanov) || strings.Contains(res.Text, "4509") {
		t.Fatalf("безопасный откат не скрыл текст: %q", res.Text)
	}
	if !res.Degraded {
		t.Error("безопасный откат не отмечен как деградация")
	}
}

func TestProcessForeignConsumerDoesNotClobberRecord(t *testing.T) {
	// Второй потребитель с тем же payload_id не должен разрушать соответствие
	// первого: иначе обратный шаг владельца перестанет работать.
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	owner := newTestConsumer(t, true)
	other := mustConsumer(t, policy.Consumer{
		ID: consumerOther, Enabled: true, Types: pii.FullSet(), Demask: true, MaskingEnabled: true,
	}, strategyPlaceholder)

	const original = clientIvanovShort
	first, err := svc.Process(context.Background(), testID1, original, owner)
	if err != nil {
		t.Fatalf("прямой шаг владельца: %v", err)
	}
	if _, err := svc.Process(context.Background(), testID1, "чужой текст", other); err != nil {
		t.Fatalf("прямой шаг чужого потребителя: %v", err)
	}
	back, err := svc.Process(context.Background(), testID1, first.Result, owner)
	if err != nil {
		t.Fatalf("обратный шаг владельца: %v", err)
	}
	if back.Result != original {
		t.Fatalf("соответствие владельца разрушено: получено %q вместо %q", back.Result, original)
	}
}

// spanLimitPhones — n строк с различными синтетическими телефонами, как в
// отчёте бизнес-жюри 23.09 (T-52): «Клиент N: телефон +7 916 XXX-XX-XX».
// Возвращает текст и список значений для поиска утечек по одному.
func spanLimitPhones(n int) (string, []string) {
	var b strings.Builder
	b.Grow(n * 52)
	phones := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		d := fmt.Sprintf("%07d", i)
		p := "+7 916 " + d[:3] + "-" + d[3:5] + "-" + d[5:]
		phones = append(phones, p)
		fmt.Fprintf(&b, "Клиент %d: телефон %s\n", i, p)
	}
	return b.String(), phones
}

// limitConsumer — потребитель с полным набором типов и заданным пределом
// замен.
func limitConsumer(t *testing.T, id string, maxSpans int) *policy.Consumer {
	t.Helper()
	c := mustConsumer(t, policy.Consumer{
		ID: id, Enabled: true, Types: pii.FullSet(), Demask: true, MaskingEnabled: true,
		MaxSpans: maxSpans,
	}, strategyPlaceholder)
	return c
}

// TestProcessSpanLimitDegradesAndRestores — T-52 AC-1: 20 050 телефонов при
// пределе 20 000 на /process. До правки ответ содержал 20 000 масок и 50
// открытых номеров; теперь строка скрыта целиком, соответствие записано, и
// обратный шаг возвращает исходник побайтово.
func TestProcessSpanLimitDegradesAndRestores(t *testing.T) {
	svc, st := realService(t, store.Options{})
	c := limitConsumer(t, policy.DefaultConsumerID, 20_000)
	text, phones := spanLimitPhones(20_050)
	ctx := context.Background()

	fwd := mustForward(t, svc, limitID, text, c)
	if !fwd.Degraded || fwd.Op != obs.OpMask {
		t.Fatalf("прямой шаг: degraded=%v op=%s, ожидался безопасный откат маскирования", fwd.Degraded, fwd.Op)
	}
	if fwd.Result != MaskFullText(text).Text {
		t.Fatalf("строка не скрыта целиком: ответ длиной %d байт", len(fwd.Result))
	}
	for _, p := range phones {
		if strings.Contains(fwd.Result, p) {
			t.Fatalf("телефон %q остался в ответе", p)
		}
	}
	if len(fwd.Mask.Applied) != 0 || fwd.Mask.Masked != 0 {
		t.Fatalf("при откате в результате остались замены: %d", len(fwd.Mask.Applied))
	}

	// Запись соответствия завершена до ответа: оригинал лежит в хранилище.
	rec, ok := st.Get(scopedKey(c.ID, limitID))
	if !ok || rec.Original != text || rec.Masked != fwd.Result {
		t.Fatalf("соответствие не записано или записано не то: найдено=%v", ok)
	}

	retry, err := svc.Process(ctx, limitID, text, c)
	if err != nil || retry.Result != fwd.Result || retry.Op != obs.OpMaskRetry {
		t.Fatalf("повтор прямого шага: %v, op=%s", err, retry.Op)
	}

	back := mustBackward(t, svc, limitID, fwd.Result, c)
	if back.Op != obs.OpUnmask || back.Result != text {
		t.Fatalf("обратный шаг не побайтовый: op=%s, длина %d вместо %d", back.Op, len(back.Result), len(text))
	}
}

// TestProcessSpanLimitBoundary — граница предела на /process: замен ровно по
// пределу — штатная маска, на одну больше — строка скрыта целиком.
func TestProcessSpanLimitBoundary(t *testing.T) {
	svc := newTestService(t, stubScanner{word: stubWordIvanov})
	c := limitConsumer(t, policy.DefaultConsumerID, 2)
	ctx := context.Background()

	exact, err := svc.Process(ctx, "b-1", "Иванов, Иванов", c)
	if err != nil || exact.Degraded || exact.Result != "[ФИО_1], [ФИО_1]" {
		t.Fatalf("ровно по пределу: %q degraded=%v err=%v", exact.Result, exact.Degraded, err)
	}

	const over = "Иванов, Иванов, Иванов"
	fwd, err := svc.Process(ctx, "b-2", over, c)
	if err != nil || !fwd.Degraded || strings.Contains(fwd.Result, surnameIvanov) {
		t.Fatalf("сверх предела: %q degraded=%v err=%v", fwd.Result, fwd.Degraded, err)
	}
	back, err := svc.Process(ctx, "b-2", fwd.Result, c)
	if err != nil || back.Result != over {
		t.Fatalf("обратный шаг: %q, %v", back.Result, err)
	}

	// Ядро сообщает причину отличимо: транспорт явного API отвечает на неё
	// своим кодом, а не общим отказом.
	if _, err := svc.Mask(ctx, over, c); !errors.Is(err, ErrSpanLimit) {
		t.Fatalf("Mask сверх предела: %v, ожидалась ErrSpanLimit", err)
	}
}

// TestProcessCoversRepeatedValues — С-4, AC-1 на реальной детекции: повтор
// даты рождения в дате договора и повтор ПИН в коде из смс детекция не
// опознаёт. До T-56 второе вхождение уходило открытым; теперь оно закрыто
// той же маской, а обратный шаг возвращает исходник побайтово.
func TestProcessCoversRepeatedValues(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	for i, tt := range []struct{ text, value, want string }{
		{"Клиент Иванов Иван Иванович, дата рождения 01.02.1990. Договор от 01.02.1990 подписан.", "01.02.1990",
			"Клиент [ФИО_1], дата рождения [ДАТА_РОЖДЕНИЯ_1]. Договор от [ДАТА_РОЖДЕНИЯ_1] подписан."},
		{"Клиент сообщил пин-код 1234, код из смс 1234.", pinValue,
			"Клиент сообщил пин-код [ПИН_1], код из смс [ПИН_1]."},
	} {
		fwd := roundTrip(t, svc, c, fmt.Sprintf("c4-%d", i), tt.text)
		if strings.Contains(fwd.Result, tt.value) {
			t.Fatalf("повтор %q остался открытым: %q", tt.value, fwd.Result)
		}
		if fwd.Result != tt.want {
			t.Fatalf("получено  %q\nожидалось %q", fwd.Result, tt.want)
		}
		if fwd.Mask.MaskedCounts != fwd.Mask.DetectedCounts {
			t.Errorf("замаскировано %v, обнаружено %v", fwd.Mask.MaskedCounts, fwd.Mask.DetectedCounts)
		}
	}
}

// TestProcessRepeatsCountTowardSpanLimit — повторы — тоже замены: если с ними
// замен больше предела, строка скрыта целиком, как при любом превышении.
func TestProcessRepeatsCountTowardSpanLimit(t *testing.T) {
	svc := newTestService(t, markScanner{values: map[string]pii.Type{pinValue: pii.PIN}, firstOnly: true})
	c := limitConsumer(t, policy.DefaultConsumerID, 2)
	ctx := context.Background()

	if _, err := svc.Mask(ctx, "ПИН 1234, код 1234, ещё 1234", c); !errors.Is(err, ErrSpanLimit) {
		t.Fatalf("Mask сверх предела с повторами: %v, ожидалась ErrSpanLimit", err)
	}
	const text = "ПИН 1234, код 1234"
	res, err := svc.Process(ctx, "lim-rep", text, c)
	if err != nil || res.Degraded || res.Result != "ПИН [ПИН_1], код [ПИН_1]" {
		t.Fatalf("ровно по пределу: %q degraded=%v err=%v", res.Result, res.Degraded, err)
	}
}
