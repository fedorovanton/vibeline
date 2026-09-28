package gateway

import (
	"context"
	"strings"
	"testing"

	"ai-gateway/internal/llm"
	"ai-gateway/internal/mask"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/store"
)

// Строка 6 задачи T-68 (Б4-8 бизнес-жюри, раунд 4): синтетика с моделью.
//
// Входы — тексты живых вызовов model-call-4 и model-call-5 бизнес-жюри,
// значения в них вымышленные. Подставная модель повторяет ответы AlfaGen
// из тех же вызовов: сохранённый ответ дословно и ответ той же формы на
// маску, которую сервис выдаёт теперь.

const (
	// call4Input — вызов 4: клиентка, в ответе модель пишет имя и отчество и
	// последние четыре цифры карты.
	call4Input = "Клиентка Шевчук Оксана Васильевна, тел. +7 927 318-44-09, карта 4377 7348 8504 2276, " +
		"просит перенести дату платежа по кредиту. Напиши ей короткое SMS, обратись по имени и " +
		"отчеству и укажи последние четыре цифры карты."
	// call4Reply — ответ AlfaGen на вызов 4 дословно (маска тогда была мужской).
	call4Reply = "Уважаемый Пётр Петрович! Получили Ваш запрос о переносе даты платежа по кредиту. " +
		"Для обработки заявки подтвердите, пожалуйста, операцию по карте **** 0002. С уважением, Банк."

	// call5Input — вызов 5: клиент, модель пишет имя и отчество через «е» и
	// полный номер карты.
	call5Input = "Клиент Смирнов Олег Петрович, тел. +7 915 222-33-44, просит закрыть вклад и перевести " +
		"остаток на карту 5469 3861 8808 1802. Напиши ему короткое SMS: обратись по имени и отчеству, " +
		"продублируй полный номер карты."
	// call5Reply — ответ AlfaGen на вызов 5 дословно.
	call5Reply = "Петр Петрович, ваш запрос на закрытие вклада и перевод остатка на карту " +
		"**4000 0000 0000 0002** принят. Средства будут зачислены в течение 1 рабочего дня. " +
		"Спасибо, что выбрали наш банк."
)

// replayModel отвечает заданным текстом и запоминает, что получил.
type replayModel struct {
	reply func(sent string) string
	sent  string
}

func (m *replayModel) Chat(_ context.Context, req llm.Request) (*llm.Response, error) {
	m.sent = req.Messages[0].Content
	return &llm.Response{Choices: []llm.Choice{{
		Message: llm.Message{Role: roleAssistant, Content: m.reply(m.sent)},
	}}}, nil
}

func proxySynthetic(t *testing.T, input string, reply func(string) string, demask bool) (sent, got string, res ProxyResult) {
	t.Helper()
	svc, _ := realService(t, store.Options{})
	model := &replayModel{reply: reply}
	res = mustProxy(t, svc, model, ProxyRequest{ID: "b4-8",
		Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: input}}}},
		strategyConsumer(t, syntheticStrategy, demask))
	return model.sent, replyOf(res), res
}

// TestSyntheticCall5RestoresPartialName — вызов 5 дословно: «Петр Петрович»
// (часть синтетического ФИО, «е» вместо «ё») восстанавливается в «Олег
// Петрович», полный синтетический номер карты — в настоящий. Раньше клиент
// получал «Сидоров Пётр»: повторная детекция находила в части маски новое
// ФИО и маскировала его следующей синтетикой.
func TestSyntheticCall5RestoresPartialName(t *testing.T) {
	sent, got, _ := proxySynthetic(t, call5Input, func(string) string { return call5Reply }, true)
	if !strings.Contains(sent, fioPetrov) || !strings.Contains(sent, "4000 0000 0000 0002") {
		t.Fatalf("в модель ушла не та маска, ответ AlfaGen к ней не подходит: %q", sent)
	}
	want := "Олег Петрович, ваш запрос на закрытие вклада и перевод остатка на карту " +
		"**5469 3861 8808 1802** принят. Средства будут зачислены в течение 1 рабочего дня. " +
		"Спасибо, что выбрали наш банк."
	if got != want {
		t.Fatalf("ответ клиенту:\nполучено  %q\nожидалось %q", got, want)
	}
}

// TestSyntheticCall4NoForeignName — вызов 4 дословно. Маска теперь женская
// («Петрова Анна Петровна»), и «Пётр Петрович» из прежнего ответа модели
// маской не является. Клиентка не получает ни вымышленного «Сидорова Петра»,
// ни «Петра Петровича» как настоящего имени: чужое ФИО в ответе — плейсхолдер.
// Последние цифры синтетической карты восстанавливаются в последние цифры
// настоящей.
func TestSyntheticCall4NoForeignName(t *testing.T) {
	sent, got, res := proxySynthetic(t, call4Input, func(string) string { return call4Reply }, true)
	if !strings.Contains(sent, "Петрова Анна Петровна") {
		t.Fatalf("маска клиентки не в женском роде: %q", sent)
	}
	for _, bad := range []string{"Сидоров", "Пётр", "Петр", "0002"} {
		if strings.Contains(got, bad) {
			t.Errorf("клиентке ушло вымышленное %q: %q", bad, got)
		}
	}
	if !strings.Contains(got, "**** 2276") {
		t.Errorf("последние цифры карты не восстановлены: %q", got)
	}
	if !strings.Contains(got, "[ФИО_") || res.ResponseMasked == 0 {
		t.Errorf("чужое ФИО из ответа не помечено плейсхолдером (%d): %q", res.ResponseMasked, got)
	}
}

// TestSyntheticCall4CurrentMaskForms — ответ той же формы, что у AlfaGen в
// вызове 4, но на нынешнюю маску: имя с отчеством, падежные формы и
// последние цифры карты восстанавливаются в значения клиентки.
func TestSyntheticCall4CurrentMaskForms(t *testing.T) {
	reply := func(string) string {
		return "Уважаемая Анна Петровна! Получили Ваш запрос о переносе даты платежа по кредиту. " +
			"Для обработки заявки подтвердите операцию по карте **** 0002. " +
			"Ответ отправим Анне Петровне, копию — Петровой."
	}
	_, got, res := proxySynthetic(t, call4Input, reply, true)
	want := "Уважаемая Оксана Васильевна! Получили Ваш запрос о переносе даты платежа по кредиту. " +
		"Для обработки заявки подтвердите операцию по карте **** 2276. " +
		"Ответ отправим Оксане Васильевне, копию — Шевчук."
	if got != want {
		t.Fatalf("ответ клиентке:\nполучено  %q\nожидалось %q", got, want)
	}
	if res.ResponseMasked != 0 {
		t.Errorf("восстановленные формы замаскированы повторно: %d", res.ResponseMasked)
	}
}

// TestSyntheticWithoutDemaskIsMarked — без права demask синтетика и её формы
// не выдаются клиенту как настоящие данные: на их месте плейсхолдеры, и ни
// одного настоящего значения в ответе нет.
func TestSyntheticWithoutDemaskIsMarked(t *testing.T) {
	reply := func(sent string) string { return sent + " Анна Петровна, карта **** 0002." }
	_, got, _ := proxySynthetic(t, call4Input, reply, false)
	for _, bad := range []string{"Петрова", "Анна", "0002", "Шевчук", "Оксана", "2276", "+7 900"} {
		if strings.Contains(got, bad) {
			t.Errorf("в ответе без права demask осталось %q: %q", bad, got)
		}
	}
	if !strings.Contains(got, placeholderFIO1) || !strings.Contains(got, "[КАРТА_1]") {
		t.Errorf("синтетика не помечена плейсхолдерами: %q", got)
	}
}

// TestDerivedFormsNeedWordBoundary — производная форма ищется только
// отдельным словом: «0002» внутри длинного числа и «Анна» внутри «Аннабель»
// не трогаются.
func TestDerivedFormsNeedWordBoundary(t *testing.T) {
	const orig = "Шевчук Оксана Васильевна, карта 4377 7348 8504 2276"
	name := (mask.Synthetic{}).Mask("Шевчук Оксана Васильевна", pii.FullName, 1)
	card := (mask.Synthetic{}).Mask("4377 7348 8504 2276", pii.CardNumber, 1)
	applied := []mask.Applied{
		{Start: 0, End: int32(len("Шевчук Оксана Васильевна")), Type: pii.FullName, Seq: 1, Replacement: name},
		{Start: int32(strings.Index(orig, "4377")), End: int32(len(orig)), Type: pii.CardNumber, Seq: 1, Replacement: card},
	}
	c := strategyConsumer(t, syntheticStrategy, true)
	got, _ := RestoreIssued("Аннабель, заказ 100002, счёт 70002; Анна, **** 0002", orig, applied, c)
	if want := "Аннабель, заказ 100002, счёт 70002; Оксана, **** 2276"; got != want {
		t.Fatalf("получено %q, ожидалось %q", got, want)
	}
}
