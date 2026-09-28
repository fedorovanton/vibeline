package gateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/mask"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// ErrFailClosed — инвариант fail-closed сработал: предусловие выпуска наружу
// не выполнено, и запрос в модель не отправлялся.
//
// Ошибка отличима специально: транспорт обязан ответить 500 и не выдавать ни
// исходный, ни частично обработанный текст. В отличие от контракта /process,
// безопасного отката здесь нет — на продуктовом контуре отказ дешевле риска
// раскрытия.
var ErrFailClosed = errors.New("gateway: запрос в модель не отправлен")

// ErrUpstream — запрос был отправлен, но модель не ответила.
var ErrUpstream = errors.New("gateway: модель не ответила")

// ErrResponse — ответ модели не удалось обработать: без повторного
// сканирования отдавать его клиенту нельзя.
var ErrResponse = errors.New("gateway: ответ модели не обработан")

// proxyKeyPrefix отделяет соответствия продуктового контура от payload_id
// контракта /process. Управляющий байт в начале делает совпадение с
// идентификатором из внешнего запроса практически невозможным.
const proxyKeyPrefix = "\x01chat:"

// ProxyRequest — запрос потребителя к модели до защиты.
type ProxyRequest struct {
	// ID — идентификатор области корреляции. Плейсхолдеры восстанавливаются
	// только в её пределах: знание чужого идентификатора ничего не открывает,
	// потому что область живёт внутри одного запроса.
	ID string
	// Chat — тело запроса к модели, как его прислал потребитель.
	Chat llm.Request
	// Budget — предел локальной обработки (REQ-604): защита запроса до
	// выпуска и повторное сканирование ответа после него, в сумме. Ожидание
	// модели в предел не входит — оно ограничено таймаутом клиента модели,
	// поэтому предел нельзя выразить дедлайном общего контекста: он оборвал
	// бы и ожидание ответа. Ноль — собственного предела нет, действует
	// только контекст вызова.
	//
	// Истечение предела до выпуска — ErrFailClosed с причиной
	// context.DeadlineExceeded в цепочке: транспорт отвечает 429, запрос в
	// модель не отправлялся.
	Budget time.Duration
}

// ProxyResult — итог проксирования.
type ProxyResult struct {
	// Response — ответ модели с обработанным содержимым.
	Response *llm.Response
	// Detected и Masked — типы ПД в запросе потребителя.
	Detected pii.Set
	Masked   pii.Set
	// DetectedCounts и MaskedCounts — счётчики по типам для метрик и логов.
	DetectedCounts [pii.Count]uint16
	MaskedCounts   [pii.Count]uint16
	// Replaced — число замен в запросе.
	Replaced int
	// Restored — число плейсхолдеров, восстановленных в ответе модели.
	Restored int
	// ResponseMasked — число значений, замаскированных в ответе модели:
	// модель могла породить ПД, которых в запросе не было.
	ResponseMasked int
	// ResponseMaskedCounts — те же значения по типам.
	ResponseMaskedCounts [pii.Count]uint16
	// BytesIn и BytesOut — объём текста запроса и ответа.
	BytesIn  int
	BytesOut int
	// Sent сообщает, был ли отправлен запрос наружу. Для fail-closed всегда
	// false: на это свойство опирается тест-перехватчик.
	Sent bool
	// UpstreamClass — класс отказа обращения к модели: http_status, timeout,
	// tls, dns, connect, network, canceled, bad_response, unknown. Пусто, если
	// отказа не было.
	//
	// Поле существует ради разбора отказа по журналу. 22.09.2026 запись
	// «модель не ответила» с ненулевым llm_ms увела разбор в сторону ключа
	// доступа, тогда как в образе не было корневых сертификатов AlfaGen;
	// класс tls показал бы это сразу.
	UpstreamClass string
	// UpstreamStatus — код ответа модели, если сервер ответил. Ноль означает,
	// что ответа не было и причину называет только класс.
	UpstreamStatus int
	// UpstreamReason — краткое описание причины на русском, пригодное для
	// журнала и показа на стенде. Ни тела запроса, ни тела ответа модели в
	// нём нет: описание выводится из класса отказа и кода ответа.
	UpstreamReason string
	// LLM — время ожидания модели. Учитывается отдельной метрикой и
	// вычитается из времени ответа сервиса: организаторы измеряют наше время.
	LLM time.Duration
	// DetectNs, PolicyNs, MaskNs, StoreNs и RestoreNs — длительности этапов в
	// наносекундах, просуммированные по всем сообщениям запроса. Транспорт
	// раскладывает их на шкалу трассировки; см. комментарий к MaskResult о
	// цене измерения.
	DetectNs  int64
	PolicyNs  int64
	MaskNs    int64
	StoreNs   int64
	RestoreNs int64
}

// Proxy — единственная точка выпуска данных наружу.
//
// Предусловия выпуска перечислены ниже явно и проверяются по порядку. Запрос
// уходит в модель только после того, как выполнены все:
//
//  1. потребитель аутентифицирован и допущен;
//  2. детекция завершена без ошибки;
//  3. политика применена;
//  4. все отобранные спаны заменены;
//  5. соответствие сохранено в хранилище.
//
// Нарушение любого предусловия возвращает ErrFailClosed, и ни одного байта
// наружу не уходит: model.Chat расположен строго ниже всех проверок — в
// callModel, который вызывается только здесь и только после записи в
// хранилище. Превышение предела замен в любом сообщении — нарушение
// предусловия 2: в цепочке ошибки тогда есть ErrSpanLimit.
func (s *Service) Proxy(ctx context.Context, model llm.Chatter, req ProxyRequest, c *policy.Consumer) (ProxyResult, error) {
	// Предусловие 1. Допуск проверяется здесь повторно, а не только в
	// транспорте: точка выпуска не полагается на то, что вызывающий код
	// ничего не забыл.
	if err := checkRelease(ctx, model, req, c); err != nil {
		return ProxyResult{}, err
	}

	// Предел локальной обработки действует на защиту и на повторное
	// сканирование ответа, но не на ожидание модели: у защиты свой
	// производный контекст, у вызова модели — исходный.
	protectStart := time.Now()
	protectCtx := ctx
	if req.Budget > 0 {
		var stop context.CancelFunc
		protectCtx, stop = context.WithTimeout(ctx, req.Budget)
		defer stop()
	}

	// Предусловия 2–4: детекция, политика и полная замена во всех сообщениях.
	var res ProxyResult
	p, err := s.protectChat(protectCtx, req.Chat, c, &res)
	if err != nil {
		return ProxyResult{}, err
	}

	// Предусловие 5: соответствие сохранено. Записываем до выпуска наружу, а
	// не после ответа модели: иначе восстановление осталось бы без записи.
	if err := s.putProxyRecord(c, req.ID, p, &res); err != nil {
		return ProxyResult{}, err
	}
	protectSpent := time.Since(protectStart)

	// Все предусловия выполнены — только теперь запрос покидает сервис.
	resp, err := callModel(ctx, model, p.sent, &res)
	if err != nil {
		return res, err
	}

	// Повторное сканирование ответа получает остаток предела: защита и
	// сканирование вместе укладываются в Budget, ожидание модели — нет.
	restoreCtx := ctx
	if req.Budget > 0 {
		var stop context.CancelFunc
		restoreCtx, stop = context.WithTimeout(ctx, req.Budget-protectSpent)
		defer stop()
	}
	return s.restoreChoices(restoreCtx, resp, p.sc, c, res)
}

// checkRelease проверяет предусловие 1 и то, что запрос вообще можно
// защищать: потребитель допущен, модель настроена, область корреляции и
// сообщения есть, контекст не отменён. Любой отказ — ErrFailClosed.
func checkRelease(ctx context.Context, model llm.Chatter, req ProxyRequest, c *policy.Consumer) error {
	if c == nil || !c.Enabled {
		return fmt.Errorf("%w: потребитель не допущен", ErrFailClosed)
	}
	if model == nil {
		return fmt.Errorf("%w: downstream-модель не настроена", ErrFailClosed)
	}
	if req.ID == "" {
		return fmt.Errorf("%w: пустая область корреляции", ErrFailClosed)
	}
	if len(req.Chat.Messages) == 0 {
		return fmt.Errorf("%w: запрос не содержит сообщений", ErrFailClosed)
	}
	if err := ctx.Err(); err != nil {
		return wrapErr(ErrFailClosed, err)
	}
	return nil
}

// wrapErr оборачивает err классом отказа kind: «<kind>: <err>», обе ошибки
// остаются в цепочке для errors.Is.
func wrapErr(kind, err error) error {
	return fmt.Errorf("%w: %w", kind, err)
}

// protectedChat — запрос, защищённый целиком: предусловия 2–4 выполнены для
// каждого сообщения. Выпускать его можно только после записи соответствия.
type protectedChat struct {
	// sent — тело запроса к модели с замаскированным содержимым.
	sent llm.Request
	// sc — область корреляции для восстановления ответа.
	sc *scope
	// originals и maskedTexts — непустые сообщения до и после защиты, в
	// порядке запроса: из них собирается запись хранилища.
	originals   []string
	maskedTexts []string
}

// protectChat маскирует все сообщения запроса, закрывает повторы значений
// между сообщениями и проверяет полноту замены в каждом (предусловия 2–4).
// Счётчики и длительности этапов накапливаются в res. Любой отказ —
// ErrFailClosed.
func (s *Service) protectChat(ctx context.Context, chat llm.Request, c *policy.Consumer, res *ProxyResult) (*protectedChat, error) {
	// Нумерация сквозная для всех сообщений запроса: модель видит историю
	// чата целиком, и два разных человека в разных сообщениях не должны
	// оказаться одним «[ФИО_1]». Номера, уже буквально написанные во входе,
	// не выдаются — иначе восстановление не отличило бы их от выданных.
	contents := make([]string, len(chat.Messages))
	for i, m := range chat.Messages {
		contents[i] = m.Content
	}
	reserved := literalIn(contents...)
	num := &mask.Numbering{Reserved: reserved}

	masked, err := s.maskMessages(ctx, chat.Messages, c, num, res)
	if err != nil {
		return nil, err
	}

	// Значение, найденное в одном сообщении, закрывается во всех сообщениях
	// запроса и проверяется в каждом (С-4): модель видит историю целиком, и
	// повтор в другом сообщении — утечка того же значения.
	union, err := coverAcrossMessages(ctx, contents, masked, c, num)
	if err != nil {
		return nil, maskFailure(err)
	}
	defer verifiers.Put(union)

	p := &protectedChat{
		sent:        chat,
		sc:          newScope(),
		originals:   make([]string, 0, len(chat.Messages)),
		maskedTexts: make([]string, 0, len(chat.Messages)),
	}
	p.sent.Messages = make([]llm.Message, len(chat.Messages))
	synthetic := syntheticOf(c)
	for i, m := range chat.Messages {
		if m.Content == "" {
			p.sent.Messages[i] = m
			continue
		}
		mr := &masked[i]
		// Предусловие 4: все отобранные спаны заменены, и ни одно значение
		// запроса не осталось открытым ни в одном сообщении.
		if err := verifyMessage(m.Content, mr, union); err != nil {
			return nil, err
		}
		p.sent.Messages[i] = llm.Message{Role: m.Role, Content: mr.Text}
		p.originals = append(p.originals, m.Content)
		p.maskedTexts = append(p.maskedTexts, mr.Text)
		p.sc.add(m.Content, mr.Applied, synthetic)
		res.addMessage(mr)
	}

	// Замена, которую нумерация не смогла развести с буквальным текстом
	// входа (стратегии, не зависящие от номера), не восстанавливается: в
	// ответе модели выданную маску не отличить от написанной пользователем.
	p.sc.markReserved(reserved)
	return p, nil
}

// maskMessages маскирует каждое непустое сообщение запроса (предусловия 2
// и 3: детекция и применение политики выполняются в mask). Ошибка означает,
// что защиту завершить не удалось.
func (s *Service) maskMessages(ctx context.Context, msgs []llm.Message, c *policy.Consumer, num *mask.Numbering, res *ProxyResult) ([]MaskResult, error) {
	masked := make([]MaskResult, len(msgs))
	for i, m := range msgs {
		res.BytesIn += len(m.Content)
		if m.Content == "" {
			continue
		}
		mr, err := s.mask(ctx, m.Content, c, num)
		if err != nil {
			return nil, maskFailure(err)
		}
		masked[i] = mr
	}
	return masked, nil
}

// verifyMessage — предусловие 4 для одного сообщения: заменены все
// отобранные спаны, и ни одно значение запроса не осталось открытым.
func verifyMessage(original string, mr *MaskResult, union *verifier) error {
	if err := VerifyReplaced(original, *mr); err != nil {
		return wrapErr(ErrFailClosed, err)
	}
	if err := union.check(mr.Text); err != nil {
		return wrapErr(ErrFailClosed, err)
	}
	return nil
}

// addMessage добавляет в итог счётчики и длительности защиты одного сообщения.
func (r *ProxyResult) addMessage(mr *MaskResult) {
	r.Detected |= mr.Detected
	r.Masked |= mr.Masked
	r.Replaced += len(mr.Applied)
	r.DetectNs += mr.DetectNs
	r.PolicyNs += mr.PolicyNs
	r.MaskNs += mr.MaskNs
	for t := 1; t < pii.Count; t++ {
		r.DetectedCounts[t] += mr.DetectedCounts[t]
		r.MaskedCounts[t] += mr.MaskedCounts[t]
	}
}

// putProxyRecord сохраняет соответствие защищённого запроса (предусловие 5).
// Отказ хранилища — ErrFailClosed: без записи восстанавливать ответ нечем.
func (s *Service) putProxyRecord(c *policy.Consumer, id string, p *protectedChat, res *ProxyResult) error {
	rec := store.Record{
		Original:  strings.Join(p.originals, "\n"),
		Masked:    strings.Join(p.maskedTexts, "\n"),
		Types:     res.Masked,
		Consumer:  c.ID,
		CreatedAt: s.now(),
	}
	putStart := time.Now()
	if err := s.store.Put(scopedKey(c.ID, proxyKeyPrefix+id), rec); err != nil {
		return fmt.Errorf("%w: соответствие не сохранено: %w", ErrFailClosed, err)
	}
	res.StoreNs = time.Since(putStart).Nanoseconds()
	return nil
}

// callModel — единственный вызов модели. Вызывается только из Proxy после
// выполнения всех предусловий выпуска. С этого момента res.Sent — true.
func callModel(ctx context.Context, model llm.Chatter, sent llm.Request, res *ProxyResult) (*llm.Response, error) {
	started := time.Now()
	resp, err := model.Chat(ctx, sent)
	res.Sent = true
	res.LLM = time.Since(started)
	if err != nil {
		res.setUpstreamCause(err)
		return nil, wrapErr(ErrUpstream, err)
	}
	if resp == nil || len(resp.Choices) == 0 {
		res.UpstreamClass = string(llm.ClassResponse)
		res.UpstreamReason = "ответ модели не содержит ни одного варианта"
		return nil, fmt.Errorf("%w: пустой ответ", ErrUpstream)
	}
	return resp, nil
}

// restoreChoices восстанавливает маски запроса и повторно сканирует каждый
// вариант ответа модели. При отказе ответ клиенту не отдаётся.
func (s *Service) restoreChoices(ctx context.Context, resp *llm.Response, sc *scope, c *policy.Consumer, res ProxyResult) (ProxyResult, error) {
	restoreStart := time.Now()
	out := *resp
	out.Choices = slices.Clone(resp.Choices)
	for i := range out.Choices {
		text, st, err := s.restoreAndRescan(ctx, out.Choices[i].Message.Content, sc, c)
		if err != nil {
			res.RestoreNs = time.Since(restoreStart).Nanoseconds()
			return res, err
		}
		out.Choices[i].Message.Content = text
		res.addResponse(len(text), &st)
	}
	res.RestoreNs = time.Since(restoreStart).Nanoseconds()
	res.Response = &out
	return res, nil
}

// addResponse добавляет в итог счётчики одного варианта ответа модели.
func (r *ProxyResult) addResponse(bytesOut int, st *respStats) {
	r.BytesOut += bytesOut
	r.Restored += st.restored
	r.ResponseMasked += st.masked
	r.Masked |= st.maskedSet
	for t := 1; t < pii.Count; t++ {
		r.ResponseMaskedCounts[t] += st.maskedCounts[t]
	}
}

// maskFailure переводит отказ защиты сообщения в ErrFailClosed.
//
// Причина остаётся в цепочке только у исходов, на которые транспорт отвечает
// своим кодом: превышение предела замен и истечение предела обработки или
// отмена. Остальные причины — прежде всего паника — в цепочку не попадают:
// текст паники не контролируется, а сообщение об ошибке уходит в журнал.
func maskFailure(err error) error {
	switch {
	case errors.Is(err, ErrSpanLimit):
		return wrapErr(ErrFailClosed, ErrSpanLimit)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: защита не уложилась в предел обработки: %w", ErrFailClosed, context.DeadlineExceeded)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: защита прервана: %w", ErrFailClosed, context.Canceled)
	}
	return fmt.Errorf("%w: защита сообщения не завершена", ErrFailClosed)
}

// setUpstreamCause переносит в результат причину отказа модели.
//
// Классификация выполняется клиентом модели, а не транспортом: класс отказа
// известен там, где ошибка возникла. Чужая реализация Chatter получает класс
// unknown — поле остаётся заполненным при любом источнике отказа.
func (r *ProxyResult) setUpstreamCause(err error) {
	f := llm.Classify(err)
	r.UpstreamClass = string(f.Class)
	r.UpstreamStatus = f.Status
	r.UpstreamReason = f.Reason
}

// UpstreamNote собирает строку причины отказа для журнала и стенда.
//
// Строка выводится из класса и кода ответа; ни текста запроса, ни тела ответа
// модели в ней нет. Пустая строка означает, что отказа обращения не было.
func (r ProxyResult) UpstreamNote() string {
	if r.UpstreamClass == "" {
		return ""
	}
	reason := r.UpstreamReason
	if reason == "" {
		reason = "модель не ответила"
	}
	if r.UpstreamStatus > 0 {
		return fmt.Sprintf("%s: код ответа %d, класс отказа %s",
			reason, r.UpstreamStatus, r.UpstreamClass)
	}
	return fmt.Sprintf("%s: класс отказа %s", reason, r.UpstreamClass)
}

// VerifyReplaced проверяет, что защищённый текст не содержит ни одного
// исходного значения из отобранных политикой спанов.
//
// Проверка строже формального «спаны заменены»: она ловит и случай, когда то
// же самое значение встречается в тексте ещё раз, а маскирование закрыло не
// все вхождения. Повторы по границам токенов закрывает само маскирование
// (mask.CoverRepeats, T-56), поэтому здесь остаются вхождения, прилипшие к
// соседнему слову, и дефекты самого маскирования. Такой остаток — утечка
// ровно того значения, которое мы обязались скрыть, поэтому запрос
// отклоняется целиком. Цена ошибки здесь несимметрична: отказ виден и
// объясним, утечка — нет.
//
// Вхождение ищется по границам цифрового токена: значение, продолженное
// цифрой слева или справа, — часть другого числа, а не само значение. CVV
// «123» в сумме «1230» открытым CVV не является; без этого правила трёх- и
// четырёхзначные CVV и ПИН совпадали бы с частями сумм, дат и номеров заявок,
// и запрос отклонялся бы ложно. Прилипшая буква границей не считается:
// «ivanov@example.test» с буквой вплотную по-прежнему ловится — буквы в
// значении и рядом с ним продолжают то же слово, и лучше отказ, чем пропуск.
//
// Все значения ищутся за один проход по защищённому тексту (mask.Values):
// поиск подстрокой на каждую замену стоил O(замены × длина текста) — 4 с на
// 637 КБ и 15 000 спанах (С-5, T-56).
//
// Проверка общая для всех точек, где маска уходит наружу: прокси к модели и
// явный эндпоинт маскирования.
func VerifyReplaced(original string, mr MaskResult) error {
	if len(mr.Applied) != len(mr.Spans) {
		return errors.New("заменены не все отобранные спаны")
	}
	if len(mr.Applied) == 0 {
		return nil
	}
	v := newVerifier()
	defer verifiers.Put(v)
	for _, a := range mr.Applied {
		if a.Start < 0 || int(a.End) > len(original) || a.Start >= a.End {
			return errors.New("границы замены вышли за пределы текста")
		}
		v.add(original[a.Start:a.End], detect.Span{Type: a.Type})
	}
	return v.check(mr.Text)
}

// verifier — множество значений, которых не должно быть в защищённом
// тексте: автомат значений и образец спана каждого значения (тип и
// уверенность — для закрытия повторов и для текста ошибки).
type verifier struct {
	vals mask.Values
	src  []detect.Span
}

var verifiers = sync.Pool{New: func() any { return &verifier{} }}

// newVerifier берёт из пула пустое множество. Возвращать — verifiers.Put.
func newVerifier() *verifier {
	v, ok := verifiers.Get().(*verifier)
	if !ok {
		v = &verifier{}
	}
	v.vals.Reset()
	v.src = v.src[:0]
	return v
}

// add добавляет значение; образец запоминается у первого вхождения.
func (v *verifier) add(value string, sample detect.Span) {
	if id := v.vals.Add(value); id >= 0 && int(id) == len(v.src) {
		v.src = append(v.src, sample)
	}
}

// check сообщает об ошибке, если хоть одно значение стоит в text
// самостоятельно — не продолжено цифрой там, где значение начинается или
// кончается цифрой (такое вхождение — часть другого числа).
func (v *verifier) check(text string) error {
	leaked := int32(-1)
	v.vals.Each(text, func(id int32, start, end int) bool {
		first, last := text[start], text[end-1]
		glued := (isDigit(first) && start > 0 && isDigit(text[start-1])) ||
			(isDigit(last) && end < len(text) && isDigit(text[end]))
		if glued {
			return true
		}
		leaked = id
		return false
	})
	if leaked >= 0 {
		// Значение не называется: сообщение об ошибке уходит в лог.
		return fmt.Errorf("значение типа %s осталось в защищённом тексте", v.src[leaked].Type.Key())
	}
	return nil
}

// coverAcrossMessages закрывает в каждом сообщении запроса значения,
// отобранные в любом сообщении, и возвращает их множество для проверки
// полноты (С-4, T-56).
//
// Маскирование сообщения закрывает повторы его собственных значений; здесь —
// повторы значений из других сообщений: «мой ПИН 1234» в одном и «напомни
// 1234» в другом. Сообщение с такими повторами собирается заново той же
// нумерацией: значения уже пронумерованы, и повтор получает ту же замену.
// Вызывающий возвращает множество в пул (verifiers.Put).
func coverAcrossMessages(ctx context.Context, contents []string, masked []MaskResult, c *policy.Consumer, num *mask.Numbering) (*verifier, error) {
	union := newVerifier()
	if len(contents) < 2 {
		// Одно сообщение: его повторы закрыло маскирование, а полноту
		// проверяет VerifyReplaced — пустое множество ничего не добавит.
		return union, nil
	}
	for i := range masked {
		union.addSpans(contents[i], masked[i].Spans)
	}
	if union.vals.Len() == 0 {
		return union, nil
	}
	if err := ctx.Err(); err != nil {
		verifiers.Put(union)
		return nil, err
	}
	var appl mask.Applier
	for i := range masked {
		if contents[i] == "" {
			continue
		}
		if err := coverMessage(&appl, contents[i], &masked[i], union, c, num); err != nil {
			verifiers.Put(union)
			return nil, err
		}
	}
	return union, nil
}

// addSpans добавляет значения спанов текста; спан с границами вне текста
// пропускается.
func (v *verifier) addSpans(text string, spans []detect.Span) {
	for _, sp := range spans {
		if sp.Start >= 0 && int(sp.End) <= len(text) && sp.Start < sp.End {
			v.add(text[sp.Start:sp.End], detect.Span{Type: sp.Type, Conf: sp.Conf})
		}
	}
}

// coverMessage закрывает в сообщении content повторы значений union и, если
// повторы нашлись, собирает маску сообщения mr заново той же нумерацией.
// Превышение предела замен — ErrSpanLimit.
func coverMessage(appl *mask.Applier, content string, mr *MaskResult, union *verifier, c *policy.Consumer, num *mask.Numbering) error {
	spans := appl.CoverValues(content, mr.Spans, &union.vals, union.src)
	if len(spans) == len(mr.Spans) {
		return nil
	}
	if c.MaxSpans > 0 && len(spans) > c.MaxSpans {
		return ErrSpanLimit
	}
	text, applied := appl.ApplyNumbered(content, spans, c.Strategy, num)
	prev := mr.MaskedCounts
	mr.Text = text
	mr.Applied = append([]mask.Applied(nil), applied...)
	mr.Spans = append([]detect.Span(nil), spans...)
	mr.Masked, mr.MaskedCounts = 0, [pii.Count]uint16{}
	for _, sp := range spans {
		mr.Masked = mr.Masked.Add(sp.Type)
		mr.MaskedCounts[sp.Type]++
	}
	for t := range mr.MaskedCounts {
		mr.DetectedCounts[t] += mr.MaskedCounts[t] - prev[t]
	}
	return nil
}

// isDigit — ASCII-цифра, как у лексера: цифровой токен состоит только из них.
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// literalIn возвращает проверку «замена уже буквально есть во входе» для
// текстов одного запроса.
//
// Для плейсхолдера «[МЕТКА]» проверяется метка: написана ли она во входе
// отдельным словом — в скобках, в разметке («**ФИО_1**») или сама по себе.
// Ответ модели восстанавливается и по метке без скобок в разметке (Ж-1,
// T-56), поэтому выдавать номер, метка которого уже есть во входе, нельзя:
// буквальную метку не отличить от выданной. Метки собираются одним проходом
// по входу при первом вопросе, и проверка — поиск в множестве, а не подстрока
// на каждое значение, которая на тысячах значений повторила бы ошибку С-5.
//
// Замены других стратегий (token, synthetic, asterisks) ищутся подстрокой;
// результаты запоминаются: нумерация и разметка неоднозначных масок
// спрашивают об одной и той же замене дважды.
func literalIn(texts ...string) func(string) bool {
	var labels map[string]struct{}
	memo := make(map[string]bool, 8)
	return func(repl string) bool {
		if label, ok := bareLabel(repl); ok {
			if labels == nil {
				labels = labelsIn(texts)
			}
			_, found := labels[label]
			return found
		}
		if v, ok := memo[repl]; ok {
			return v
		}
		found := false
		for _, t := range texts {
			if strings.Contains(t, repl) {
				found = true
				break
			}
		}
		memo[repl] = found
		return found
	}
}

// bareLabel возвращает метку плейсхолдера «[МЕТКА]» без скобок.
func bareLabel(m string) (string, bool) {
	if len(m) < 3 || m[0] != '[' || m[len(m)-1] != ']' {
		return "", false
	}
	label := m[1 : len(m)-1]
	if strings.ContainsAny(label, "[]") {
		return "", false
	}
	return label, true
}

// labelsIn собирает слова, похожие на метку плейсхолдера: слово (ряд букв,
// цифр и подчёркиваний) целиком из заглавных букв, цифр и подчёркиваний,
// кончающееся на «_<номер>».
func labelsIn(texts []string) map[string]struct{} {
	out := make(map[string]struct{}, 4)
	for _, t := range texts {
		collectLabels(t, out)
	}
	return out
}

// collectLabels добавляет в out слова текста t, похожие на метку.
func collectLabels(t string, out map[string]struct{}) {
	for i := 0; i < len(t); {
		r, size := utf8.DecodeRuneInString(t[i:])
		if !isWordRune(r) {
			i += size
			continue
		}
		end, label := wordEnd(t, i)
		if w := t[i:end]; label && looksLikeLabel(w) {
			out[w] = struct{}{}
		}
		i = end
	}
}

// wordEnd возвращает конец слова, начинающегося в t[start], и признак того,
// что слово целиком состоит из знаков метки (isLabelRune).
func wordEnd(t string, start int) (int, bool) {
	i, label := start, true
	for i < len(t) {
		r, size := utf8.DecodeRuneInString(t[i:])
		if !isWordRune(r) {
			break
		}
		label = label && isLabelRune(r)
		i += size
	}
	return i, label
}

func isLabelRune(r rune) bool {
	return r == '_' || (r >= '0' && r <= '9') || unicode.IsUpper(r)
}

// looksLikeLabel — слово кончается на «_<цифры>» и не состоит из одного номера.
func looksLikeLabel(w string) bool {
	i := len(w)
	for i > 0 && isDigit(w[i-1]) {
		i--
	}
	return i < len(w) && i >= 2 && w[i-1] == '_'
}

// scopeEntry — соответствие «маска → исходное значение» внутри одной области.
type scopeEntry struct {
	original string
	typ      pii.Type
	// seq — номер значения: по нему собирается плейсхолдер, которым
	// помечается невосстановленная синтетическая маска.
	seq int
	// ambiguous отмечает маску, за которой стоит больше одного значения или
	// которую нельзя отличить от буквального текста входа. Так бывает у
	// стратегий, которые не различают значения (звёздочки), или не зависят
	// от номера (token): восстанавливать такую маску нельзя — вернётся не то
	// значение.
	ambiguous bool
	// reserved — маска буквально написана во входе: это текст пользователя,
	// и в ответе она остаётся как есть.
	reserved bool
	// synthetic — маска выдана стратегией synthetic и правдоподобна: не
	// восстановленная, она читалась бы клиентом как настоящие данные, поэтому
	// в ответ идёт плейсхолдер (Б4-8).
	synthetic bool
	// derived — производная форма синтетической маски: часть или падежная
	// форма ФИО, последние цифры или слитная запись номера. Ищется только
	// отдельным словом и уступает выданной маске при совпадении.
	derived bool
}

// scope — область корреляции: маски, выданные в одном запросе к модели или
// для одной записи явного API.
//
// Восстанавливаются только маски, выданные в этой области: чужой или
// подделанный плейсхолдер не может совпасть с записью другого потребителя.
// Реализация одна для прокси и явного API (С-6, T-56).
type scope struct {
	byMask map[string]*scopeEntry
	order  []string
	maxSeq [pii.Count]int
}

func newScope() *scope {
	return &scope{byMask: make(map[string]*scopeEntry, 16)}
}

// add запоминает замены одного текста. Замена с границами вне текста
// пропускается: сопоставить её со значением нельзя.
//
// synthetic сообщает, выдана ли замена типа стратегией synthetic: для таких
// замен запоминаются и производные формы (addDerived). Пустой synthetic —
// производных форм нет.
func (sc *scope) add(text string, applied []mask.Applied, synthetic func(pii.Type) bool) {
	for _, a := range applied {
		if a.Replacement == "" || a.Start < 0 || int(a.End) > len(text) || a.Start >= a.End {
			continue
		}
		if a.Seq > sc.maxSeq[a.Type] {
			sc.maxSeq[a.Type] = a.Seq
		}
		sc.addIssued(text[a.Start:a.End], a, synthetic != nil && synthetic(a.Type))
	}
}

// addIssued запоминает выданную замену a значения orig. Маска, за которой
// уже стоит другое значение, становится неоднозначной.
func (sc *scope) addIssued(orig string, a mask.Applied, synth bool) {
	if e, ok := sc.byMask[a.Replacement]; ok && !e.derived {
		if e.original != orig {
			e.ambiguous = true
		}
		return
	} else if !ok {
		sc.order = append(sc.order, a.Replacement)
	}
	// Выданная маска вытесняет совпавшую с ней производную форму другого
	// значения: полное совпадение надёжнее части.
	sc.byMask[a.Replacement] = &scopeEntry{original: orig, typ: a.Type, seq: a.Seq, synthetic: synth}
	if synth {
		sc.addDerived(orig, a)
	}
}

// addDerived запоминает производные формы синтетической замены a значения
// orig — то, во что модель переписывает правдоподобную маску (Б4-8):
//
//   - ФИО: части и падежные формы («Анна Петровна», «Анне Петровне»,
//     «Петровой») — им соответствуют те же части и падежи исходного ФИО;
//   - номер карты: слитная запись без пробелов и последние четыре цифры
//     («**** 0002») — им соответствуют слитная запись и последние четыре
//     цифры исходного номера;
//   - телефон: слитная запись с «+» и без.
//
// Остальные типы модель не переписывает так, чтобы форму можно было
// сопоставить без догадок, и производных форм у них нет.
func (sc *scope) addDerived(orig string, a mask.Applied) {
	switch a.Type {
	case pii.FullName:
		for _, f := range mask.SyntheticNameForms(orig, a.Replacement) {
			sc.addForm(f.Synthetic, f.Original, a)
		}
	case pii.CardNumber:
		rd, od := digitsOnly(a.Replacement), digitsOnly(orig)
		if len(rd) >= 12 && len(od) >= 12 {
			sc.addForm(rd, od, a)
			sc.addForm(rd[len(rd)-4:], od[len(od)-4:], a)
		}
	case pii.Phone:
		rd := digitsOnly(a.Replacement)
		if len(rd) >= 10 && len(digitsOnly(orig)) >= 10 {
			sc.addForm("+"+rd, orig, a)
			sc.addForm(rd, orig, a)
		}
	}
}

// addForm запоминает производную форму. Форма, совпавшая с выданной маской,
// уступает ей; форма, за которой оказалось два разных значения, становится
// неоднозначной и не восстанавливается.
func (sc *scope) addForm(form, original string, a mask.Applied) {
	if form == "" || form == original {
		return
	}
	if e, ok := sc.byMask[form]; ok {
		if e.derived && e.original != original {
			e.ambiguous = true
		}
		return
	}
	sc.byMask[form] = &scopeEntry{original: original, typ: a.Type, seq: a.Seq, synthetic: true, derived: true}
	sc.order = append(sc.order, form)
}

// digitsOnly оставляет в строке только ASCII-цифры.
func digitsOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// markReserved помечает неоднозначными маски, буквально написанные во входе.
func (sc *scope) markReserved(reserved func(string) bool) {
	for _, m := range sc.order {
		if reserved(m) {
			e := sc.byMask[m]
			e.ambiguous = true
			e.reserved = true
		}
	}
}

// syntheticOf сообщает, какие типы потребитель маскирует стратегией synthetic.
func syntheticOf(c *policy.Consumer) func(pii.Type) bool {
	if c == nil {
		return nil
	}
	return func(t pii.Type) bool { return c.StrategyName(t) == syntheticStrategy }
}

// syntheticStrategy — имя стратегии правдоподобной синтетики.
const syntheticStrategy = "synthetic"

// RestoreIssued восстанавливает в text маски, выданные при маскировании
// original заменами applied по политике c, — обратный шаг явного API для
// изменённой маски.
//
// Реализация та же, что у ответа модели на прокси: только выданные в этой
// области маски, в том числе метка плейсхолдера в разметке без скобок (Ж-1)
// и производные формы синтетики; неоднозначные маски и маски, буквально
// написанные в original, не восстанавливаются. Возвращает текст и число
// восстановленных масок.
func RestoreIssued(text, original string, applied []mask.Applied, c *policy.Consumer) (string, int) {
	sc := newScope()
	sc.add(original, applied, syntheticOf(c))
	sc.markReserved(literalIn(original))
	out, _, n := sc.restore(text, true)
	return out, n
}

// respStats — что произошло с одним вариантом ответа модели.
type respStats struct {
	restored     int
	masked       int
	maskedSet    pii.Set
	maskedCounts [pii.Count]uint16
}

// region — участок текста в байтах.
type region struct{ start, end int }

// markupFrames — разметка, в которой модель пишет метку плейсхолдера без
// квадратных скобок: «**ФИО_1**», «*ФИО_1*», «`ФИО_1`» (Ж-1, T-56).
// Двойные знаки раньше одинарных: «**ФИО_1**» — жирный, а не курсив внутри
// звёздочек.
var markupFrames = [...]string{"**", "__", "*", "_", "`"}

// framedAt сообщает, что метка на [start, end) обрамлена одним и тем же
// знаком разметки с обеих сторон, а снаружи обрамления нет продолжения
// слова: «**ФИО_1**,» — да, «X_ФИО_1_» — нет.
func framedAt(text string, start, end int) bool {
	for _, f := range markupFrames {
		openAt, closeAt := start-len(f), end+len(f)
		if openAt < 0 || closeAt > len(text) || text[openAt:start] != f || text[end:closeAt] != f {
			continue
		}
		return standalone(text, openAt, closeAt)
	}
	return false
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// standalone сообщает, что участок [start, end) не продолжает соседнее слово
// ни слева, ни справа.
func standalone(text string, start, end int) bool {
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); isWordRune(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); isWordRune(r) {
			return false
		}
	}
	return true
}

// restore подставляет исходные значения на место выданных масок.
//
// Выданная маска распознаётся как есть, а плейсхолдер «[МЕТКА]» — ещё и
// меткой без скобок в обрамлении разметки: модель переписывает «[ФИО_1]» в
// «**ФИО_1**» (Ж-1). Разметка остаётся, подставляется значение на место
// метки. Метка вне разметки не восстанавливается: «ФИО_1» в обычном тексте —
// не маска.
//
// Возвращает текст и участки, которые повторная детекция трогать не должна:
// восстановленные значения — собственные данные потребителя, разрешённые его
// политикой, — и маски, оставленные как есть (демаскирование не разрешено или
// маска неоднозначна). Синтетическая маска правдоподобна и нашлась бы
// детекцией как новые ПД, поэтому оставленные маски тоже защищены.
//
// Синтетическая маска восстанавливается и в производных формах — частью ФИО,
// в падеже, последними цифрами номера (Б4-8). Синтетическую маску, которую
// восстановить нельзя, клиент получает плейсхолдером того же значения, а не
// правдоподобным вымыслом, который читался бы как настоящие данные.
//
// Неизвестная или подделанная маска сюда не попадёт: ищутся только маски,
// выданные в этой области. Все маски ищутся за один проход по тексту.
func (sc *scope) restore(text string, demask bool) (string, []region, int) {
	if len(sc.order) == 0 || text == "" {
		return text, nil, 0
	}
	var vals mask.Values
	forms := sc.indexForms(&vals)
	hits := sc.findHits(text, &vals, forms)
	if len(hits) == 0 {
		return text, nil, 0
	}
	return sc.rebuild(text, hits, demask)
}

// restoreForm — маска и признак «это метка без скобок» для значения
// автомата восстановления.
type restoreForm struct {
	mask string
	bare bool
}

// indexForms добавляет в vals выданные маски области и метки плейсхолдеров
// без скобок; forms[id] описывает значение id.
func (sc *scope) indexForms(vals *mask.Values) []restoreForm {
	forms := make([]restoreForm, 0, 2*len(sc.order))
	for _, m := range sc.order {
		if id := vals.Add(m); int(id) == len(forms) {
			forms = append(forms, restoreForm{mask: m})
		}
		if label, ok := bareLabel(m); ok {
			if id := vals.Add(label); int(id) == len(forms) {
				forms = append(forms, restoreForm{mask: m, bare: true})
			}
		}
	}
	return forms
}

// findHits находит в text вхождения выданных масок за один проход и
// упорядочивает их слева направо, при совпадении начала — более длинную
// маску первой.
func (sc *scope) findHits(text string, vals *mask.Values, forms []restoreForm) []event {
	var hits []event
	vals.Each(text, func(id int32, start, end int) bool {
		f := forms[id]
		if f.bare && !framedAt(text, start, end) {
			return true
		}
		if sc.byMask[f.mask].derived && !standalone(text, start, end) {
			// Производная форма — только отдельным словом: «Петр» внутри
			// «Петровна» и «0002» внутри длинного числа — не она.
			return true
		}
		hits = append(hits, event{start: start, end: end, mask: f.mask})
		return true
	})
	slices.SortFunc(hits, func(a, b event) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return b.end - a.end
	})
	return hits
}

// rebuild собирает текст с подстановкой на место вхождений hits; см. restore.
func (sc *scope) rebuild(text string, hits []event, demask bool) (string, []region, int) {
	var b strings.Builder
	b.Grow(len(text))
	kept := make([]region, 0, len(hits))
	restored, prev := 0, 0
	for _, h := range hits {
		if h.start < prev {
			continue // перекрытие с уже обработанной маской
		}
		b.WriteString(text[prev:h.start])
		put, ok := sc.byMask[h.mask].replacement(text[h.start:h.end], demask)
		if ok {
			restored++
		}
		at := b.Len()
		b.WriteString(put)
		kept = append(kept, region{start: at, end: at + len(put)})
		prev = h.end
	}
	b.WriteString(text[prev:])
	return b.String(), kept, restored
}

// replacement возвращает, что поставить на место вхождения found маски
// записи e, и признак восстановления исходного значения.
func (e *scopeEntry) replacement(found string, demask bool) (string, bool) {
	switch {
	case demask && !e.ambiguous:
		return e.original, true
	case e.synthetic && !e.reserved:
		// Синтетика, которую восстановить нельзя (нет права demask или
		// форма неоднозначна), не выдаётся клиенту как настоящие данные:
		// на её месте — плейсхолдер того же значения (Б4-8).
		return mask.Placeholder{}.Mask("", e.typ, e.seq), false
	}
	return found, false
}

// event — вхождение выданной маски в ответе модели.
type event struct {
	start, end int
	mask       string
}

// restoreAndRescan восстанавливает плейсхолдеры этого запроса и маскирует
// персональные данные, которые модель породила сама.
//
// Порядок — сначала восстановление, потом детекция на восстановленном
// тексте, — выбран так, чтобы ни одна выданная маска не была замаскирована
// повторно: найденное внутри восстановленных значений и оставленных масок
// отбрасывается, маскируется только то, что лежит за их пределами. Если
// спан детекции частично заходит на такой участок, маскируется его остаток:
// дописанное моделью к значению потребителя — это уже новые данные.
//
// Нумерация масок ответа продолжает номера запроса: [ФИО_1] из запроса и ПД,
// придуманные моделью, не должны получить один плейсхолдер. Новая маска
// ответа восстановлению не подлежит, поэтому совпасть с выданной и подставить
// чужое значение она не может.
func (s *Service) restoreAndRescan(ctx context.Context, text string, sc *scope, c *policy.Consumer) (out string, st respStats, err error) {
	if text == "" {
		return text, st, nil
	}

	w := s.workspaceFromPool()
	defer s.pool.Put(w)

	defer func() {
		if r := recover(); r != nil {
			// Ответ не проверен — отдавать его клиенту нельзя.
			out = ""
			st = respStats{}
			err = fmt.Errorf("%w: сканирование ответа прервано: %v", ErrResponse, r)
		}
	}()

	text, kept, restored := sc.restore(text, c.Demask)
	st.restored = restored

	spans, err := s.rescan(ctx, w, text, c)
	if err != nil {
		return "", respStats{}, err
	}
	if len(spans) == 0 {
		return text, st, nil
	}

	m := &respMasker{text: text, sc: sc, c: c, st: st, local: make(map[respSeqKey]int, 8)}
	m.b.Grow(len(text))
	m.maskSpans(spans, kept)
	m.b.WriteString(text[m.prev:])
	return m.b.String(), m.st, nil
}

// rescan запускает детекцию на восстановленном ответе и возвращает спаны
// для маскирования. Спаны живут в буферах w: w возвращается в пул только
// после их использования.
func (s *Service) rescan(ctx context.Context, w *workspace, text string, c *policy.Consumer) ([]detect.Span, error) {
	lex.Tokenize(text, &w.doc)
	if _, derr := s.engine.Detect(ctx, &w.doc, c.DetectOptions(), &w.cand, &w.res); derr != nil {
		return nil, fmt.Errorf("%w: сканирование ответа не завершено: %w", ErrResponse, derr)
	}
	if w.res.LimitExceeded {
		// Разметка ответа неполна: значения модели сверх предела ушли бы
		// клиенту открытыми. Ответ не отдаётся, как при любом отказе
		// повторной проверки.
		return nil, wrapErr(ErrResponse, ErrSpanLimit)
	}
	// Повторы найденного закрываются так же, как в запросе (С-4): значение,
	// которое модель написала дважды, а детекция опознала один раз, не уходит
	// клиенту открытым. Повтор внутри восстановленного значения ниже
	// отбрасывается вместе с прочими спанами на защищённых участках.
	spans := w.appl.CoverRepeats(text, c.Filter(&w.res))
	if c.MaxSpans > 0 && len(spans) > c.MaxSpans {
		return nil, wrapErr(ErrResponse, ErrSpanLimit)
	}
	return spans, nil
}

// respMasker маскирует в ответе модели значения, найденные повторной
// детекцией, в обход защищённых участков (восстановленных значений и
// оставленных масок). Текст собирается в b слева направо; prev — конец уже
// перенесённой части text.
type respMasker struct {
	text  string
	sc    *scope
	c     *policy.Consumer
	b     strings.Builder
	local map[respSeqKey]int
	next  [pii.Count]int
	prev  int
	st    respStats
}

// maskSpans маскирует спаны; kept — защищённые участки по возрастанию.
func (m *respMasker) maskSpans(spans []detect.Span, kept []region) {
	k := 0
	for _, sp := range spans {
		start, end := int(sp.Start), int(sp.End)
		if start < m.prev || end > len(m.text) || end <= start {
			continue // рассогласование: пропускаем битый спан
		}
		for k < len(kept) && kept[k].end <= start {
			k++
		}
		if k == len(kept) || kept[k].start >= end {
			m.piece(start, end, sp.Type)
			continue
		}
		m.around(start, end, sp.Type, kept[k:])
	}
}

// around маскирует части спана [start, end) вне защищённых участков kept:
// спан задевает их, и маскируется только дописанное моделью.
func (m *respMasker) around(start, end int, typ pii.Type, kept []region) {
	cur := start
	for j := 0; cur < end; j++ {
		pieceEnd := end
		if j < len(kept) && kept[j].start < end {
			pieceEnd = max(cur, kept[j].start)
		}
		if ps, pe := trimToValue(m.text, cur, pieceEnd); ps < pe {
			m.piece(ps, pe, typ)
		}
		if j >= len(kept) || kept[j].start >= end {
			break
		}
		cur = max(cur, kept[j].end)
	}
}

// piece заменяет маской участок [start, end) ответа.
func (m *respMasker) piece(start, end int, typ pii.Type) {
	m.b.WriteString(m.text[m.prev:start])
	value := m.text[start:end]
	key := respSeqKey{t: typ, v: value}
	seq, ok := m.local[key]
	if !ok {
		m.next[typ]++
		seq = m.sc.maxSeq[typ] + m.next[typ]
		m.local[key] = seq
	}
	strat := m.c.Strategy(typ)
	if strat.Name() == syntheticStrategy {
		// ПД, найденные в ответе модели, клиент получает плейсхолдером, а
		// не синтетикой: правдоподобное вымышленное значение в ответе
		// читалось бы как настоящее. Именно так «Пётр Петрович» из ответа
		// модели превращался в «Сидоров Пётр» у клиентки (Б4-8): модель
		// переписала выданную синтетику по-своему, детекция нашла в этом
		// новое ФИО и замаскировала его следующим вымышленным именем.
		strat = mask.Placeholder{}
	}
	m.b.WriteString(strat.Mask(value, typ, seq))
	m.st.masked++
	m.st.maskedSet = m.st.maskedSet.Add(typ)
	m.st.maskedCounts[typ]++
	m.prev = end
}

// trimToValue сужает участок [start, end) до первой и последней буквы или
// цифры: остаток спана после вычитания защищённых участков начинается и
// заканчивается разделителями, которые значением не являются.
func trimToValue(text string, start, end int) (int, int) {
	for start < end {
		r, n := utf8.DecodeRuneInString(text[start:end])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			break
		}
		start += n
	}
	for end > start {
		r, n := utf8.DecodeLastRuneInString(text[start:end])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			break
		}
		end -= n
	}
	return start, end
}

// respSeqKey — ключ нумерации масок в ответе модели: одинаковые значения
// одного типа получают один номер.
type respSeqKey struct {
	t pii.Type
	v string
}
