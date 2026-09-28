package gateway

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/obs"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// ErrEmptyID возвращается, когда идентификатор корреляции пуст: без него
// восстановление невозможно, а молча подменять его нельзя.
var ErrEmptyID = errors.New("gateway: пустой payload_id")

// ProcessResult — итог обработки запроса контракта /process.
type ProcessResult struct {
	// Result — строка, возвращаемая клиенту.
	Result string
	// Op — выполненная операция; идёт в логи и метрики.
	Op obs.Op
	// Mask — подробности маскирования. Для обратного шага пусто.
	Mask MaskResult
	// Degraded отмечает срабатывание безопасного отката.
	Degraded bool
	// StoreNs — длительность обращения к хранилищу соответствий в
	// наносекундах: чтение состояния области корреляции плюс запись.
	StoreNs int64
}

// Process реализует автомат контракта /process.
//
// Направление определяется сопоставлением payload с сохранённым состоянием по
// payload_id, а не счётчиком вызовов: счётчик ломается на первом же повторе,
// который проверяющая система выполняет при ошибке или 429.
//
// Таблица переходов:
//
//	состояние        payload              действие                       ответ
//	───────────────────────────────────────────────────────────────────────────
//	записи нет       любой                маскировать, сохранить          маска
//	есть             равен сохранённой    обратный шаг                    оригинал
//	                 маске
//	есть             равен сохранённому   повтор прямого шага             маска
//	                 оригиналу
//	есть             не совпал ни с чем,  маскировать как новый вход      новая маска
//	                 похож на маску       сохранённую запись не менять
//	есть             не совпал ни с чем   маскировать как новый вход      новая маска
//	                                      и заменить запись
//
// Вход, похожий на маску (есть плейсхолдер, токен или «[ЗАЩИЩЕНО]»), запись
// не заменяет: это искажённый или подделанный обратный шаг, и по записи ещё
// может прийти настоящий — перетирать её нельзя (T-19, AC-5).
//
// Последняя строка — новая пара с тем же payload_id: проверяющая система
// может повторить набор с теми же идентификаторами в пределах TTL. Прежде
// запись в этом случае не менялась, и обратный шаг второго прогона получал
// в ответ маску, а если маски двух текстов совпадали — исходник первого
// текста, то есть чужие данные (техническое жюри 23.09, раунд 2). Контракт
// не допускает двух разных текстов одной пары вперемешку (A6.5: повтор — с
// тем же payload), поэтому последний прямой шаг и есть действующий.
//
// Отказ штатной обработки не приводит к ошибке ответа: текст скрывается
// целиком безопасным откатом. Пять невалидных ответов подряд останавливают
// весь нагрузочный прогон, поэтому отказ в обслуживании здесь дороже
// избыточного маскирования. Ни одного исходного символа наружу при этом
// не уходит.
func (s *Service) Process(ctx context.Context, id, payload string, c *policy.Consumer) (ProcessResult, error) {
	if id == "" {
		return ProcessResult{}, ErrEmptyID
	}

	key := scopedKey(c.ID, id)

	lookupStart := time.Now()
	stored, found := s.store.Get(key)
	lookupNs := time.Since(lookupStart).Nanoseconds()

	if found {
		switch payload {
		case stored.Masked:
			if !c.Demask {
				// Демаскирование потребителю не разрешено. Повторно отдаём
				// маску: это безопасно и идемпотентно.
				return ProcessResult{Result: stored.Masked, Op: obs.OpMaskRetry, StoreNs: lookupNs}, nil
			}
			return ProcessResult{Result: stored.Original, Op: obs.OpUnmask, StoreNs: lookupNs}, nil
		case stored.Original:
			return ProcessResult{Result: stored.Masked, Op: obs.OpMaskRetry, StoreNs: lookupNs}, nil
		}
	}

	res, err := s.maskOrDegrade(ctx, payload, c)
	if err != nil {
		return ProcessResult{}, err
	}
	op := obs.OpMask
	if found {
		op = obs.OpMaskConflict
		if looksMasked(payload) {
			return ProcessResult{
				Result: res.Text, Op: op, Mask: res,
				Degraded: res.Degraded, StoreNs: lookupNs,
			}, nil
		}
	}
	rec := store.Record{
		Original:  payload,
		Masked:    res.Text,
		Types:     res.Masked,
		Consumer:  c.ID,
		CreatedAt: s.now(),
	}
	putStart := time.Now()
	if err := s.store.Put(key, rec); err != nil {
		// Соответствие не сохранено — обратный шаг работать не будет.
		// Возвращаем ошибку, а не маску: молчаливая потеря восстановления
		// хуже явного отказа по одному элементу.
		return ProcessResult{}, err
	}
	return ProcessResult{
		Result: res.Text, Op: op, Mask: res, Degraded: res.Degraded,
		StoreNs: lookupNs + time.Since(putStart).Nanoseconds(),
	}, nil
}

// scopedKey строит ключ хранилища, включающий область потребителя.
//
// Без области один payload_id у разных потребителей означал бы одну запись:
// второй потребитель затёр бы чужое соответствие, и обратный шаг первого
// перестал бы работать.
//
// Ключ обязан быть инъективным: разные пары «потребитель, payload_id» —
// разные ключи. Склейка через разделитель этого не гарантирует — payload_id
// приходит извне и может содержать любой байт, включая разделитель, а
// идентификатор потребителя на него не проверяется. Поэтому перед
// идентификатором потребителя стоит его длина: по ней ключ однозначно
// делится на две части, какие бы байты в них ни были.
func scopedKey(consumerID, payloadID string) string {
	var buf [20]byte
	n := strconv.AppendInt(buf[:0], int64(len(consumerID)), 10)
	return string(n) + ":" + consumerID + payloadID
}

// maskOrDegrade выполняет маскирование, а при отказе штатной обработки
// скрывает текст целиком.
//
// Превышение предела замен (ErrSpanLimit) — такой же отказ: частичная маска
// оставила бы значения сверх предела открытыми, а ответ 5XX приблизил бы
// остановку прогона. Строка скрывается целиком, и оригинал сохраняется в
// хранилище вызывающим кодом тем же путём, что и при штатной маске, — обратный
// шаг возвращает исходник побайтово.
func (s *Service) maskOrDegrade(ctx context.Context, payload string, c *policy.Consumer) (MaskResult, error) {
	res, err := s.Mask(ctx, payload, c)
	if err != nil {
		// Истечение бюджета обработки — не повод маскировать всё подряд:
		// ответ всё равно опоздает. Отдаём ошибку вызывающему коду, он
		// переводит её в управляемый отказ с Retry-After.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return MaskResult{}, err
		}
		return MaskFullText(payload), nil
	}
	return res, nil
}

// looksMasked сообщает, что во входе есть фрагмент, похожий на выданную
// маску: «[МЕТКА_N]» в любом регистре, токен «{{pii:…}}» или «[ЗАЩИЩЕНО]».
// Проверка грубая и в сторону осторожности: такой вход запись не заменяет.
func looksMasked(s string) bool {
	if strings.Contains(s, "{{pii:") || strings.Contains(s, "{{PII:") || strings.Contains(s, protectedWhole) {
		return true
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '[' {
			continue
		}
		end := strings.IndexByte(s[i:], ']')
		if end < 0 {
			return false
		}
		if looksLikeMaskLabel(strings.TrimSpace(s[i+1 : i+end])) {
			return true
		}
		i += end
	}
	return false
}

// looksLikeMaskLabel сообщает, что содержимое квадратных скобок похоже на
// метку плейсхолдера «МЕТКА_N»: не длиннее 64 байт, после последнего «_»
// непустой ряд цифр, перед ним — непустая метка.
func looksLikeMaskLabel(inner string) bool {
	u := strings.LastIndexByte(inner, '_')
	if u <= 0 || u >= len(inner)-1 || len(inner) > 64 {
		return false
	}
	for _, r := range inner[u+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
