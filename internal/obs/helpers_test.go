package obs

// Общие фикстуры внутренних тестов пакета. Значения синтетические: реальные
// персональные данные в репозиторий не попадают.

// Потребители и ключи записей журнала.
const (
	callerDemo      = "demo"
	callerCRM       = "crm"
	callerBenchmark = "benchmark"
	reqCRM          = "req-crm"

	keyConsumer      = "consumer"
	keyRequestID     = "request_id"
	keyOwner         = "owner"
	keyEndpoint      = "endpoint"
	keyType          = "type"
	keyLevel         = "level"
	keyMsg           = "msg"
	keyDetectedTypes = "detected_types"
	keyMaskedTypes   = "masked_types"
	keyMaskedCount   = "masked_count"
	keyDurationMS    = "duration_ms"
	keyOutcome       = "outcome"
	keyError         = "error"

	msgHandled = "запрос обработан"
)

// Значения меток, типов ПД и синтетическое ФИО.
const (
	opMaskName          = "mask"
	endpointProcessName = "process"
	typeFullName        = "full_name"
	fioIvanov           = "Иванов Иван Иванович"
)

// Имена рядов экспозиции.
const (
	metricDurationBucket = "aigw_request_duration_seconds_bucket"
	metricStoreEntries   = "aigw_store_entries"
	metricPIIDetected    = "aigw_pii_detected_total"
	leInf                = "+Inf"
)

// Настройки журнала.
const (
	formatJSON    = "json"
	formatText    = "text"
	levelInfo     = "info"
	levelError    = "error"
	fmtLoggerFail = "сборка журнала: %v"
)
