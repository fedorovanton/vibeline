package config

// File — корень файла конфигурации.
type File struct {
	Server    ServerSection     `yaml:"server"`
	Store     StoreSection      `yaml:"store"`
	LLM       LLMSection        `yaml:"llm"`
	Detection DetectionSection  `yaml:"detection"`
	Logging   LoggingSection    `yaml:"logging"`
	Consumers []ConsumerSection `yaml:"consumers"`
}

// ServerSection — параметры HTTP-сервера и ограничения входа.
type ServerSection struct {
	Addr string `yaml:"addr"`
	// MaxBodyBytes ограничивает размер тела запроса. Вход до 100 000 токенов
	// требует запаса: одна кириллическая буква занимает два байта.
	MaxBodyBytes Bytes `yaml:"max_body_bytes"`
	// MaxConcurrent — предел одновременно обрабатываемых запросов. При его
	// достижении сервис отвечает 429 с Retry-After, а не копит очередь.
	MaxConcurrent int      `yaml:"max_concurrent"`
	ReadTimeout   Duration `yaml:"read_timeout"`
	WriteTimeout  Duration `yaml:"write_timeout"`
	IdleTimeout   Duration `yaml:"idle_timeout"`
	// RequestTimeout — бюджет локальной обработки одного запроса: детекция,
	// применение политики, маскирование и запись соответствий в Store.
	// Ожидание ответа модели в него не входит и ограничено отдельно —
	// LLM.Timeout, — иначе продуктовый прокси рвал бы длинные запросы.
	// На /process это весь запрос целиком: модель там не вызывается.
	RequestTimeout  Duration `yaml:"request_timeout"`
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
}

// StoreSection — параметры хранилища соответствий.
type StoreSection struct {
	TTL           Duration `yaml:"ttl"`
	MaxEntries    int      `yaml:"max_entries"`
	MaxBytes      Bytes    `yaml:"max_bytes"`
	SweepInterval Duration `yaml:"sweep_interval"`
}

// LLMSection — параметры downstream-модели.
type LLMSection struct {
	// Mode: alfagen — реальный вызов, stub — демонстрационный ответ без сети.
	Mode      string   `yaml:"mode"`
	BaseURL   string   `yaml:"base_url"`
	Model     string   `yaml:"model"`
	Timeout   Duration `yaml:"timeout"`
	APIKeyEnv string   `yaml:"api_key_env"`
}

// DetectionSection — параметры движка детекции по умолчанию.
type DetectionSection struct {
	Profile  string `yaml:"profile"`
	MaxSpans int    `yaml:"max_spans"`
}

// LoggingSection — параметры журналирования.
type LoggingSection struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// ConsumerSection — описание одной системы-потребителя.
type ConsumerSection struct {
	ID      string `yaml:"id"`
	Enabled *bool  `yaml:"enabled"`
	// APIKeyEnv — имя переменной окружения с ключом. Основной способ:
	// файл конфигурации попадает в репозиторий и в архив сдачи, поэтому
	// рабочие ключи задаются окружением.
	APIKeyEnv string `yaml:"api_key_env"`
	// APIKey — ключ прямо в конфигурации. Предназначен только для
	// демонстрационного потребителя, чтобы проверяющий мог запустить сервис
	// по README без предварительной настройки окружения. Переменная
	// окружения из APIKeyEnv имеет приоритет и перекрывает это значение.
	//
	// Рабочие ключи сюда класть нельзя: сборка архива ищет секреты в
	// содержимом, но отличить рабочий ключ от демонстрационного она не может.
	APIKey string `yaml:"api_key"`
	// Types — список машинных ключей типов ПД либо [all].
	Types   []string `yaml:"types"`
	Demask  *bool    `yaml:"demask"`
	Masking *bool    `yaml:"masking"`
	Profile string   `yaml:"profile"`
	// MaxSpans переопределяет общий предел числа замен.
	MaxSpans int            `yaml:"max_spans"`
	Mask     MaskSection    `yaml:"mask"`
	Combos   []ComboSection `yaml:"combinations"`
	// ModelRate — лимит частоты обращений потребителя к маршрутам, которые
	// вызывают модель: /v1/chat/completions и /api/v1/analyze. Не задан —
	// лимита нет. На /process и маршруты без модели не действует.
	ModelRate *RateSection `yaml:"model_rate"`
}

// RateSection — параметры token bucket: средняя частота и всплеск.
type RateSection struct {
	// RPS — сколько запросов в секунду восполняется в корзине. Ноль —
	// лимит выключен.
	RPS float64 `yaml:"rps"`
	// Burst — ёмкость корзины: сколько запросов подряд проходит без паузы.
	// Ноль — округлённая вверх частота, но не меньше одного.
	Burst int `yaml:"burst"`
}

// MaskSection — выбор стратегии маскирования.
type MaskSection struct {
	Default string            `yaml:"default"`
	PerType map[string]string `yaml:"per_type"`
}

// ComboSection — правило маскирования по комбинации типов.
type ComboSection struct {
	Mask     []string `yaml:"mask"`
	OnlyWith []string `yaml:"only_with"`
}
