package detect

// Сообщения проверок, общие для тестов сканеров и движка. Вынесены, чтобы
// одна и та же формулировка не повторялась литералом в каждом файле.
const (
	msgDetectFailed    = "Detect: %v"
	msgSpanWant        = "спан %q, ожидался %q"
	msgConfWant        = "уверенность %v, ожидалась %v"
	msgAllocsWant      = "аллокаций на вызов: %v, ожидалось 0"
	msgNoCandidates    = "кандидаты не ожидались, получено %d: %q"
	msgOneCandidate    = "найдено %d кандидатов, ожидался один"
	msgOneCandidateGot = "найдено %d кандидатов, ожидался один: %v"
	msgSpanStartWant   = "начало спана %d, ожидалось %d"
	msgSpanEndWant     = "конец спана %d, ожидался %d"
	msgBenchTextSize   = "длина текста %d байт, ожидалось около 4 КБ"
	msgMaskWant        = "маска\n  получено: %s\n  ожидалось: %s"
	msgOneSpanGot      = "спанов %d, ожидался один: %s"
	msgDictLoad        = "загрузка справочников: %v"
	msgScanAllocs      = "Scan аллоцирует: %.0f allocs/op"
)
