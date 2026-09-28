package detect

// Сообщения проверок сканера ФИО, которых нет в общем messages_test.go.
const (
	msgSpanNotFound   = "спан %q не найден: %s"
	msgConfWantRule   = "уверенность %v, ожидалась %v (%s)"
	msgCandidateLevel = "кандидат %q уровня %v: %s"
)

// Синтетические ФИО и их части, которые повторяются в таблицах тестов
// сканера ФИО. Ни одно значение не принадлежит живому человеку.
const (
	nameFxIvanovFull       = "Иванов Иван Иванович"
	nameFxPetrovaFull      = "Петрова Анна Сергеевна"
	nameFxIvanov           = "Иванов"
	nameFxIvanovLower      = "иванов"
	nameFxIvanovIvanLower  = "иванов иван"
	nameFxIvanIvanovich    = "Иван Иванович"
	nameFxOlegPetrovich    = "Олег Петрович"
	nameFxOlegPetrovichLow = "олег петрович"
	nameFxAnnaPetrovna     = "Анна Петровна"
	nameFxMatveevnaGvozd   = "Матвеевна Гвоздарёва"
	nameFxKimOleg          = "Ким Олег"
	nameFxShultsInitials   = "Шульц Т. М."
	nameFxMelnik           = "Мельник"
	nameFxKoval            = "Коваль"
	nameFxKorneeva         = "Корнеева"
	nameFxChernysh         = "Черныш"
	nameFxShevchuk         = "Шевчук"
)
