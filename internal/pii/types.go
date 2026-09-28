// Package pii — реестр типов персональных данных.
//
// Тип ПД представлен плотным целочисленным значением: это позволяет держать
// наборы типов в битовой маске и индексировать счётчики массивом, без
// аллокаций в горячем пути.
package pii

// Type — тип персональных данных.
type Type uint8

// Обязательные типы по ТЗ §3.2.1 (17 категорий) и дополнительные документы
// из ТЗ §6. Порядок значений менять нельзя: он используется как индекс массива.
const (
	Unknown Type = iota

	// Личные данные.
	FullName
	BirthDate
	BirthPlace
	Citizenship

	// Паспорт РФ.
	PassportNumber
	PassportAuthority
	PassportDeptCode
	PassportIssueDate

	// Водительское удостоверение.
	DriverLicense

	// Адрес.
	Address

	// Контакты.
	Email
	Phone

	// Финансовые.
	INN
	CardNumber
	CVV
	PIN
	CardHolder

	// Дополнительные документы (ТЗ §6, бонус).
	SNILS
	ForeignPassport
	OMSPolicy
	VehicleReg
	VIN
	OGRN
	// BankAccount — номер банковского счёта: двадцать цифр, первые пять —
	// балансовый счёт («40817…»). В обязательные категории ТЗ §3.2.1 не
	// входит, но для банка это банковская тайна (бизнес-жюри 23.09, раунд 4,
	// Б4-14). Добавлен в конец: значения остальных типов — индексы массивов
	// и ключи счётчиков, и сдвигать их нельзя.
	BankAccount

	// count — служебная граница; всегда последняя.
	count
)

// Count — число зарегистрированных типов, включая Unknown.
const Count = int(count)

type meta struct {
	key         string // машинный ключ: в конфиге, логах и метриках
	label       string // человекочитаемое имя для отчётов и UI
	placeholder string // основа плейсхолдера: [ФИО_1]
	required    bool   // входит в обязательное покрытие ТЗ §3.2.1
}

var metas = [Count]meta{
	Unknown:           {"unknown", "Неизвестно", "PII", false},
	FullName:          {"full_name", "ФИО", "ФИО", true},
	BirthDate:         {"birth_date", "Дата рождения", "ДАТА_РОЖДЕНИЯ", true},
	BirthPlace:        {"birth_place", "Место рождения", "МЕСТО_РОЖДЕНИЯ", true},
	Citizenship:       {"citizenship", "Гражданство", "ГРАЖДАНСТВО", true},
	PassportNumber:    {"passport_number", "Серия и номер паспорта", "ПАСПОРТ", true},
	PassportAuthority: {"passport_authority", "Орган, выдавший паспорт", "ОРГАН_ВЫДАЧИ", true},
	PassportDeptCode:  {"passport_dept_code", "Код подразделения", "КОД_ПОДРАЗДЕЛЕНИЯ", true},
	PassportIssueDate: {"passport_issue_date", "Дата выдачи паспорта", "ДАТА_ВЫДАЧИ", true},
	DriverLicense:     {"driver_license", "Водительское удостоверение", "ВОДИТЕЛЬСКОЕ_УДОСТОВЕРЕНИЕ", true},
	Address:           {"address", "Адрес", "АДРЕС", true},
	Email:             {"email", "Email", "EMAIL", true},
	Phone:             {"phone", "Номер телефона", "ТЕЛЕФОН", true},
	INN:               {"inn", "ИНН", "ИНН", true},
	CardNumber:        {"card_number", "Номер банковской карты", "КАРТА", true},
	CVV:               {"cvv", "CVV-код", "CVV", true},
	PIN:               {"pin", "ПИН-код карты", "ПИН", true},
	CardHolder:        {"card_holder", "Имя держателя карты", "ДЕРЖАТЕЛЬ_КАРТЫ", true},
	SNILS:             {"snils", "СНИЛС", "СНИЛС", false},
	ForeignPassport:   {"foreign_passport", "Загранпаспорт", "ЗАГРАНПАСПОРТ", false},
	OMSPolicy:         {"oms_policy", "Полис ОМС", "ПОЛИС_ОМС", false},
	VehicleReg:        {"vehicle_reg", "Госномер транспортного средства", "ГОСНОМЕР", false},
	VIN:               {"vin", "VIN транспортного средства", "VIN", false},
	OGRN:              {"ogrn", "ОГРН", "ОГРН", false},
	BankAccount:       {"bank_account", "Номер банковского счёта", "СЧЁТ", false},
}

// Key возвращает машинный ключ типа: используется в конфиге, логах и метриках.
func (t Type) Key() string { return metas[t.clamp()].key }

// Label возвращает человекочитаемое имя типа для отчётов и демо-стенда.
func (t Type) Label() string { return metas[t.clamp()].label }

// Placeholder возвращает основу плейсхолдера без номера и скобок.
func (t Type) Placeholder() string { return metas[t.clamp()].placeholder }

// Required сообщает, входит ли тип в обязательное покрытие ТЗ §3.2.1.
func (t Type) Required() bool { return metas[t.clamp()].required }

// String реализует fmt.Stringer через машинный ключ.
func (t Type) String() string { return t.Key() }

func (t Type) clamp() Type {
	if int(t) >= Count {
		return Unknown
	}
	return t
}

// All возвращает все типы, кроме Unknown, в порядке объявления.
func All() []Type {
	out := make([]Type, 0, Count-1)
	for t := Type(1); int(t) < Count; t++ {
		out = append(out, t)
	}
	return out
}

// ByKey разбирает машинный ключ типа. Второе значение — признак успеха.
func ByKey(key string) (Type, bool) {
	for t := Type(1); int(t) < Count; t++ {
		if metas[t].key == key {
			return t, true
		}
	}
	return Unknown, false
}
