package pii

import "testing"

// keyBankAccount — ключ номера банковского счёта в конфигурации.
const keyBankAccount = "bank_account"

// TestTypeValuesStable закрепляет значения типов: они служат индексами
// массивов счётчиков, битами множества и порядком в отчётах, поэтому новый тип
// добавляется только в конец и ни одно прежнее значение не сдвигает.
func TestTypeValuesStable(t *testing.T) {
	want := []struct {
		typ Type
		val int
		key string
	}{
		{Unknown, 0, "unknown"},
		{FullName, 1, "full_name"},
		{BirthDate, 2, "birth_date"},
		{BirthPlace, 3, "birth_place"},
		{Citizenship, 4, "citizenship"},
		{PassportNumber, 5, "passport_number"},
		{PassportAuthority, 6, "passport_authority"},
		{PassportDeptCode, 7, "passport_dept_code"},
		{PassportIssueDate, 8, "passport_issue_date"},
		{DriverLicense, 9, "driver_license"},
		{Address, 10, "address"},
		{Email, 11, "email"},
		{Phone, 12, "phone"},
		{INN, 13, "inn"},
		{CardNumber, 14, "card_number"},
		{CVV, 15, "cvv"},
		{PIN, 16, "pin"},
		{CardHolder, 17, "card_holder"},
		{SNILS, 18, "snils"},
		{ForeignPassport, 19, "foreign_passport"},
		{OMSPolicy, 20, "oms_policy"},
		{VehicleReg, 21, "vehicle_reg"},
		{VIN, 22, "vin"},
		{OGRN, 23, "ogrn"},
		{BankAccount, 24, keyBankAccount},
	}
	if len(want) != Count {
		t.Fatalf("в таблице теста %d типов, в реестре %d: новый тип не внесён в тест", len(want), Count)
	}
	for _, w := range want {
		if int(w.typ) != w.val {
			t.Errorf("%s = %d, ожидалось %d: значение типа сдвинуто", w.key, w.typ, w.val)
		}
		if w.typ.Key() != w.key {
			t.Errorf("тип %d: ключ %q, ожидался %q", w.val, w.typ.Key(), w.key)
		}
	}
}

// TestBankAccountMeta — метаданные номера банковского счёта (T-64):
// дополнительный тип, не входящий в обязательные 17 категорий ТЗ §3.2.1.
func TestBankAccountMeta(t *testing.T) {
	if got := BankAccount.Key(); got != keyBankAccount {
		t.Errorf("Key() = %q", got)
	}
	if got := BankAccount.Label(); got != "Номер банковского счёта" {
		t.Errorf("Label() = %q", got)
	}
	if got := BankAccount.Placeholder(); got != "СЧЁТ" {
		t.Errorf("Placeholder() = %q", got)
	}
	if BankAccount.Required() {
		t.Error("номер счёта не входит в обязательное покрытие ТЗ §3.2.1")
	}
	if got, ok := ByKey(keyBankAccount); !ok || got != BankAccount {
		t.Errorf("ByKey(bank_account) = %v, %v", got, ok)
	}
	if !FullSet().Has(BankAccount) {
		t.Error("FullSet не содержит номер счёта: types: [all] его бы не включил")
	}
}

// TestRequiredCount — обязательных типов ровно 17, как в ТЗ §3.2.1:
// дополнительный тип их числа не меняет.
func TestRequiredCount(t *testing.T) {
	n := 0
	for _, tp := range All() {
		if tp.Required() {
			n++
		}
	}
	if n != 17 {
		t.Fatalf("обязательных типов %d, ожидалось 17", n)
	}
}

// TestMetaUnique — ключ и основа плейсхолдера различают типы: совпадение
// ключей сломало бы конфигурацию, совпадение плейсхолдеров — демаскирование.
func TestMetaUnique(t *testing.T) {
	keys := make(map[string]Type, Count)
	holders := make(map[string]Type, Count)
	for _, tp := range All() {
		if tp.Key() == "" || tp.Label() == "" || tp.Placeholder() == "" {
			t.Errorf("тип %d без метаданных", tp)
		}
		if prev, ok := keys[tp.Key()]; ok {
			t.Errorf("ключ %q у типов %d и %d", tp.Key(), prev, tp)
		}
		keys[tp.Key()] = tp
		if prev, ok := holders[tp.Placeholder()]; ok {
			t.Errorf("плейсхолдер %q у типов %d и %d", tp.Placeholder(), prev, tp)
		}
		holders[tp.Placeholder()] = tp
	}
}

// TestSetWidth — множество типов — битовая маска Set; тип сверх её
// разрядности молча выпал бы из всех наборов.
func TestSetWidth(t *testing.T) {
	if Count > 32 {
		t.Fatalf("типов %d, а Set вмещает 32", Count)
	}
	if FullSet().Len() != Count-1 {
		t.Fatalf("FullSet содержит %d типов, зарегистрировано %d", FullSet().Len(), Count-1)
	}
}
