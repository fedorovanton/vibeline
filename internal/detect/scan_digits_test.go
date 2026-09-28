package detect

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Все номера в тестах синтетические. Исключение — ИНН 7707083893: это
// публичный реквизит юридического лица, персональными данными он не является.
// ИНН организации 7710564237 — синтетический, с верной контрольной суммой.

// digitsWant — ожидаемый кандидат: тип, точный текст спана и уверенность.
type digitsWant struct {
	typ  pii.Type
	text string
	conf Confidence
}

func TestScanDigits(t *testing.T) {
	cases := []struct {
		name string
		text string
		// want — кандидаты, которые обязаны быть найдены.
		want []digitsWant
		// absent — типы, которых в кандидатах быть не должно.
		absent []pii.Type
	}{
		// Паспорт: AC-1.
		{
			name: "паспорт серией и номером через пробел",
			text: "Паспорт 4509 123456 выдан отделом",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},
		{
			name: "паспорт десятью цифрами подряд с маркером",
			text: "паспорт 4509123456",
			want: []digitsWant{{pii.PassportNumber, dfxPassportRun, Strong}},
		},
		{
			name: "паспорт десятью цифрами подряд без маркера — только форма",
			text: "В анкете указано 4509123456 и ничего больше",
			want: []digitsWant{{pii.PassportNumber, dfxPassportRun, Weak}},
		},
		{
			name: "паспорт серией из двух пар",
			text: "паспорт 45 09 123456",
			want: []digitsWant{{pii.PassportNumber, "45 09 123456", Strong}},
		},
		{
			name: "конструкция серия — номер даёт два спана без служебного слова",
			text: "серия 4509 номер 123456",
			want: []digitsWant{
				{pii.PassportNumber, "4509", Strong},
				{pii.PassportNumber, "123456", Strong},
			},
		},
		{
			name: "серия двумя парами и номер после знака номера",
			text: "паспорт серия 32 07 № 481905",
			want: []digitsWant{
				{pii.PassportNumber, "32 07", Strong},
				{pii.PassportNumber, "481905", Strong},
			},
		},
		{
			name:   "четыре цифры без паспортного контекста паспортом не считаются",
			text:   "в 4509 году такого не было",
			absent: []pii.Type{pii.PassportNumber, pii.PIN},
		},
		{
			name:   "две пары цифр без контекста документа серией не считаются",
			text:   "в отчёте строки 32 07 и всё",
			absent: []pii.Type{pii.PassportNumber, pii.DriverLicense},
		},

		// Водительское удостоверение в раздельной записи.
		{
			name: "водительское удостоверение серией и номером порознь",
			text: "водительское удостоверение серия 5511 номер 730164",
			want: []digitsWant{
				{pii.DriverLicense, "5511", Strong},
				{pii.DriverLicense, "730164", Strong},
			},
		},
		{
			name: "ближайший маркер разводит паспорт и в/у, стоящие рядом",
			text: "ВУ 6301472085, паспорт серия 8240 номер 316502",
			want: []digitsWant{
				{pii.DriverLicense, "6301472085", Strong},
				{pii.PassportNumber, "8240", Strong},
				{pii.PassportNumber, "316502", Strong},
			},
		},

		// Номер договора: та же форма, но не персональные данные.
		{
			name:   "номер договора паспортом не считается",
			text:   "номер договора 5108 224937 указан в обращении",
			absent: []pii.Type{pii.PassportNumber, pii.DriverLicense},
		},
		{
			name:   "номер договора через дефис паспортом не считается",
			text:   "В реестре договор 7012-583164 закрыт",
			absent: []pii.Type{pii.PassportNumber, pii.DriverLicense},
		},
		{
			name:   "серия и номер договора паспортом не считаются",
			text:   "соглашение серия 9315 номер 640228",
			absent: []pii.Type{pii.PassportNumber, pii.DriverLicense},
		},
		{
			name: "договор в том же предложении не снимает паспорт при своём маркере",
			text: "паспорт 4509 123456 приложен к договору",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},

		// Карта: AC-2.
		{
			name: "номер карты группами по четыре проходит Луна",
			text: "Карта 2200 7001 2345 6781 действительна",
			want: []digitsWant{{pii.CardNumber, "2200 7001 2345 6781", Certain}},
		},
		{
			name: "номер карты слитно проходит Луна",
			text: "карта 2200700123456781",
			want: []digitsWant{{pii.CardNumber, "2200700123456781", Certain}},
		},
		{
			name: "шестнадцать цифр без Луна рядом со словом карта",
			text: "Карта 2200 7001 2345 6789 указана с ошибкой",
			want: []digitsWant{{pii.CardNumber, dfxCardNoLuhn, Strong}},
		},
		{
			name: "шестнадцать цифр без Луна и без маркера остаются формой",
			text: "Код 2200 7001 2345 6789 указан с ошибкой",
			want: []digitsWant{{pii.CardNumber, dfxCardNoLuhn, Weak}},
		},
		{
			name: "маркер карты рядом с договором не поднимает номер",
			text: "Договор 2200 7001 2345 6789 привязан к карте",
			want: []digitsWant{{pii.CardNumber, dfxCardNoLuhn, Weak}},
		},
		{
			name:   "группы не по четыре номером карты не считаются",
			text:   "заказы 22007 0012 3456 6781 обработаны",
			absent: []pii.Type{pii.CardNumber},
		},

		// ИНН: AC-3.
		{
			name: "ИНН с верной контрольной суммой",
			text: "ИНН 7707083893",
			want: []digitsWant{{pii.INN, "7707083893", Certain}},
		},
		{
			name: "двенадцатизначный ИНН с верной контрольной суммой",
			text: "инн 500100732259 в заявлении",
			want: []digitsWant{{pii.INN, dfxPersonINN, Certain}},
		},
		{
			name: "ИНН с неверной суммой держится на маркере",
			text: "ИНН 1234567890",
			want: []digitsWant{{pii.INN, "1234567890", Strong}},
		},
		{
			name:   "десять цифр с неверной суммой и без маркера — не ИНН",
			text:   "в отчёте встретилось 1234567890 и всё",
			absent: []pii.Type{pii.INN},
		},

		// Телефон: AC-4, AC-9.
		{
			name: "телефон с плюсом и дефисами",
			text: "тел. +7 916 123-45-67",
			want: []digitsWant{{pii.Phone, "+7 916 123-45-67", Strong}},
		},
		{
			name: "мобильный в скобках без маркера",
			text: "8(916)1234567",
			want: []digitsWant{{pii.Phone, "8(916)1234567", Strong}},
		},
		{
			name: "карта с неразрывными пробелами",
			text: "карта 4111\u00a01111\u00a01111\u00a01111",
			want: []digitsWant{{pii.CardNumber, "4111\u00a01111\u00a01111\u00a01111", Certain}},
		},
		{
			name: "телефон с узким неразрывным пробелом",
			text: "тел. +7\u202f916\u202f123-45-67",
			want: []digitsWant{{pii.Phone, "+7\u202f916\u202f123-45-67", Strong}},
		},
		{
			name: "мобильный слитно без маркера",
			text: "Мой номер 89161234567, перезвоните после 18",
			want: []digitsWant{{pii.Phone, "89161234567", Strong}},
		},
		{
			name: "городской без маркера остаётся формой",
			text: "8(495)1234567",
			want: []digitsWant{{pii.Phone, "8(495)1234567", Weak}},
		},
		{
			name: "английский маркер телефона",
			text: "phone 8 495 123 45 67",
			want: []digitsWant{{pii.Phone, "8 495 123 45 67", Strong}},
		},
		{
			name: "английский маркер паспорта",
			text: "Ivan Ivanov, passport 4509 123456",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},
		{
			name: "телефон пробелами с маркером",
			text: "мобильный 8 916 123 45 67",
			want: []digitsWant{{pii.Phone, "8 916 123 45 67", Strong}},
		},
		{
			name:   "бесплатная линия телефоном клиента не является",
			text:   "позвоните на 8-800-555-35-35",
			absent: []pii.Type{pii.Phone},
		},
		{
			name:   "сервисный код банка телефоном клиента не является",
			text:   "смс на 8 900 123 45 67 не приходят",
			absent: []pii.Type{pii.Phone},
		},

		// CVV: AC-5.
		{
			name: "CVV с маркером",
			text: "cvv 123",
			want: []digitsWant{{pii.CVV, "123", Strong}},
		},
		{
			name: "код проверки как маркер CVV",
			text: "код проверки 456",
			want: []digitsWant{{pii.CVV, "456", Strong}},
		},
		{
			name:   "три цифры без маркера CVV не являются",
			text:   "доставка заняла 123 часа",
			absent: []pii.Type{pii.CVV},
		},

		// ПИН: AC-6.
		{
			name: "ПИН с маркером",
			text: "пин-код 1234",
			want: []digitsWant{{pii.PIN, "1234", Strong}},
		},
		{
			name: "латинский маркер ПИН",
			text: "pin 4321",
			want: []digitsWant{{pii.PIN, "4321", Strong}},
		},
		{
			name:   "четыре цифры без маркера ПИНом не являются",
			text:   "выпуск 1234 экземпляров",
			absent: []pii.Type{pii.PIN},
		},

		// Код подразделения: AC-7.
		{
			name: "код подразделения с маркером",
			text: "код подразделения 770-053",
			want: []digitsWant{{pii.PassportDeptCode, "770-053", Strong}},
		},
		{
			name: "код подразделения сокращением к/п",
			text: "к/п 770053",
			want: []digitsWant{{pii.PassportDeptCode, "770053", Strong}},
		},
		{
			name: "форма ddd-ddd без маркера остаётся слабой",
			text: "в графе стоит 770-053",
			want: []digitsWant{{pii.PassportDeptCode, "770-053", Weak}},
		},
		{
			name:   "шесть цифр подряд без маркера кодом подразделения не являются",
			text:   "тираж 770053 экземпляра",
			absent: []pii.Type{pii.PassportDeptCode},
		},

		// Водительское удостоверение: AC-8.
		{
			name: "водительское удостоверение вытесняет паспорт",
			text: "водительское удостоверение 7723 456789",
			want: []digitsWant{{pii.DriverLicense, "7723 456789", Strong}},
			// Форма та же, что у паспорта: при маркере в/у паспортного
			// кандидата быть не должно.
			absent: []pii.Type{pii.PassportNumber},
		},
		{
			name:   "сокращение в/у распознаётся тремя токенами",
			text:   "в/у 7723456789 выдано",
			want:   []digitsWant{{pii.DriverLicense, "7723456789", Strong}},
			absent: []pii.Type{pii.PassportNumber},
		},
		{
			name: "водительское удостоверение старого образца с буквами",
			text: "водительское удостоверение 77 АВ 123456",
			want: []digitsWant{{pii.DriverLicense, "77 АВ 123456", Strong}},
		},
		{
			name:   "тот же номер под паспортным маркером — паспорт, не в/у",
			text:   "паспорт 7723 456789",
			want:   []digitsWant{{pii.PassportNumber, "7723 456789", Strong}},
			absent: []pii.Type{pii.DriverLicense},
		},
		{
			name:   "форма dd AA dddddd без маркера удостоверением не является",
			text:   "партия 77 АВ 123456 отгружена",
			absent: []pii.Type{pii.DriverLicense},
		},

		// T-59, строка 1: CVV2 и описательные маркеры CVV.
		{
			name:   "CVV2 без двоеточия: цифра маркера не входит в значение",
			text:   "Карта 4111 1111 1111 1111, CVV2 417.",
			want:   []digitsWant{{pii.CVV, "417", Strong}},
			absent: []pii.Type{pii.PIN},
		},
		{
			name: "cvv2 строчными",
			text: "cvv2 417",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},
		{
			name: "CVC2",
			text: "CVC2 417",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},
		{
			name: "CVV2 рядом с ПИН не превращается в ПИН",
			text: "Карта 2200 6639 2332 1466, CVV2 582, ПИН 7310.",
			want: []digitsWant{{pii.CVV, "582", Strong}, {pii.PIN, "7310", Strong}},
		},
		{
			name: "CVV2/CVC2 через косую",
			text: "CVV2/CVC2: 417",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},
		{
			name: "код безопасности",
			text: "Карта 4111 1111 1111 1111, код безопасности 417.",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},
		{
			name: "защитный код",
			text: "защитный код 417",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},
		{
			name: "секретный код карты",
			text: "секретный код карты 417",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},
		{
			name: "на обороте без слова код — только форма",
			text: "три цифры на обороте 417",
			want: []digitsWant{{pii.CVV, "417", Weak}},
		},
		{
			name: "защитный без слова код — только форма",
			text: "защитный слой 417 мкм",
			want: []digitsWant{{pii.CVV, "417", Weak}},
		},
		{
			name:   "слово код само по себе CVV не задаёт",
			text:   "код 417 не подошёл",
			absent: []pii.Type{pii.CVV},
		},

		// T-59, строка 2: сокращения «код подр.», «подразд.», «КП».
		{
			name: "код подр. с точкой",
			text: "Паспорт 4509 123456, выдан 01.02.2015, код подр. 770-095.",
			want: []digitsWant{{pii.PassportDeptCode, "770-095", Strong}},
		},
		{
			name: "код подразд.",
			text: "код подразд. 500-001",
			want: []digitsWant{{pii.PassportDeptCode, "500-001", Strong}},
		},
		{
			name: "КП",
			text: "КП 500-001",
			want: []digitsWant{{pii.PassportDeptCode, "500-001", Strong}},
		},
		{
			name:   "подробно маркером подразделения не является",
			text:   "подробно 770095",
			absent: []pii.Type{pii.PassportDeptCode},
		},
		{
			name:   "КПП маркером подразделения не является",
			text:   "кпп 770201",
			absent: []pii.Type{pii.PassportDeptCode},
		},
		{
			name:   "диапазон через тире слабым кодом подразделения не становится",
			text:   "от 100–200 тысяч",
			absent: []pii.Type{pii.PassportDeptCode},
		},

		// T-59, строка 3: телефон без кода страны, тире, иностранные номера.
		{
			name: "код в скобках без +7 и 8",
			text: "Клиент Иванов Иван Иванович, телефон (916) 482-17-35.",
			want: []digitsWant{{pii.Phone, "(916) 482-17-35", Strong}},
		},
		{
			name: "код в скобках без маркера",
			text: "звоните (495) 123-45-67",
			want: []digitsWant{{pii.Phone, "(495) 123-45-67", Strong}},
		},
		{
			name: "городской через дефисы с маркером",
			text: "тел. 495-123-45-67",
			want: []digitsWant{{pii.Phone, "495-123-45-67", Strong}},
		},
		{
			name: "мобильный пробелом и дефисами с маркером",
			text: "мобильный 916 482-17-35",
			want: []digitsWant{{pii.Phone, "916 482-17-35", Strong}},
		},
		{
			name: "мобильный пробелами с маркером",
			text: "моб.: 916 482 17 35",
			want: []digitsWant{{pii.Phone, "916 482 17 35", Strong}},
		},
		{
			name: "мобильная форма 3-3-2-2 без маркера телефона",
			text: "Мой номер 916-123-45-67",
			want: []digitsWant{{pii.Phone, "916-123-45-67", Strong}},
		},
		{
			name: "код и номер одной группой",
			text: "тел.: 916 4821735",
			want: []digitsWant{{pii.Phone, "916 4821735", Strong}},
		},
		{
			name:   "десять цифр подряд при маркере телефона — телефон, а не ИНН",
			text:   "тел. 9161234567",
			want:   []digitsWant{{pii.Phone, "9161234567", Strong}},
			absent: []pii.Type{pii.INN, pii.PassportNumber},
		},
		{
			name:   "контактный номер — телефон, а не паспорт",
			text:   "контактный номер 9164821735",
			want:   []digitsWant{{pii.Phone, "9164821735", Strong}},
			absent: []pii.Type{pii.PassportNumber},
		},
		{
			name: "маркер телефона ближе маркера ИНН",
			text: "ИНН 500100732259, телефон 9161234567",
			want: []digitsWant{{pii.Phone, "9161234567", Strong}, {pii.INN, dfxPersonINN, Certain}},
		},
		{
			name:   "маркер паспорта ближе маркера телефона",
			text:   "паспорт 4509123456, телефон не указан",
			want:   []digitsWant{{pii.PassportNumber, dfxPassportRun, Strong}},
			absent: []pii.Type{pii.Phone},
		},
		{
			name:   "серия и номер при маркере телефона рядом остаются паспортом",
			text:   "телефон не указан, паспорт 4509 123456",
			want:   []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
			absent: []pii.Type{pii.Phone},
		},
		{
			name:   "бесплатная линия в скобках телефоном клиента не является",
			text:   "тел. (800) 555-35-35",
			absent: []pii.Type{pii.Phone},
		},
		{
			name:   "десять цифр подряд без маркера телефоном не являются",
			text:   "В анкете указано 9161234567 и ничего больше",
			absent: []pii.Type{pii.Phone},
		},
		{
			name: "городской семизначный с маркером",
			text: "тел. 123-45-67",
			want: []digitsWant{{pii.Phone, "123-45-67", Strong}},
		},
		{
			name:   "семь цифр без маркера телефоном не являются",
			text:   "артикул 123-45-67",
			absent: []pii.Type{pii.Phone},
		},
		{
			name: "короткое тире между группами",
			text: "телефон +7 916 123–45–67",
			want: []digitsWant{{pii.Phone, "+7 916 123–45–67", Strong}},
		},
		{
			name: "неразрывный дефис между группами",
			text: "телефон +7 916 123‑45‑67",
			want: []digitsWant{{pii.Phone, "+7 916 123‑45‑67", Strong}},
		},
		{
			name: "знак минуса между группами",
			text: "телефон +7 916 123−45−67",
			want: []digitsWant{{pii.Phone, "+7 916 123−45−67", Strong}},
		},
		{
			name: "карта через короткое тире",
			text: "карта 4111–1111–1111–1111",
			want: []digitsWant{{pii.CardNumber, "4111–1111–1111–1111", Certain}},
		},
		{
			name: "белорусский номер",
			text: "телефон +375 29 123-45-67",
			want: []digitsWant{{pii.Phone, "+375 29 123-45-67", Strong}},
		},
		{
			name: "украинский номер",
			text: "телефон +380 67 123 4567",
			want: []digitsWant{{pii.Phone, "+380 67 123 4567", Strong}},
		},
		{
			name: "американский номер",
			text: "phone +1 212 555 0100",
			want: []digitsWant{{pii.Phone, "+1 212 555 0100", Strong}},
		},
		{
			name:   "сумма с плюсом телефоном не является",
			text:   "поступление +12 345 678 руб",
			absent: []pii.Type{pii.Phone},
		},

		// T-59, строка 4: номер заявки, обращения, операции.
		{
			name:   "номер заявки паспортом не считается",
			text:   "Номер заявки 1234567890 от 03.03.2026.",
			absent: []pii.Type{pii.PassportNumber, pii.INN, pii.Phone},
		},
		{
			name:   "номер обращения паспортом не считается",
			text:   "Номер обращения 1234567890 от 03.03.2026.",
			absent: []pii.Type{pii.PassportNumber, pii.INN},
		},
		{
			name:   "номер транзакции паспортом не считается",
			text:   "Номер транзакции 4509123456.",
			absent: []pii.Type{pii.PassportNumber, pii.INN},
		},
		{
			name:   "трек-номер паспортом не считается",
			text:   "Трек-номер 1234567890.",
			absent: []pii.Type{pii.PassportNumber, pii.INN},
		},
		{
			name:   "номер заявки формой серии и номера паспортом не считается",
			text:   "Номер заявки 4509 123456.",
			absent: []pii.Type{pii.PassportNumber},
		},
		{
			name:   "заявка со знаком номера паспортом не считается",
			text:   "Заявка № 4509123456 одобрена.",
			absent: []pii.Type{pii.PassportNumber, pii.INN},
		},
		{
			name:   "номер заявки с верной суммой ИНН ИНН не считается",
			text:   "номер заявки 9161234567",
			absent: []pii.Type{pii.INN, pii.PassportNumber},
		},
		{
			name: "паспорт, указанный в заявке, остаётся паспортом",
			text: "Паспорт, указанный в заявке: 4509 123456",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},
		{
			name: "номер паспорта остаётся паспортом",
			text: "номер паспорта 4509 123456",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},

		// T-64, строки 1–2: сокращения «пасп.», «сер.», «ном.».
		{
			name: "сокращение пасп. с серией и номером",
			text: "Клиент Иванов И.И., пасп. 4509 123456, просит выписку.",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},
		{
			name: "сокращение пасп без точки",
			text: "пасп 4512 889901",
			want: []digitsWant{{pii.PassportNumber, "4512 889901", Strong}},
		},
		{
			name: "сокращение пасп. и РФ перед номером",
			text: "Данные: пасп. РФ 4509 123456.",
			want: []digitsWant{{pii.PassportNumber, dfxPassport, Strong}},
		},
		{
			name: "сокращение пасп. с серией парами и знаком номера",
			text: "пасп. 45 12 № 889901",
			want: []digitsWant{
				{pii.PassportNumber, "45 12", Strong},
				{pii.PassportNumber, "889901", Strong},
			},
		},
		{
			name: "сокращения сер. и ном. дают два спана без служебных слов",
			text: "сер. 4618 ном. 507329",
			want: []digitsWant{
				{pii.PassportNumber, "4618", Strong},
				{pii.PassportNumber, "507329", Strong},
			},
		},
		{
			name: "полное серия и сокращение ном.",
			text: "серия 4618 ном. 507329",
			want: []digitsWant{
				{pii.PassportNumber, "4618", Strong},
				{pii.PassportNumber, "507329", Strong},
			},
		},
		{
			name: "сер. и ном. перед слитной записью",
			text: "сер. и ном. 4618 507329",
			want: []digitsWant{{pii.PassportNumber, "4618 507329", Strong}},
		},
		{
			name:   "слово на сер- маркером серии не является",
			text:   "сервис 4618 номинал 507329",
			absent: []pii.Type{pii.PassportNumber, pii.DriverLicense},
		},

		// T-64, строки 3–5: невидимые и типографские разделители групп.
		// Карта 4276 0198 7654 3215 и ИНН 502411835606 синтетические, Лун и
		// контрольная сумма верны.
		{
			name: "карта через ZWSP",
			text: "карта 4276\u200b0198\u200b7654\u200b3215",
			want: []digitsWant{{pii.CardNumber, "4276\u200b0198\u200b7654\u200b3215", Certain}},
		},
		{
			name: "карта через ZWJ",
			text: "карта 4276\u200d0198\u200d7654\u200d3215",
			want: []digitsWant{{pii.CardNumber, "4276\u200d0198\u200d7654\u200d3215", Certain}},
		},
		{
			name: "карта через WORD JOINER",
			text: "карта 4276\u20600198\u20607654\u20603215",
			want: []digitsWant{{pii.CardNumber, "4276\u20600198\u20607654\u20603215", Certain}},
		},
		{
			name: "карта через мягкий перенос",
			text: "карта 4276\u00ad0198\u00ad7654\u00ad3215",
			want: []digitsWant{{pii.CardNumber, "4276\u00ad0198\u00ad7654\u00ad3215", Certain}},
		},
		{
			name: "карта через цифровой пробел",
			text: "карта 4276\u20070198\u20077654\u20073215",
			want: []digitsWant{{pii.CardNumber, "4276\u20070198\u20077654\u20073215", Certain}},
		},
		{
			name: "карта через BOM и пробел",
			text: "карта 4276\ufeff 0198 7654 3215",
			want: []digitsWant{{pii.CardNumber, "4276\ufeff 0198 7654 3215", Certain}},
		},
		{
			name: "ИНН через ZWSP",
			text: "ИНН 5024\u200b1183\u200b5606",
			want: []digitsWant{{pii.INN, "5024\u200b1183\u200b5606", Certain}},
		},
		{
			name: "ИНН через цифровой пробел",
			text: "ИНН 5024\u20071183\u20075606",
			want: []digitsWant{{pii.INN, "5024\u20071183\u20075606", Certain}},
		},
		{
			name: "телефон через WORD JOINER",
			text: "тел. +7\u2060926\u2060407\u206018\u206035",
			want: []digitsWant{{pii.Phone, "+7\u2060926\u2060407\u206018\u206035", Strong}},
		},
		{
			name: "телефон через мягкий перенос",
			text: "тел. +7\u00ad926\u00ad407\u00ad18\u00ad35",
			want: []digitsWant{{pii.Phone, "+7\u00ad926\u00ad407\u00ad18\u00ad35", Strong}},
		},
		{
			name: "невидимый символ у дефиса не рвёт номер",
			text: "тел. +7 916 123\u200b-45-67",
			want: []digitsWant{{pii.Phone, "+7 916 123\u200b-45-67", Strong}},
		},
		{
			name: "невидимый символ в маркере CVV2 не склеивает цифру со значением",
			text: "CVV\u200b2 417",
			want: []digitsWant{{pii.CVV, "417", Strong}},
		},

		// T-64, строки 4–5: точка и косая — только для карты с Луном, ИНН с
		// суммой и телефона с признаком.
		{
			name: "карта через точку с верным Луном",
			text: "карта 4276.0198.7654.3215",
			want: []digitsWant{{pii.CardNumber, "4276.0198.7654.3215", Certain}},
		},
		{
			name: "карта через косую с верным Луном",
			text: "карта 4276/0198/7654/3215",
			want: []digitsWant{{pii.CardNumber, "4276/0198/7654/3215", Certain}},
		},
		{
			name:   "карта через точку с неверным Луном не заводится даже при маркере",
			text:   "карта 4276.0198.7654.3216",
			absent: []pii.Type{pii.CardNumber},
		},
		{
			name:   "карта через косую с неверным Луном не заводится",
			text:   "карта 4276/0198/7654/3216",
			absent: []pii.Type{pii.CardNumber},
		},
		{
			name: "ИНН через точку с верной суммой",
			text: "ИНН 5024.1183.5606",
			want: []digitsWant{{pii.INN, "5024.1183.5606", Certain}},
		},
		{
			name: "ИНН через косую с верной суммой",
			text: "ИНН 5024/1183/5606",
			want: []digitsWant{{pii.INN, "5024/1183/5606", Certain}},
		},
		{
			name:   "ИНН через точку с неверной суммой не заводится",
			text:   "ИНН 5024.1183.5607",
			absent: []pii.Type{pii.INN},
		},
		{
			name:   "ИНН через косую с неверной суммой не заводится",
			text:   "ИНН 5024/1183/5607",
			absent: []pii.Type{pii.INN},
		},
		{
			name: "телефон через косую с плюсом",
			text: "тел. +7/926/407/18/35",
			want: []digitsWant{{pii.Phone, "+7/926/407/18/35", Strong}},
		},
		{
			name: "мобильный через косую без маркера",
			text: "8/926/407/18/35",
			want: []digitsWant{{pii.Phone, "8/926/407/18/35", Strong}},
		},
		{
			name:   "городской через косую без маркера и без плюса телефоном не считается",
			text:   "7/495/407/18/35",
			absent: []pii.Type{pii.Phone},
		},
		{
			name:   "бесплатная линия через косую телефоном клиента не является",
			text:   "тел. 8/800/555/35/35",
			absent: []pii.Type{pii.Phone},
		},
		{
			name:   "дата через точку",
			text:   "Дата 12.05.2024, клиент доволен",
			absent: []pii.Type{pii.CardNumber, pii.Phone, pii.INN, pii.PassportNumber},
		},
		{
			name:   "дата через косую",
			text:   "Дата 12/05/2024, клиент доволен",
			absent: []pii.Type{pii.CardNumber, pii.Phone, pii.INN, pii.PassportNumber},
		},
		{
			name:   "сумма через точку",
			text:   "сумма 1.500.000 руб.",
			absent: []pii.Type{pii.CardNumber, pii.Phone, pii.INN},
		},
		{
			name:   "дробь",
			text:   "доля 1/2 и 3/4",
			absent: []pii.Type{pii.CardNumber, pii.Phone, pii.INN, pii.PassportNumber, pii.CVV, pii.PIN},
		},
		{
			name:   "номер договора через косую и дефис",
			text:   "договор 12/345-67 от клиента",
			absent: []pii.Type{pii.CardNumber, pii.Phone, pii.INN, pii.PassportNumber},
		},
		{
			name:   "номер договора через косую рядом с маркером телефона",
			text:   "тел. по договору 12/345-67",
			absent: []pii.Type{pii.CardNumber, pii.Phone},
		},
		{
			name:   "учебный год через косую",
			text:   "в 2024/2025 учебном году",
			absent: []pii.Type{pii.CardNumber, pii.Phone, pii.INN, pii.PassportNumber, pii.PIN},
		},
		{
			name: "серия и номер через косую остаются серией и номером",
			text: "Серия/номер: 4509/123456.",
			want: []digitsWant{
				{pii.PassportNumber, "4509", Strong},
				{pii.PassportNumber, "123456", Strong},
			},
		},

		// T-64, строка 6: «call me at», «reach me at».
		{
			name: "английское me at перед номером без кода страны",
			text: "Reach me at 495 123 45 67 after six.",
			want: []digitsWant{{pii.Phone, "495 123 45 67", Strong}},
		},
		{
			name: "английское me at перед местным номером",
			text: "call me at 123-45-67",
			want: []digitsWant{{pii.Phone, "123-45-67", Strong}},
		},
		{
			name:   "одно at маркером телефона не является",
			text:   "Meeting at 495 123 45 67 is cancelled",
			absent: []pii.Type{pii.Phone},
		},

		// T-59, соседние формы из N10: Amex и ИНН группами.
		{
			name: "Amex группами 4-6-5",
			text: "Amex 3782 822463 10005",
			want: []digitsWant{{pii.CardNumber, "3782 822463 10005", Certain}},
		},
		{
			name: "ИНН группами по четыре",
			text: "ИНН 5001 0073 2259",
			want: []digitsWant{{pii.INN, "5001 0073 2259", Certain}},
		},
		{
			name: "ИНН парами через пробел",
			text: "ИНН: 50 01 00 73 22 59",
			want: []digitsWant{{pii.INN, "50 01 00 73 22 59", Certain}},
		},
		{
			name: "ИНН через дефисы с неверной суммой держится на маркере",
			text: "ИНН 5001-0073-2250",
			want: []digitsWant{{pii.INN, "5001-0073-2250", Strong}},
		},
		{
			name:   "двенадцать цифр группами без маркера ИНН не являются",
			text:   "итого 5001 0073 2259 шт",
			absent: []pii.Type{pii.INN},
		},

		// T-59, строка 5: ИНН организации.
		{
			name:   "ИНН банка",
			text:   "ИНН банка 7710564237",
			absent: []pii.Type{pii.INN, pii.PassportNumber},
		},
		{
			name:   "ИНН организации",
			text:   "ИНН организации 7710564237",
			absent: []pii.Type{pii.INN, pii.PassportNumber},
		},
		{
			name:   "ИНН работодателя с формой собственности",
			text:   "ИНН работодателя ООО «Ромашка» 7710564237.",
			absent: []pii.Type{pii.INN, pii.PassportNumber},
		},
		{
			name: "десятизначный ИНН без слова организации маскируется",
			text: "Клиент Иванов Иван Иванович, ИНН 7710564237",
			want: []digitsWant{{pii.INN, dfxOrgINN, Certain}},
		},
		{
			name: "двенадцатизначный ИНН рядом с банком маскируется",
			text: "ИНН сотрудника банка 500100732259",
			want: []digitsWant{{pii.INN, dfxPersonINN, Certain}},
		},
		{
			// Число проходит и контрольную сумму ИНН: правило организации
			// его не снимает, потому что рядом маркер паспорта.
			name: "паспорт рядом со словом банк остаётся паспортом",
			text: "работает в банке, паспорт 7710564237",
			want: []digitsWant{{pii.PassportNumber, dfxOrgINN, Strong}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkDigitsCandidates(t, c.text, c.want, c.absent) })
	}
}

// checkDigitsCandidates прогоняет цифровой сканер по тексту и проверяет, что
// все кандидаты want найдены, а кандидатов типов absent нет.
func checkDigitsCandidates(t *testing.T, text string, want []digitsWant, absent []pii.Type) {
	t.Helper()
	spans := scanDigitsText(t, text)
	for _, w := range want {
		if !hasDigitsSpan(text, spans, w) {
			t.Errorf("не найден кандидат %s %q с уверенностью %s\nнайдено: %s",
				w.typ, w.text, w.conf, formatDigitsSpans(text, spans))
		}
	}
	for _, s := range spans {
		if slices.Contains(absent, s.Type) {
			t.Errorf("лишний кандидат %s %q (%s, правило %s)",
				s.Type, text[s.Start:s.End], s.Conf, s.Rule)
		}
	}
}

// TestScanDigitsByteOffsets закрепляет требование контракта: смещения спанов
// считаются в байтах, а кириллическая буква занимает два байта.
func TestScanDigitsByteOffsets(t *testing.T) {
	const text = "Паспорт 4509 123456"
	spans := scanDigitsText(t, text)
	var got *Span
	for i := range spans {
		if spans[i].Type == pii.PassportNumber {
			got = &spans[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("паспорт не найден: %s", formatDigitsSpans(text, spans))
	}
	// «Паспорт» — семь кириллических букв, то есть 14 байт, плюс пробел.
	const wantStart, wantEnd = 15, 26
	if int(got.Start) != wantStart || int(got.End) != wantEnd {
		t.Fatalf("спан = [%d, %d), ожидалось [%d, %d)", got.Start, got.End, wantStart, wantEnd)
	}
	if text[got.Start:got.End] != dfxPassport {
		t.Fatalf("текст спана = %q", text[got.Start:got.End])
	}
}

// TestScanDigitsCVV2DigitStaysMarker — «2» в «CVV2» принадлежит маркеру: ни
// один кандидат не накрывает её (T-59, строка 1). До правки «2 582» рядом с
// «ПИН» давало маску «CVV[ПИН_1]».
func TestScanDigitsCVV2DigitStaysMarker(t *testing.T) {
	for _, text := range []string{
		"Карта 2200 6639 2332 1466, CVV2 582, ПИН 7310.",
		"cvv2 417",
		"CVV2/CVC2: 417",
		"код CVV2 417",
	} {
		t.Run(text, func(t *testing.T) {
			// Цифра маркера — первая «2» после буквы «V»/«C» маркера.
			marker := strings.Index(strings.ToLower(text), "v2")
			if marker < 0 {
				marker = strings.Index(strings.ToLower(text), "c2")
			}
			digit := int32(marker + 1)
			for _, s := range scanDigitsText(t, text) {
				if s.Start <= digit && digit < s.End {
					t.Errorf("цифра маркера попала в кандидата %s %q", s.Type, text[s.Start:s.End])
				}
			}
		})
	}
}

// TestScanDigitsRecordNextToPassport — номер заявки снимается, а паспорт в
// том же предложении остаётся (T-59, строка 4): маркер заявки действует
// только на своё число.
func TestScanDigitsRecordNextToPassport(t *testing.T) {
	for _, text := range []string{
		"паспорт 4509 123456, номер заявки 1234567890",
		"Номер заявки 1234567890, паспорт 4509 123456",
	} {
		t.Run(text, func(t *testing.T) {
			spans := scanDigitsText(t, text)
			if !hasDigitsSpan(text, spans, digitsWant{pii.PassportNumber, dfxPassport, Strong}) {
				t.Errorf("паспорт не найден: %s", formatDigitsSpans(text, spans))
			}
			record := strings.Index(text, "1234567890")
			for _, s := range spans {
				if int(s.Start) <= record && record < int(s.End) {
					t.Errorf("номер заявки стал кандидатом %s (%s)", s.Type, s.Rule)
				}
			}
		})
	}
}

// TestDetectOrgRequisites — ИНН и ОГРН организации не маскируются и на уровне
// движка: подъём по кластеру и соседние ПД их не возвращают (T-59, строка 5).
func TestDetectOrgRequisites(t *testing.T) {
	cases := []struct {
		name string
		text string
		// keep — фрагменты, которые не должен накрыть ни один спан.
		keep []string
		// want — типы, которые обязаны остаться в тексте.
		want []pii.Type
	}{
		{
			name: "ИНН, ОГРН и БИК банка",
			text: "ИНН банка 7710564237, ОГРН 1027700132195, БИК 044525593.",
			keep: []string{dfxOrgINN, "1027700132195", "044525593"},
		},
		{
			name: "ИНН работодателя рядом с ФИО клиента",
			text: "Клиент Иванов Иван Иванович, ИНН работодателя 7710564237.",
			keep: []string{dfxOrgINN},
			want: []pii.Type{pii.FullName},
		},
		{
			name: "ИНН клиента в том же предложении, что организация",
			text: "ИНН организации 7710564237, ИНН клиента 500100732259.",
			keep: []string{dfxOrgINN},
			want: []pii.Type{pii.INN},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spans := docsDetect(t, c.text)
			for _, k := range c.keep {
				checkDigitsKept(t, c.text, spans, k)
			}
			for _, w := range c.want {
				if _, ok := docsSpanOf(spans, w); !ok {
					t.Errorf("тип %s не найден ровно один", w)
				}
			}
		})
	}
}

// checkDigitsKept проверяет, что ни один спан не накрывает фрагмент keep.
func checkDigitsKept(t *testing.T, text string, spans []Span, keep string) {
	t.Helper()
	at := strings.Index(text, keep)
	for _, s := range spans {
		if int(s.Start) < at+len(keep) && int(s.End) > at {
			t.Errorf("реквизит организации %q замаскирован как %s (%s)", keep, s.Type, s.Rule)
		}
	}
}

// TestScanDigitsNoAllocs закрепляет требование контракта: Scan не аллоцирует.
// Накопитель кандидатов переиспользуется — так же, как в рабочем конвейере.
func TestScanDigitsNoAllocs(t *testing.T) {
	doc := lex.Tokenize(digitsBenchText(), nil)
	dicts := digitsTestDicts(t)
	var (
		s    digitsScanner
		cand Candidates
	)
	if n := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}); n != 0 {
		t.Fatalf(msgScanAllocs, n)
	}
}

func BenchmarkScanDigits(b *testing.B) {
	text := digitsBenchText()
	doc := lex.Tokenize(text, nil)
	dicts, err := dict.Load()
	if err != nil {
		b.Fatalf(msgDictLoad, err)
	}
	var (
		s    digitsScanner
		cand Candidates
	)
	// Прогрев: ёмкость накопителя набирается один раз, как и в пуле рабочих
	// областей сервиса.
	s.Scan(doc, dicts, &cand)

	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}
}

// digitsBenchText собирает синтетический текст примерно на 4 КБ со всеми
// разбираемыми формами и достаточным числом посторонних чисел.
func digitsBenchText() string {
	const block = "Клиент обратился в отделение: паспорт серия 4509 номер 123456, " +
		"код подразделения 770-053, ИНН 500100732259, телефон +7 916 123-45-67. " +
		"Карта 2200 7001 2345 6781, cvv 123, пин-код 1234, второй номер 8(916)1234567. " +
		"Водительское удостоверение 7723 456789 выдано в 2019 году, сумма 15000 рублей, " +
		"договор 12-45 от 03.07.2021, справочная линия 8-800-555-35-35 работает круглосуточно. " +
		"CVV2 417, код подр. 500-001, мобильный (916) 482-17-35, +375 29 123–45–67, " +
		"номер заявки 1234567890, ИНН банка 7710564237.\n"
	return strings.Repeat(block, 4096/len(block)+1)
}

var (
	digitsDictsOnce sync.Once
	digitsDictsSet  *dict.Set
	digitsDictsErr  error
)

// digitsTestDicts загружает встроенные справочники один раз на пакет.
func digitsTestDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	digitsDictsOnce.Do(func() { digitsDictsSet, digitsDictsErr = dict.Load() })
	if digitsDictsErr != nil {
		tb.Fatalf(msgDictLoad, digitsDictsErr)
	}
	return digitsDictsSet
}

// scanDigitsText прогоняет сканер по тексту и возвращает кандидатов.
func scanDigitsText(tb testing.TB, text string) []Span {
	tb.Helper()
	doc := lex.Tokenize(text, nil)
	var out Candidates
	digitsScanner{}.Scan(doc, digitsTestDicts(tb), &out)
	return out.Spans
}

func hasDigitsSpan(text string, spans []Span, w digitsWant) bool {
	for _, s := range spans {
		if s.Type == w.typ && s.Conf == w.conf && text[s.Start:s.End] == w.text {
			return true
		}
	}
	return false
}

func formatDigitsSpans(text string, spans []Span) string {
	if len(spans) == 0 {
		return "(пусто)"
	}
	var b strings.Builder
	for i, s := range spans {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(s.Type.String())
		b.WriteString(" ")
		b.WriteString(digitsQuote(text[s.Start:s.End]))
		b.WriteString(" ")
		b.WriteString(s.Conf.String())
		b.WriteString(" ")
		b.WriteString(s.Rule)
	}
	return b.String()
}

func digitsQuote(s string) string { return "«" + s + "»" }

// digitsMasked прогоняет полный конвейер и заменяет каждый спан основой
// плейсхолдера в скобках, без номера: «пасп. [ПАСПОРТ]». Так ожидание в тесте
// читается как колонка «Ожидается» таблицы задачи.
func digitsMasked(tb testing.TB, text string) string {
	tb.Helper()
	spans := docsDetect(tb, text)
	var b strings.Builder
	prev := 0
	for _, s := range spans {
		b.WriteString(text[prev:s.Start])
		b.WriteString("[" + s.Type.Placeholder() + "]")
		prev = int(s.End)
	}
	b.WriteString(text[prev:])
	return b.String()
}

// TestDetectDigitsAbbrevSeparators — сокращения маркеров («пасп.», «сер.»,
// «ном.»), невидимые и типографские разделители групп и «me at» через весь
// конвейер (таблица T-64): сканеры, контр-правила, подъём по кластеру и
// отбор. Ожидание — маска целиком, чтобы ни чужой тип на тех же цифрах, ни
// служебное слово в спане не прошли молча.
func TestDetectDigitsAbbrevSeparators(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		// Строка 1: Б4-2.
		{"пасп. в обращении", "Клиент Иванов И.И., пасп. 4509 123456, просит выписку.",
			"Клиент [ФИО], пасп. [ПАСПОРТ], просит выписку."},
		{"пасп. одной строкой", "пасп. 4512 889901", "пасп. [ПАСПОРТ]"},
		// «РФ» в названии документа — не гражданство (T-65, строка 11): ни
		// после полного «паспорт», ни после «пасп.».
		{"паспорт РФ как контроль", "Данные: паспорт РФ 4509 123456.", "Данные: паспорт РФ [ПАСПОРТ]."},
		{"пасп. РФ", "Данные: пасп. РФ 4509 123456.", "Данные: пасп. РФ [ПАСПОРТ]."},
		{"пасп. серия парами", "пасп. 45 12 № 889901", "пасп. [ПАСПОРТ] № [ПАСПОРТ]"},
		{"пасп. с датой выдачи", "пасп. 4509 123456 выдан 01.02.2015",
			"пасп. [ПАСПОРТ] выдан [ДАТА_ВЫДАЧИ]"},
		{"пасп. серия и номер словами", "пасп. серия 45 12 номер 889901",
			"пасп. серия [ПАСПОРТ] номер [ПАСПОРТ]"},
		// Строка 2: P4-7.
		{"сер. и ном.", "сер. 4618 ном. 507329", "сер. [ПАСПОРТ] ном. [ПАСПОРТ]"},
		{"серия и ном.", "серия 4618 ном. 507329", "серия [ПАСПОРТ] ном. [ПАСПОРТ]"},
		// Строки 3–5: P4-6.
		{"карта через ZWSP", "карта 4276\u200b0198\u200b7654\u200b3215", dfxCardMasked},
		{"карта через цифровой пробел", "карта 4276\u20070198\u20077654\u20073215", dfxCardMasked},
		{"карта через точку", "карта 4276.0198.7654.3215", dfxCardMasked},
		{"карта через косую", "карта 4276/0198/7654/3215", dfxCardMasked},
		{"ИНН через ZWJ", "ИНН 5024\u200d1183\u200d5606", "ИНН [ИНН]"},
		{"ИНН через косую", "ИНН 5024/1183/5606", "ИНН [ИНН]"},
		{"телефон через мягкий перенос", "тел. +7\u00ad926\u00ad407\u00ad18\u00ad35", "тел. [ТЕЛЕФОН]"},
		{"телефон через косую", "тел. +7/926/407/18/35", "тел. [ТЕЛЕФОН]"},
		// Ложные срабатывания: дата, сумма, дробь и номер договора через
		// точку и косую остаются как есть.
		{"договор, дата и сумма", "Договор 12/345-67 от 12/05/2024, сумма 1.500.000 руб., доля 1/2.",
			"Договор 12/345-67 от 12/05/2024, сумма 1.500.000 руб., доля 1/2."},
		// Строка 6: Б4-15.
		{"reach me at", "Reach me at +7 916 700-80-91.", "Reach me at [ТЕЛЕФОН]."},
		{"me at без кода страны", "Text me at 916 700 80 91, please.", "Text me at [ТЕЛЕФОН], please."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := digitsMasked(t, c.text); got != c.want {
				t.Errorf(msgMaskWant, got, c.want)
			}
		})
	}
}

// TestDetectPassportAbbrevWithAuthority — «пасп.» с органом выдачи: номер
// паспорта обязан уйти под маску паспорта, а не адреса. До правки шесть цифр
// номера без маркера разбирались как почтовый индекс (Б4-2, пятая фраза).
func TestDetectPassportAbbrevWithAuthority(t *testing.T) {
	const text = "пасп. 45 12 № 889901 выдан 01.02.2015 отделом УФМС России по Республике Татарстан"
	spans := docsDetect(t, text)
	for _, v := range []string{"45 12", "889901"} {
		at := int32(strings.Index(text, v))
		s, ok := spanAt(spans, at)
		if !ok || s.Type != pii.PassportNumber || text[s.Start:s.End] != v {
			t.Errorf("%q: спан %+v, найден %v; ожидался паспорт ровно по значению", v, s, ok)
		}
	}
}
