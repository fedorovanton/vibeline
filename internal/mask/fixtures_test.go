package mask

// Синтетические значения и сообщения, общие для тестов пакета. Вынесены,
// чтобы одно и то же значение не повторялось литералом в каждом файле. Все
// значения вымышленные: имена из встроенного справочника, телефоны
// служебного диапазона, адреса в example.org и example.test.
const (
	fioPetrov       = "Петров Пётр"
	fioPetrovFull   = "Петров Пётр Петрович"
	surnamePetrov   = "Петров"
	surnamePetrova  = "Петрова"
	fioSidorov      = "Сидоров Сидор"
	fioIvanov       = "Иванов Иван"
	mailPetrov      = "petrov@example.test"
	mailUser1       = "user1@example.org"
	phoneSample     = "+7 916 123-45-67"
	phoneSynthFirst = "+7 900 000-00-00"
	birthDateSample = "01.02.1990"
	epochDate       = "01.01.1970"
	fourZeros       = "0000"
	badByte         = "\xff"

	strategySynthetic = "synthetic"
	strategyToken     = "token"
	tokenPrefix       = "{{pii:"

	msgResultWant = "результат %q, ожидалось %q"
	msgResult     = "результат %q"
)
