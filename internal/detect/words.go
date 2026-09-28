package detect

// Слова и основы, которые повторяются в нескольких сканерах пакета: в
// switch по нормализованному слову, в стоп-списках и в проверках префикса.
// Значения — нормализованная форма (нижний регистр, «ё» → «е»), как её отдаёт
// lex.Doc.NormOf. wordHis совпадает с окончанием прилагательного «-его» и
// служит в таблицах окончаний тем же литералом.
const (
	wordNear      = "около"
	wordAbout     = "про"
	wordThis      = "это"
	wordFor       = "для"
	wordWas       = "был"
	wordWasFem    = "была"
	wordNow       = "теперь"
	wordUnder     = "под"
	wordHis       = "его"
	wordYear      = "год"
	wordOfYear    = "года"
	wordBirthStem = "рожд"
	wordBornStem  = "родил"
	wordToday     = "сегодня"
	wordBank      = "банк"
	wordNamed     = "имени"
	wordRegion    = "области"
)
