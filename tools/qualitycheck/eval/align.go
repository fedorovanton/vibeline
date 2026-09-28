package eval

import "unicode/utf8"

// Выравнивание оригинала и ответа сервиса.
//
// Метрика избыточности требует знать, какие байты оригинала не сохранились в
// ответе. Эталонной маски не существует, формат плейсхолдера свободен
// (07-clarifications.md §7.1), поэтому разбирать ответ по известному шаблону
// нельзя — приходится выравнивать две строки.
//
// Выравнивание приблизительное и это принципиально: точного соответствия между
// произвольной маской и оригиналом не существует. Поэтому избыточность —
// вспомогательная метрика; главная, сокрытие значения, от выравнивания не
// зависит вовсе.

const (
	// maxSkip — предел рассинхронизации в токенах. Самое длинное значение
	// корпуса — адрес целиком (около 25 токенов вместе с разделителями);
	// предел взят с запасом.
	maxSkip = 48
	// runLen — сколько подряд равных токенов считается точкой ресинхронизации.
	// Одного мало: случайное совпадение пробела объявило бы совпадение там,
	// где текст дальше расходится.
	runLen = 3
)

// Region — полуинтервал байтов исходного текста, не сохранившийся в ответе.
type Region struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Len — длина области в байтах.
func (r Region) Len() int { return r.End - r.Start }

// token — байтовые границы куска текста.
type token struct{ start, end int }

// tokenize режет текст на чередующиеся серии пробельных и непробельных
// символов. Каждый байт попадает ровно в один токен, поэтому суммарная длина
// несопоставленных токенов — это и есть число изменённых байтов.
func tokenize(s string) []token {
	toks := make([]token, 0, len(s)/4+1)
	i := 0
	for i < len(s) {
		j := i
		if isSpace(s[i]) {
			for j < len(s) && isSpace(s[j]) {
				j++
			}
		} else {
			for j < len(s) && !isSpace(s[j]) {
				j++
			}
		}
		toks = append(toks, token{start: i, end: j})
		i = j
	}
	return toks
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func slice(s string, toks []token) []string {
	out := make([]string, len(toks))
	for i, t := range toks {
		out[i] = s[t.start:t.end]
	}
	return out
}

// MaskedRegions возвращает области оригинала, которых нет в ответе сервиса.
//
// Алгоритм — жадное сопоставление с ограниченным просмотром вперёд: пока
// токены совпадают, идём вместе; на расхождении ищем ближайшую пару смещений,
// после которой совпадают runLen токенов подряд. Ограниченный просмотр выбран
// вместо полного поиска наименьшего редакционного расстояния сознательно:
// корпус содержит записи на 100 000 токенов, а расхождения в них локальны.
func MaskedRegions(original, masked string) []Region {
	if original == masked {
		return nil
	}
	origToks, maskToks := tokenize(original), tokenize(masked)
	a, b := slice(original, origToks), slice(masked, maskToks)

	var regions []Region
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		da, db, ok := resync(a[i:], b[j:])
		if !ok {
			break
		}
		regions = addRegion(regions, original, masked, origToks[i:i+da], maskToks[j:j+db])
		i += da
		j += db
	}
	if i < len(a) {
		// Ресинхронизация не найдена: остаток оригинала считаем изменённым.
		// Это завышает избыточность, но никогда её не занижает — отчёт не
		// должен выглядеть лучше, чем есть.
		regions = addRegion(regions, original, masked, origToks[i:], maskToks[min(j, len(maskToks)):])
	}
	return regions
}

// resync ищет минимальное смещение (da, db), после которого строки снова
// совпадают. Перебор идёт по возрастанию суммы смещений: чем ближе точка
// ресинхронизации, тем меньше байтов будет объявлено изменёнными.
func resync(a, b []string) (int, int, bool) {
	for sum := 1; sum <= 2*maxSkip; sum++ {
		lo := max(sum-maxSkip, 0)
		hi := min(sum, maxSkip)
		for da := lo; da <= hi; da++ {
			db := sum - da
			if da > len(a) || db > len(b) {
				continue
			}
			if matchRun(a[da:], b[db:]) {
				return da, db, true
			}
		}
	}
	return 0, 0, false
}

// matchRun сообщает, совпадают ли следующие runLen токенов. У конца текста
// требуется полное совпадение остатка: иначе последний токен объявлял бы
// ресинхронизацию там, где дальше ничего нет.
func matchRun(a, b []string) bool {
	n := runLen
	if len(a) < n || len(b) < n {
		if len(a) != len(b) {
			return false
		}
		n = len(a)
	}
	for k := 0; k < n; k++ {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

// addRegion добавляет область изменённых байтов, отрезав от неё совпадающие
// края. Отрезать нужно: значение часто стоит вплотную к знаку препинания, и
// без обрезки запятая после паспорта попала бы в избыточное маскирование.
func addRegion(regions []Region, original, masked string, aToks, bToks []token) []Region {
	if len(aToks) == 0 {
		return regions
	}
	aStart, aEnd := aToks[0].start, aToks[len(aToks)-1].end
	bStart, bEnd := 0, 0
	if len(bToks) > 0 {
		bStart, bEnd = bToks[0].start, bToks[len(bToks)-1].end
	}

	as, bs := original[aStart:aEnd], masked[bStart:bEnd]
	p := commonPrefix(as, bs)
	s := commonSuffix(as[p:], bs[p:])
	aStart += p
	aEnd -= s
	if aStart >= aEnd {
		return regions
	}
	return append(regions, Region{Start: aStart, End: aEnd})
}

// commonPrefix возвращает длину общего начала в байтах, выровненную по границе
// руны: байтовое смещение внутри кириллической буквы бессмысленно.
func commonPrefix(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	for i > 0 && !utf8.RuneStart(a[i]) {
		i--
	}
	return i
}

// commonSuffix — то же для общего конца.
func commonSuffix(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	for i > 0 && !utf8.RuneStart(a[len(a)-i]) {
		i--
	}
	return i
}

// uncoveredBytes считает байты областей regions, не попавшие ни в один
// полуинтервал cover. Оба списка отсортированы по возрастанию и внутри себя не
// перекрываются, поэтому хватает одного встречного прохода.
func uncoveredBytes(regions, cover []Region) int {
	total, k := 0, 0
	for _, r := range regions {
		pos := r.Start
		// Интервалы, закончившиеся до начала области, не понадобятся и
		// следующим областям: области идут по возрастанию.
		for k < len(cover) && cover[k].End <= pos {
			k++
		}
		for c := k; c < len(cover) && cover[c].Start < r.End && pos < r.End; c++ {
			if cover[c].Start > pos {
				total += cover[c].Start - pos
			}
			if cover[c].End > pos {
				pos = cover[c].End
			}
		}
		if pos < r.End {
			total += r.End - pos
		}
	}
	return total
}
