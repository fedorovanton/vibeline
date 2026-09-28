//go:build race

package detect

// raceSlowdown — во сколько раз детектор гонок замедляет сканеры. Сторож
// сложности TestCounterScanLinear отличает линейный проход от квадратичного
// на три порядка, поэтому запас в 10 раз квадратичный цикл не пропускает.
const raceSlowdown = 10
