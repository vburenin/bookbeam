package media

import (
	"testing"
)

// win1251 encodes s (Cyrillic + ASCII only) as Windows-1251 bytes.
func win1251(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	for _, r := range s {
		if r < 0x80 {
			out = append(out, byte(r))
			continue
		}
		found := false
		for i, c := range cp1251 {
			if c == r {
				out = append(out, byte(0x80+i))
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%q is not in Windows-1251", r)
		}
	}
	return out
}

func TestLegacyTextCyrillic(t *testing.T) {
	for _, s := range []string{
		"Мастер и Маргарита",
		"Булгаков М.А.",
		"Глава 01. Никогда не разговаривайте с неизвестными",
		"Я",             // single letter, no ASCII letters
		"Ёжик в тумане", // Ё lives outside А–я
		"Кобзар. Їжак, Ґанок, Євшан-зілля, Іван",  // Ukrainian letters
		"Гарри Поттер и Философский камень (CD1)", // mixed with Latin
		"Стругацкие — Пикник на обочине",          // ASCII punctuation around words
		"Сергей Чонишвили",
	} {
		if got := legacyText(win1251(t, s)); got != s {
			t.Errorf("legacyText(cp1251 %q) = %q", s, got)
		}
	}
}

func TestLegacyTextWestern(t *testing.T) {
	for in, want := range map[string]string{
		"caf\xe9":                          "café",
		"M\xfcller":                        "Müller",
		"Informa\xe7\xe3o":                 "Informação",
		"Les Mis\xe9rables":                "Les Misérables",
		"\xc0 la recherche du temps perdu": "À la recherche du temps perdu",
		"\xc7a":                            "Ça",
		"Stra\xdfe":                        "Straße",
		"Don\x92t Panic \x96 Part 2":       "Don’t Panic – Part 2", // Windows-1252 punctuation
		"Caf\xe9 \xe0 Paris":               "Café à Paris",
		"Copyright \xa9 1999":              "Copyright © 1999",
		"Plain ASCII":                      "Plain ASCII",
		"Мастер (already UTF-8)":           "Мастер (already UTF-8)",
	} {
		if got := legacyText([]byte(in)); got != want {
			t.Errorf("legacyText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeName(t *testing.T) {
	if got := DecodeName("Мастер и Маргарита"); got != "Мастер и Маргарита" {
		t.Errorf("valid UTF-8 changed: %q", got)
	}
	if got := DecodeName(string(win1251(t, "Аудиокниги/Пикник"))); got != "Аудиокниги/Пикник" {
		t.Errorf("DecodeName(cp1251) = %q", got)
	}
}

// Russian rips: ID3v2.3 frames labelled ISO-8859-1 (and sometimes UTF-8)
// that really hold Windows-1251, plus a Windows-1251 ID3v1 tag.
func TestID3Cyrillic(t *testing.T) {
	frames := cat(
		id3Frame23("TIT2", 0, cat([]byte{0}, win1251(t, "Глава 1"))),
		id3Frame23("TALB", 0, cat([]byte{3}, win1251(t, "Мастер и Маргарита"))), // mislabelled UTF-8
		id3Frame23("TPE1", 0, cat([]byte{0}, win1251(t, "Михаил Булгаков"))),
		id3Frame23("COMM", 0, commFrame(0, "rus", "", string(win1251(t, "Читает Олег Басилашвили")))),
	)
	v1 := make([]byte, 128)
	copy(v1, "TAG")
	copy(v1[63:], win1251(t, "Неверный альбом"))
	copy(v1[93:], "1966")
	info := mustProbe(t, cat(id3TagBytes(3, 0, frames), mpegStream(10, 128), v1), "", Options{})
	expectFields(t, info, Info{
		Title: "Глава 1", Album: "Мастер и Маргарита", Artist: "Михаил Булгаков",
		Comment: "Читает Олег Басилашвили", Year: "1966",
	})

	// ID3v1 only.
	v1only := make([]byte, 128)
	copy(v1only, "TAG")
	copy(v1only[3:], win1251(t, "Пролог"))
	copy(v1only[33:], win1251(t, "Стругацкие"))
	info = mustProbe(t, cat(mpegStream(10, 128), v1only), "", Options{})
	expectFields(t, info, Info{Title: "Пролог", Artist: "Стругацкие"})
}
