package docpreview

import "testing"

func TestKindFor(t *testing.T) {
	cases := map[string]string{
		"a.docx": "document", "a.DOC": "document", "a.odt": "document", "a.rtf": "document",
		"a.xlsx": "spreadsheet", "a.xls": "spreadsheet", "a.csv": "spreadsheet", "a.ods": "spreadsheet",
		"a.pptx": "presentation", "a.ppt": "presentation", "a.odp": "presentation",
		"a.pdf": "pdf",
		"a.png": "", "a.txt": "", "a.json": "",
	}
	for name, want := range cases {
		if got := KindFor(name); got != want {
			t.Fatalf("KindFor(%q)=%q want %q", name, got, want)
		}
		if Supports(name) != (want != "") {
			t.Fatalf("Supports(%q) mismatch", name)
		}
	}
}

func TestGenerateRejectsUnsupportedAndMissing(t *testing.T) {
	if _, err := Generate(t.Context(), "/no/such/file.png", t.TempDir(), 3); err == nil {
		t.Fatal("missing file must error")
	}
	if _, err := Generate(t.Context(), "/no/such/file.txt", t.TempDir(), 3); err == nil {
		t.Fatal("unsupported file must error before touching deps")
	}
}
