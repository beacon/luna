package dpkg

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

func TestDpkgScanner(t *testing.T) {
	s := &Scanner{}
	t.Log("Start")
	defer t.Log("Done")
	pkgs, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, err := ioutil.TempFile(os.TempDir(), "scanresult-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	if err := enc.Encode(pkgs); err != nil {
		t.Fatal(err)
	}
	t.Log("File saved to:", f.Name())
}
