package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSharedSnapshotFixtures runs the cross-language cases of
// packages/profile-schemas/fixtures.json (found in the parent checkout)
// through this loader's snapshot rules.
func TestSharedSnapshotFixtures(t *testing.T) {
	wd, _ := os.Getwd()
	var path string
	for d := wd; d != filepath.Dir(d); d = filepath.Dir(d) {
		c := filepath.Join(d, "packages", "profile-schemas", "fixtures.json")
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("UNEXECUTED: packages/profile-schemas/fixtures.json not found beside this repository")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Now   string `json:"now"`
		Cases []struct {
			Name     string          `json:"name"`
			Schema   string          `json:"schema"`
			AppID    string          `json:"appId"`
			Valid    bool            `json:"valid"`
			Instance json.RawMessage `json:"instance"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, doc.Now)
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range doc.Cases {
		if c.Schema != "apollo-snapshot" {
			continue
		}
		ran++
		_, err := ParseApolloSnapshot(c.Instance, c.AppID, now)
		if (err == nil) != c.Valid {
			t.Errorf("%s: err=%v want valid=%v", c.Name, err, c.Valid)
		}
	}
	if ran == 0 {
		t.Fatal("no snapshot cases")
	}
}
