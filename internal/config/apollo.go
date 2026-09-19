package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// ApolloSnapshot is the reviewed export of one Apollo release
// (packages/profile-schemas/apollo-snapshot.schema.json): the app, cluster
// and namespace it came from, its release key, when it was fetched and
// until when it may be used, and the non-secret configurations as koanf
// paths. During an Apollo outage only a validated, unexpired snapshot is
// usable; nothing is started from an unvalidated one (DD-09 §4).
type ApolloSnapshot struct {
	SchemaVersion  int               `json:"schemaVersion"`
	AppID          string            `json:"appId"`
	Cluster        string            `json:"cluster"`
	Namespace      string            `json:"namespace"`
	ReleaseKey     string            `json:"releaseKey"`
	FetchedAt      string            `json:"fetchedAt"`
	ExpiresAt      string            `json:"expiresAt"`
	Configurations map[string]string `json:"configurations"`
}

var (
	releaseKeyPattern = regexp.MustCompile(`^[0-9]{14}-[0-9a-f]{12}$`)
	configKeyPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	// Keys that name a secret or a placement never come from Apollo
	// (packages/profile-schemas/apollo-snapshot.schema.json).
	secretKeyPattern = regexp.MustCompile(`(^|\.)(url|url_file|address|token|secret|password|access_key_id|secret_access_key|snapshot_file)$`)
)

// LoadApolloSnapshot reads and validates a snapshot for the given app at the
// given instant; any deviation rejects it.
func LoadApolloSnapshot(path, appID string, now time.Time) (ApolloSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: %w", err)
	}
	return ParseApolloSnapshot(raw, appID, now)
}

// ParseApolloSnapshot is LoadApolloSnapshot on bytes (tests, fixtures).
func ParseApolloSnapshot(raw []byte, appID string, now time.Time) (ApolloSnapshot, error) {
	var s ApolloSnapshot
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: %w", err)
	}
	if dec.More() {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: trailing content")
	}
	switch {
	case s.SchemaVersion != 1:
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: schemaVersion %d is not 1", s.SchemaVersion)
	case s.AppID != appID:
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: appId %q is not this service (%s)", s.AppID, appID)
	case s.Cluster == "" || s.Namespace == "":
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: cluster and namespace are required")
	case !releaseKeyPattern.MatchString(s.ReleaseKey):
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: releaseKey %q is not an Apollo release key", s.ReleaseKey)
	case s.Configurations == nil:
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: configurations are required")
	}
	fetched, err := time.Parse(time.RFC3339, s.FetchedAt)
	if err != nil {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: fetchedAt: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: expiresAt: %w", err)
	}
	if !expires.After(fetched) {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: expiresAt must follow fetchedAt")
	}
	if !expires.After(now) {
		return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: expired at %s; an expired snapshot never starts a generation", s.ExpiresAt)
	}
	for key := range s.Configurations {
		if !configKeyPattern.MatchString(key) {
			return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: %q is not a configuration key", key)
		}
		if secretKeyPattern.MatchString(key) {
			return ApolloSnapshot{}, fmt.Errorf("apollo snapshot: %q names a secret or a placement and never comes from Apollo", key)
		}
	}
	return s, nil
}
