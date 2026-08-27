package audit

import (
	"encoding/json"
	"fmt"
)

// decodeDetail parses the stored detail column back into a map.
//
// A missing or null detail decodes to an empty map rather than nil, so that
// canonicalJSON produces "{}" — the same bytes that were hashed at write time.
func decodeDetail(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("audit: decoding detail: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}
