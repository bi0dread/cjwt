package opaque

import (
	"encoding/json"
)

// parseJSONField parses a JSON byte array into the target interface
func parseJSONField(data []byte, target interface{}) error {
	if len(data) == 0 {
		return nil
	}

	// Handle null values
	if string(data) == "null" {
		return nil
	}

	return json.Unmarshal(data, target)
}
