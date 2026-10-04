package store

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/vburenin/bookbeam/server/internal/library"
)

// PatchSettings validates and merges a partial settings object. Either all
// fields apply or none (and an *InputError names the problem).
func (s *Store) PatchSettings(name string, idx *library.Index, patch map[string]json.RawMessage) (Settings, error) {
	var out Settings
	err := s.withUser(name, idx, func(u *user) error {
		next := u.data.Settings
		if err := applySettingsPatch(&next, patch); err != nil {
			return err
		}
		u.data.Settings = next
		out = next
		return s.save(u)
	})
	return out, err
}

func applySettingsPatch(st *Settings, patch map[string]json.RawMessage) error {
	keys := make([]string, 0, len(patch))
	for k := range patch {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic error messages
	for _, k := range keys {
		raw := patch[k]
		var err error
		switch k {
		case "skipBack":
			err = decodeChoice(raw, &st.SkipBack, skipChoices)
		case "skipForward":
			err = decodeChoice(raw, &st.SkipForward, skipChoices)
		case "theme":
			err = decodeChoice(raw, &st.Theme, themeChoices)
		case "autoRewind":
			err = json.Unmarshal(raw, &st.AutoRewind)
		case "defaultSpeed":
			var v float64
			if err = json.Unmarshal(raw, &v); err == nil && !validSpeed(v) {
				err = fmt.Errorf("must be between %v and %v", MinSpeed, MaxSpeed)
			}
			st.DefaultSpeed = v
		default:
			return invalid(fmt.Sprintf("unknown setting %q", k))
		}
		if err != nil {
			return invalid(fmt.Sprintf("invalid %s: %v", k, err))
		}
	}
	return nil
}

// decodeChoice decodes raw into dst, requiring one of the allowed values.
func decodeChoice[T comparable](raw json.RawMessage, dst *T, allowed []T) error {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if !slices.Contains(allowed, v) {
		return fmt.Errorf("must be one of %v", allowed)
	}
	*dst = v
	return nil
}
