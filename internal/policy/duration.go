package policy

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so YAML can use the strings humans
// actually write (15m, 1h). std yaml.v3 will not do this for you.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("policy ttl: %w", err)
	}
	if parsed <= 0 {
		return fmt.Errorf("policy ttl must be > 0, got %s", s)
	}
	*d = Duration(parsed)
	return nil
}
