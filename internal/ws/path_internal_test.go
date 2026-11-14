package ws

import "testing"

func TestIsShortNameAlias(t *testing.T) {
	yes := []string{"GIT~1", "git~12", "PROGRA~2.TXT", "DOCUME~1"}
	for _, name := range yes {
		if !isShortNameAlias(name) {
			t.Errorf("isShortNameAlias(%q) = false, want true", name)
		}
	}
	no := []string{"", "~", "foo~", "foo~bar", "foo~1~2x", "file.txt~", "tilde~"}
	for _, name := range no {
		if isShortNameAlias(name) {
			t.Errorf("isShortNameAlias(%q) = true, want false", name)
		}
	}
}
