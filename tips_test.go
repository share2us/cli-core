package clicore

import (
	"strings"
	"testing"
)

func TestTipsRenderCommandName(t *testing.T) {
	tips := Tips("s2u")
	if len(tips) == 0 {
		t.Fatal("expected tips")
	}
	for _, tip := range tips {
		if strings.Contains(tip, "%s") {
			t.Fatalf("tip has unrendered %%s: %q", tip)
		}
		if strings.TrimSpace(tip) == "" || strings.Contains(tip, "\n") {
			t.Fatalf("tip must be a non-empty single line: %q", tip)
		}
	}
}

func TestRandomTipIsAMember(t *testing.T) {
	set := map[string]bool{}
	for _, tip := range Tips("share2us") {
		set[tip] = true
	}
	for i := 0; i < 50; i++ {
		got := RandomTip("share2us")
		if !set[got] {
			t.Fatalf("RandomTip returned a non-member: %q", got)
		}
	}
}
