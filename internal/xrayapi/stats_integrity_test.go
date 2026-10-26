package xrayapi

import "testing"

func TestTrafficCompletenessFailsClosed(t *testing.T) {
	cases := []struct{ up, down, wantOK bool }{{true, true, true}, {false, false, false}, {false, true, false}, {true, false, false}}
	for _, v := range cases {
		err := validateTrafficCompleteness(v.up, v.down)
		if (err == nil) != v.wantOK {
			t.Fatalf("up=%v down=%v err=%v", v.up, v.down, err)
		}
	}
}
