package wireguard

import (
	"testing"
)

func TestCheck(t *testing.T) {
	_, err := GetInfo()
	if err != nil {
		t.Log(err)
	}
}
