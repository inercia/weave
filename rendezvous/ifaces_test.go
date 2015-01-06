package rendezvous

import (
	"testing"
)

func TestInterfacesGuess(t *testing.T) {
	var ifaces IfaceNamesList = NewIfaceNamesList()
	eps, err := EndpointsListFromIfaceNamesList(ifaces)
	if err != nil {
		t.Fail()
	}
	if len(eps) == 0 {
		t.Fail()
	}
}
