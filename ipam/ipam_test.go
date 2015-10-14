package ipam

import "testing"

func TestGetAddress(t *testing.T) {
   addr := GetAddress("XYZ")
   t.Errorf("Whatever %s is, it is wrong.", addr)
}