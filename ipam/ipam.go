package ipam

import (
  "net"
)

type PaniNetwork struct {
  cidr uint64
}

func GetAddress(tenantName string) net.IP {
   return net.ParseIP("fe80::3636:3bff:fec9:9f1a");
}


