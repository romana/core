package agent

import (
	//	"fmt"
	//	"log"
	"net"
	"net/url"
)

const (
	expectedNumberOfFileds = 3
)

// NetIf is a structure that represents
// network interface and it's ip configuration
// together with basic methods operating on this structure.
type NetIf struct {
	name string
	mac  string
	ip   net.IP
}

// ParseNetIf is a method of NetIF that fills new structure with data from HTTP request.
func (i *NetIf) ParseNetIf(r url.Values) error {
	fields := 0
	for key, values := range r {
		switch key {
		case "interface_name":
			i.name = values[0]
			fields++
		case "mac_address":
			i.mac = values[0]
			fields++
		case "ip_address":
			i.ip = net.ParseIP(values[0])
			if i.ip == nil {
				return failedToParseNetif()
			}
			fields++
		default:
			return garbageRequestError(key)
		}
	}
	if fields != expectedNumberOfFileds {
		return requestParseError(fields)
	}
	return nil
}
