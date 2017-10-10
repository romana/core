package enforcer

import (
	"context"
	"time"

	"github.com/romana/ipset"
)

// updateIpsets is a flush/rebuild implementation of ipset update
// it will wipe all sets in a system and populate new ones.
// TODO for Stas this monopolizes ipsets
// and also pollutes with sets which never deleted.
// Need cleaner implementation
func updateIpsets(ctx context.Context, sets *ipset.Ipset) error {
	_, err := ipset.Flush(nil)
	if err != nil {
		return err
	}

	// attempt to cleanup unused chains,
	// can err, don't care.
	_, _ = ipset.Destroy(nil)

	ipsetHandle, err := ipset.NewHandle()
	if err != nil {
		return err
	}

	err = ipsetHandle.Start()
	if err != nil {
		return err
	}

	err = ipsetHandle.Create(sets)
	if err != nil {
		return err
	}

	err = ipsetHandle.Add(sets)
	if err != nil {
		return err
	}

	err = ipsetHandle.Quit()
	if err != nil {
		return err
	}

	cTimout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = ipsetHandle.Wait(cTimout)
	if err != nil {
		return err
	}

	return nil

}
