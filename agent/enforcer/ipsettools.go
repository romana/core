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

	err := attemptIpsetCleanup(ctx, sets)
	if err != nil {
		return err
	}

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

// attemptIpsetCleanup attempts to destroy every set.
// TODO make it less nuclear.
func attemptIpsetCleanup(ctx context.Context, sets *ipset.Ipset) error {
	iset, _ := ipset.Load(context.Background())
	for _, set := range iset.Sets {
		_, _ = ipset.Destroy(set)
	}

	// flush everything that survived mass destroy.
	_, err := ipset.Flush(nil)

	return err
}
