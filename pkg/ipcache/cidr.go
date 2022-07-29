// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package ipcache

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
)

var (
	// IdentityAllocator is a package-level variable which is used to allocate
	// identities for CIDRs.
	// TODO: plumb an allocator in from callers of these functions vs. having
	// this as a package-level variable.
	IdentityAllocator cache.IdentityAllocator
)

// AllocateCIDRs attempts to allocate identities for a list of CIDRs. If any
// allocation fails, all allocations are rolled back and the error is returned.
// When an identity is freshly allocated for a CIDR, it is added to the
// ipcache if 'newlyAllocatedIdentities' is 'nil', otherwise the newly allocated
// identities are placed in 'newlyAllocatedIdentities' and it is the caller's
// responsibility to upsert them into ipcache by calling UpsertGeneratedIdentities().
//
// Previously used numeric identities for the given prefixes may be passed in as the
// 'oldNIDs' parameter; nil slice must be passed if no previous numeric identities exist.
// Previously used NID is allocated if still available. Non-availability is not an error.
//
// Upon success, the caller must also arrange for the resulting identities to
// be released via a subsequent call to ReleaseCIDRIdentitiesByCIDR().
func AllocateCIDRs(
	prefixes []*net.IPNet, oldNIDs []identity.NumericIdentity, newlyAllocatedIdentities map[string]*identity.Identity,
) ([]*identity.Identity, error) {
	// maintain list of used identities to undo on error
	usedIdentities := make([]*identity.Identity, 0, len(prefixes))

	// Maintain list of newly allocated identities to update ipcache,
	// but upsert them to ipcache only if no map was given by the caller.
	upsert := false
	if newlyAllocatedIdentities == nil {
		upsert = true
		newlyAllocatedIdentities = map[string]*identity.Identity{}
	}

	IPIdentityCache.Lock()
	allocatedIdentities := make(map[string]*identity.Identity, len(prefixes))
	for i, p := range prefixes {
		if p == nil {
			continue
		}

		lbls := cidr.GetCIDRLabels(p)
		lbls.MergeLabels(GetIDMetadataByIP(p.IP.String()))
		oldNID := identity.InvalidIdentity
		if oldNIDs != nil && len(oldNIDs) > i {
			oldNID = oldNIDs[i]
		}
		id, isNew, err := allocate(p, lbls, oldNID)
		if err != nil {
			IPIdentityCache.Unlock()
			IdentityAllocator.ReleaseSlice(context.Background(), nil, usedIdentities)
			return nil, err
		}

		prefixStr := p.String()
		usedIdentities = append(usedIdentities, id)
		allocatedIdentities[prefixStr] = id
		if isNew {
			newlyAllocatedIdentities[prefixStr] = id
		}
	}
	IPIdentityCache.Unlock()

	// Only upsert into ipcache if identity wasn't allocated
	// before and the caller does not care doing this
	if upsert {
		UpsertGeneratedIdentities(newlyAllocatedIdentities, nil)
	}

	identities := make([]*identity.Identity, 0, len(allocatedIdentities))
	for _, id := range allocatedIdentities {
		identities = append(identities, id)
	}
	return identities, nil
}

// AllocateCIDRsForIPs performs the same action as AllocateCIDRs but for IP
// addresses instead of CIDRs.
//
// Upon success, the caller must also arrange for the resulting identities to
// be released via a subsequent call to ReleaseCIDRIdentitiesByID().
func AllocateCIDRsForIPs(
	prefixes []net.IP, newlyAllocatedIdentities map[string]*identity.Identity,
) ([]*identity.Identity, error) {
	return AllocateCIDRs(ip.GetCIDRPrefixesFromIPs(prefixes), nil, newlyAllocatedIdentities)
}

func cidrLabelToPrefix(label string) (string, bool) {
	if !strings.HasPrefix(label, labels.LabelSourceCIDR) {
		return "", false
	}
	return strings.TrimPrefix(label, labels.LabelSourceCIDR+":"), true
}

// UpsertGeneratedIdentities unconditionally upserts 'newlyAllocatedIdentities'
// into the ipcache, then also upserts any CIDR identities in 'usedIdentities'
// that were not already upserted. If any 'usedIdentities' are upserted, these
// are counted separately as they may provide an indication of another logic
// error elsewhere in the codebase that is causing premature ipcache deletions.
func UpsertGeneratedIdentities(newlyAllocatedIdentities map[string]*identity.Identity, usedIdentities []*identity.Identity) {
	for prefixString, id := range newlyAllocatedIdentities {
		IPIdentityCache.Upsert(prefixString, nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
	if len(usedIdentities) == 0 {
		return
	}

	toUpsert := make(map[string]*identity.Identity)
	IPIdentityCache.mutex.RLock()
	for _, id := range usedIdentities {
		prefix, ok := cidrLabelToPrefix(id.CIDRLabel.String())
		if !ok {
			log.WithFields(logrus.Fields{
				logfields.Identity: id.ID,
			}).Warning("BUG: Attempting to upsert non-CIDR identity")
			continue
		}
		if _, ok := IPIdentityCache.LookupByIPRLocked(prefix); ok {
			// Already there; continue
			continue
		}
		toUpsert[prefix] = id
	}
	IPIdentityCache.mutex.RUnlock()
	for prefix, id := range toUpsert {
		metrics.IPCacheErrorsTotal.WithLabelValues(
			metricTypeRecover, metricErrorUnexpected,
		).Inc()
		IPIdentityCache.Upsert(prefix, nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
}

// allocate will allocate a new identity for the given prefix based on the
// given set of labels. This function performs both global and local (CIDR)
// identity allocation and the set of labels determine which identity
// allocation type is to occur.
//
// If the identity is a CIDR identity, then its corresponding Identity will
// have its CIDR labels set correctly.
//
// A possible previously used numeric identity for these labels can be passed
// in as the 'oldNID' parameter; identity.InvalidIdentity must be passed if no
// previous numeric identity exists.
//
// It is up to the caller to provide the full set of labels for identity
// allocation.
func allocate(prefix *net.IPNet, lbls labels.Labels, oldNID identity.NumericIdentity) (*identity.Identity, bool, error) {
	if prefix == nil {
		return nil, false, nil
	}

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()

	id, isNew, err := IdentityAllocator.AllocateIdentity(allocateCtx, lbls, false, oldNID)
	if err != nil {
		return nil, isNew, fmt.Errorf("failed to allocate identity for cidr %s: %s", prefix, err)
	}

	if lbls.Has(labels.LabelWorld[labels.IDNameWorld]) {
		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefix.String()})
	}

	return id, isNew, err
}

func releaseCIDRIdentities(ctx context.Context, identities map[string]*identity.Identity) {
	// Create a critical section for identity release + removal from ipcache.
	// Otherwise, it's possible to trigger the following race condition:
	//
	// Goroutine 1                | Goroutine 2
	// releaseCIDRIdentities()    | AllocateCIDRs()
	// -> Release(..., id, ...)   |
	//                            | -> allocate(...)
	//                            | -> ipc.UpsertGeneratedIdentities(...)
	// -> ipc.deleteLocked(...)   |
	//
	// In this case, the expectation from Goroutine 2 is that an identity
	// is allocated and that identity is in the ipcache, but the result
	// is that the identity is allocated but the ipcache entry is missing.
	IPIdentityCache.Lock()
	defer IPIdentityCache.Unlock()
	for prefix, id := range identities {
		released, err := IdentityAllocator.Release(ctx, id, false)
		if err != nil {
			log.WithFields(logrus.Fields{
				logfields.Identity: id,
				logfields.CIDR:     prefix,
			}).WithError(err).Warning("Unable to release CIDR identity. Ignoring error. Identity may be leaked")
		}

		if released {
			IPIdentityCache.deleteLocked(prefix, source.Generated)
		}
	}
}

// ReleaseCIDRIdentitiesByCIDR releases the identities of a list of CIDRs.
// When the last use of the identity is released, the ipcache entry is deleted.
func ReleaseCIDRIdentitiesByCIDR(prefixes []*net.IPNet) {
	// TODO: Structure the code to pass context down from the Daemon.
	releaseCtx, cancel := context.WithTimeout(context.TODO(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	identities := make(map[string]*identity.Identity, len(prefixes))
	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		if id := IdentityAllocator.LookupIdentity(releaseCtx, cidr.GetCIDRLabels(prefix)); id != nil {
			identities[prefix.String()] = id
		} else {
			log.Errorf("Unable to find identity of previously used CIDR %s", prefix.String())
		}
	}

	releaseCIDRIdentities(releaseCtx, identities)
}

// ReleaseCIDRIdentitiesByID releases the specified identities.
// When the last use of the identity is released, the ipcache entry is deleted.
func ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
	fullIdentities := make(map[string]*identity.Identity, len(identities))
	for _, nid := range identities {
		if id := IdentityAllocator.LookupIdentityByID(ctx, nid); id != nil {
			cidr, ok := cidrLabelToPrefix(id.CIDRLabel.String())
			if !ok {
				log.WithFields(logrus.Fields{
					logfields.Identity: nid,
					logfields.Labels:   id.Labels,
				}).Warn("Unexpected release of non-CIDR identity, will leak this identity. Please report this issue to the developers.")
				continue
			}
			fullIdentities[cidr] = id
		} else {
			log.WithFields(logrus.Fields{
				logfields.Identity: nid,
			}).Warn("Unexpected release of numeric identity that is no longer allocated")
		}
	}

	releaseCIDRIdentities(ctx, fullIdentities)
}
