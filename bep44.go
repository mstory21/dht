package dht

// get and put.

import (
	"container/heap"
	"context"
	_ "net"
	"time"

	"github.com/anacrolix/sync"
	"github.com/willf/bloom"

	"github.com/fluturenet/dht/krpc"

	"crypto/sha1"

	_ "fmt"
)

type StorageAnswer struct {
	StorageItem StorageItem
	NodeInfo    krpc.NodeInfo
}

// Maintains state for an ongoing ArbitraryData operation. An ArbitraryData is started
// by calling Server.ArbitraryData.
type ArbitraryData struct {
	mu    sync.Mutex
	Value chan StorageAnswer
	// Inner chan is set to nil when on close.
	values     chan StorageAnswer
	target     [20]byte
	seq        uint64
	ctx        context.Context
	cancel     func()
	stop       <-chan struct{}
	triedAddrs *bloom.BloomFilter
	// How many transactions are still ongoing.
	pending int
	server  *Server
	// Count of (probably) distinct addresses we've sent get_peers requests
	// to.
	numContacted int

	nodesPendingContact nodesByDistance
	nodeContactorCond   sync.Cond
	contactRateLimiter  chan struct{}
}

// Claculates the target from the public key
func TargetFromPublicKey(pkey []byte) [20]byte {
	return sha1.Sum(pkey)
}

// Claculates the target from the public key with salt
func TargetFromPublicKeyWithSalt(pkey, salt []byte) [20]byte {
	return sha1.Sum(append(pkey, salt...))
}

// Returns the number of distinct remote addresses the ArbitraryData has queried.
func (a *ArbitraryData) NumContacted() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.numContacted
}

// This is kind of the second thing you want to do with DHT. It traverses the nodes and saves-retrieves th Arbitrary Storage Item
func (s *Server) ArbitraryData(target [20]byte, seq *uint64) (*ArbitraryData, error) {
	startAddrs, err := s.traversalStartingNodes()
	if err != nil {
		return nil, err
	}
	a := &ArbitraryData{
		Value:              make(chan StorageAnswer, 100),
		values:             make(chan StorageAnswer),
		triedAddrs:         newBloomFilterForTraversal(),
		server:             s,
		target:             target,
		contactRateLimiter: make(chan struct{}, 10),
	}
	if seq != nil {
		a.seq = *seq
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.stop = a.ctx.Done()
	a.nodesPendingContact.target = int160FromByteArray(target)
	a.nodeContactorCond.L = &a.mu
	go a.rateUnlimiter()
	// Function ferries from values to Values until discovery is halted.
	go func() {
		defer close(a.Value)
		for {
			select {
			case psv := <-a.values:
				select {
				case a.Value <- psv:
				case <-a.stop:
					return
				}
			case <-a.stop:
				return
			}
		}
	}()
	for _, n := range startAddrs {
		a.pendContact(n)
	}
	a.maybeClose()
	go a.nodeContactor()
	return a, nil
}

func (a *ArbitraryData) rateUnlimiter() {
	for {
		select {
		case a.contactRateLimiter <- struct{}{}:
		case <-a.ctx.Done():
			return
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *ArbitraryData) shouldContact(addr krpc.NodeAddr) bool {
	if !validNodeAddr(addr.UDP()) {
		return false
	}
	if a.triedAddrs.TestString(addr.String()) {
		return false
	}
	if a.server.ipBlocked(addr.IP) {
		return false
	}
	return true
}

func (a *ArbitraryData) completeContact() {
	a.pending--
	a.maybeClose()
}

func (a *ArbitraryData) contact(node addrMaybeId) bool {
	if !a.shouldContact(node.Addr) {
		// log.Printf("shouldn't contact: %v", node)
		return false
	}
	a.numContacted++
	a.pending++
	a.triedAddrs.AddString(node.Addr.String())
	go a.get(node)
	return true
}

func (a *ArbitraryData) maybeClose() {
	if a.nodesPendingContact.Len() == 0 && a.pending == 0 {
		a.close()
	}
}

func (a *ArbitraryData) responseNode(node krpc.NodeInfo) {
	i := int160FromByteArray(node.ID)
	a.pendContact(addrMaybeId{node.Addr, &i})
}

// ArbitraryData Put to a peer, if appropriate.
/*
func (a *ArbitraryData) maybePut(to Addr, token *string, peerId *krpc.ID) {
	if token == nil {
		return
	}
	if !a.server.config.NoSecurity && (peerId == nil || !NodeIdSecure(*peerId, to.IP())) {
		return
	}
	a.server.mu.Lock()
	defer a.server.mu.Unlock()
	a.server.put(to, a.target, *token)
}*/

func (a *ArbitraryData) get(node addrMaybeId) {
	addr := NewAddr(node.Addr.UDP())
	m, err := a.server.get(context.TODO(), addr, a.target)
	if err == nil {
		select {
		case a.contactRateLimiter <- struct{}{}:
		default:
		}
	}
	if m.E != nil {
		//                fmt.Println(m.E)
		goto end
	}
	// Register suggested nodes closer to the target.
	if m.R != nil && m.SenderID() != nil {
		expvars.Add("ArbitraryData get response nodes values", int64(len(m.R.Nodes)))
		expvars.Add("ArbitraryData get response nodes6 values", int64(len(m.R.Nodes6)))
		a.mu.Lock()
		m.R.ForAllNodes(a.responseNode)
		a.mu.Unlock()

		//recevided something ..
		if m.R.V != nil {
			si := StorageItem{
				Target: a.target,
				V:      m.R.V,
				K:      m.R.K,
				Seq:    m.R.Seq,
				Sig:    m.R.Sig,
			}
			sa := StorageAnswer{
				StorageItem: si,
				NodeInfo: krpc.NodeInfo{
					Addr: addr.KRPC(),
					ID:   *m.SenderID(),
				},
			}
			select {
			case a.values <- sa:
			case <-a.stop:
			}
			//if received good data store it!
			if si.Check() == nil {
				a.server.AddStorageItem(si)
			}
		}

		// nothing received or received seq < storedItem.Seq PUT-IT
		storedItem, gotItem := a.server.GetStorageItem(a.target)
		if m.R.V == nil || (gotItem && storedItem.IsMutable() && storedItem.Seq > m.R.Seq) {
			if m.R.Token == nil {
				goto end
			}
			if !a.server.config.NoSecurity && (m.SenderID() == nil || !NodeIdSecure(*m.SenderID(), addr.IP())) {
				goto end
			}
			a.server.mu.Lock()
			defer a.server.mu.Unlock()
			a.server.put(addr, a.target, *m.R.Token)
		}
	}

end:
	a.mu.Lock()
	a.completeContact()
	a.mu.Unlock()
}

// Stop the ArbitraryData.
func (a *ArbitraryData) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.close()
}

func (a *ArbitraryData) close() {
	select {
	case <-a.stop:
	default:
		a.cancel()
		a.nodeContactorCond.Broadcast()
	}
}

func (a *ArbitraryData) pendContact(node addrMaybeId) {
	if !a.shouldContact(node.Addr) {
		// log.Printf("shouldn't contact (pend): %v", node)
		return
	}
	heap.Push(&a.nodesPendingContact, node)
	a.nodeContactorCond.Signal()
}

func (a *ArbitraryData) waitContactRateToken() bool {
	select {
	case <-a.ctx.Done():
		return false
	case <-a.contactRateLimiter:
		return true
	}
}

func (a *ArbitraryData) contactPendingNode() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for {
		if a.ctx.Err() != nil {
			return false
		}
		for a.nodesPendingContact.Len() > 0 {
			if a.contact(heap.Pop(&a.nodesPendingContact).(addrMaybeId)) {
				return true
			}
		}
		a.nodeContactorCond.Wait()
	}
}

func (a *ArbitraryData) nodeContactor() {
	for {
		if !a.waitContactRateToken() {
			return
		}
		if !a.contactPendingNode() {
			return
		}
	}
}
