package dht

// get and put.

import (
	"context"
	_ "net"

	"github.com/anacrolix/missinggo/v2/conntrack"
	"github.com/anacrolix/missinggo/v2/iter"
	"github.com/anacrolix/stm"
	"github.com/anacrolix/stm/stmutil"

	"github.com/anacrolix/dht/v2/krpc"

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
	Value chan StorageAnswer

	values chan StorageAnswer // Responses are pushed to this channel.

	// These only exist to support routines relying on channels for synchronization.
	done    <-chan struct{}
	doneVar *stm.Var
	cancel  func()

	triedAddrs *stm.Var // Settish of krpc.NodeAddr.String

	pending *stm.Var // How many transactions are still ongoing (int).
	server  *Server

	target int160
	// Count of (probably) distinct addresses we've sent get_peers requests to.
	numContacted *stm.Var
	seq          uint64

	nodesPendingContact *stm.Var
}

// Calculates the target from the public key
func TargetFromPublicKey(pkey []byte) [20]byte {
	return sha1.Sum(pkey)
}

// Calculates the target from the public key with salt
func TargetFromPublicKeyWithSalt(pkey, salt []byte) [20]byte {
	return sha1.Sum(append(pkey, salt...))
}

// Returns the number of distinct remote addresses the ArbitraryData has queried.
func (a *ArbitraryData) NumContacted() int {
	return stm.AtomicGet(a.numContacted).(int)
}

// This is kind of the second thing you want to do with DHT. It traverses the nodes and saves-retrieves th Arbitrary Storage Item
func (s *Server) ArbitraryData(target [20]byte, seq *uint64) (*ArbitraryData, error) {
	startAddrs, err := s.traversalStartingNodes()
	if err != nil {
		return nil, err
	}
	a := &ArbitraryData{
		Value:               make(chan StorageAnswer, 100),
		values:              make(chan StorageAnswer),
		triedAddrs:          stm.NewVar(stmutil.NewSet()),
		server:              s,
		target:              int160FromByteArray(target),
		nodesPendingContact: stm.NewVar(nodesByDistance(int160FromByteArray(target))),
		pending:             stm.NewVar(0),
		numContacted:        stm.NewVar(0),
	}
	if seq != nil {
		a.seq = *seq
	}
	var ctx context.Context
	ctx, a.cancel = context.WithCancel(context.Background())
	a.done = ctx.Done()
	a.doneVar, _ = stmutil.ContextDoneVar(ctx)
	// Function ferries from values to Values until discovery is halted.
	go func() {
		defer close(a.Value)
		for {
			select {
			case psv := <-a.values:
				select {
				case a.Value <- psv:
				case <-a.done:
					return
				}
			case <-a.done:
				return
			}
		}
	}()
	for _, n := range startAddrs {
		stm.Atomically(a.pendContact(n))
	}
	go a.closer()
	go a.nodeContactor()
	return a, nil
}

func (a *ArbitraryData) closer() {
	stm.Atomically(stm.VoidOperation(func(tx *stm.Tx) {
		if tx.Get(a.doneVar).(bool) {
			return
		}
		tx.Assert(tx.Get(a.pending).(int) == 0)
		tx.Assert(tx.Get(a.nodesPendingContact).(stmutil.Lenner).Len() == 0)
	}))
	a.cancel()
}

func (a *ArbitraryData) shouldContact(addr krpc.NodeAddr, tx *stm.Tx) bool {
	if !validNodeAddr(addr.UDP()) {
		return false
	}
	if tx.Get(a.triedAddrs).(stmutil.Settish).Contains(addr.String()) {
		return false
	}
	if a.server.ipBlocked(addr.IP) {
		return false
	}
	return true
}

func (a *ArbitraryData) completeContact() {
	stm.Atomically(stm.VoidOperation(func(tx *stm.Tx) {
		tx.Set(a.pending, tx.Get(a.pending).(int)-1)
	}))
}

func (a *ArbitraryData) responseNode(node krpc.NodeInfo) {
	i := int160FromByteArray(node.ID)
	stm.Atomically(a.pendContact(addrMaybeId{node.Addr, &i}))
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

func (a *ArbitraryData) get(addr Addr, cteh *conntrack.EntryHandle) numWrites {
	m, writes, _ := a.server.get(context.TODO(), addr, a.target)
	if m.E != nil {
		//                fmt.Println(m.E)
		goto end
	}
	// Register suggested nodes closer to the target.
	if m.R != nil && m.SenderID() != nil {
		expvars.Add("ArbitraryData get response nodes values", int64(len(m.R.Nodes)))
		expvars.Add("ArbitraryData get response nodes6 values", int64(len(m.R.Nodes6)))
		m.R.ForAllNodes(a.responseNode)

		//received something ..
		if m.R.V != nil {
			si := StorageItem{
				Target: a.target.AsByteArray(),
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
			case <-a.done:
			}
			//if received good data store it!
			//note this doesn't have the salt, so it will fail on mutables with salt.
			if si.Check() == nil {
				a.server.AddStorageItem(si)
			}
		}

		// nothing received or received seq < storedItem.Seq PUT-IT
		storedItem, gotItem := a.server.GetStorageItem(a.target.AsByteArray())
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
	a.completeContact()

	return writes
}

// Stop the ArbitraryData.
func (a *ArbitraryData) Close() {
	a.close()
}

func (a *ArbitraryData) close() {
	a.cancel()
}

func (a *ArbitraryData) pendContact(node addrMaybeId) stm.Operation {
	return stm.VoidOperation(func(tx *stm.Tx) {
		if !a.shouldContact(node.Addr, tx) {
			// log.Printf("shouldn't contact (pend): %v", node)
			return
		}
		tx.Set(a.nodesPendingContact, tx.Get(a.nodesPendingContact).(stmutil.Settish).Add(node))
	})
}

func (a *ArbitraryData) nodeContactor() {
	for {
		type txResT struct {
			done    bool
			contact bool
			addr    Addr
			cteh    *conntrack.EntryHandle
		}
		txRes := stm.Atomically(func(tx *stm.Tx) interface{} {
			if tx.Get(a.doneVar).(bool) {
				return txResT{done: true}
			}
			npc := tx.Get(a.nodesPendingContact).(stmutil.Settish)
			first, ok := iter.First(npc.Iter)
			if !ok {
				tx.Retry()
			}
			addr := first.(addrMaybeId).Addr
			tx.Set(a.nodesPendingContact, npc.Delete(first))
			if !a.shouldContact(addr, tx) {
				return txResT{}
			}
			cteh := a.server.config.ConnectionTracking.Allow(tx, a.server.connTrackEntryForAddr(NewAddr(addr.UDP())), "announce get_peers", -1)
			if cteh == nil {
				tx.Retry()
			}
			if !a.server.sendLimit.AllowStm(tx) {
				tx.Retry()
			}
			tx.Set(a.numContacted, tx.Get(a.numContacted).(int)+1)
			tx.Set(a.pending, tx.Get(a.pending).(int)+1)
			tx.Set(a.triedAddrs, tx.Get(a.triedAddrs).(stmutil.Settish).Add(addr.String()))
			return txResT{addr: NewAddr(addr.UDP()), cteh: cteh, contact: true}
		}).(txResT)
		if txRes.done {
			break
		}
		if txRes.contact {
			go a.get(txRes.addr, txRes.cteh)
		}
	}
}
