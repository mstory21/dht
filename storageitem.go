package dht

import (
	"crypto/sha1"

	"github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/exp/errors"

	"github.com/anacrolix/torrent/bencode"

	"fmt"
	_ "time"
)

// this is the local representation of a Storage Item
// can store mutable or immutable items
type StorageItem struct {
	Target [20]byte
	V      interface{}
	K      [32]byte
	Salt   []byte
	Sig    [64]byte
	Seq    uint64
	Cas    []byte

	PrivateKey ed25519.PrivateKey

	//lastUpdate time.Time
}

// calculates the target and the signature of a Storage Item
func (s *StorageItem) Calc() error {
	v, ok := bencode.Marshal(s.V)
	if ok != nil {
		return ok
	}

	if len(v) > 1000 {
		return errors.New("message (v field) too big.")
	}

	if s.PrivateKey == nil {
		s.Target = sha1.Sum(v)
		return nil
	}

	copy(s.K[:], s.PrivateKey.Public().(ed25519.PublicKey))
	if s.Salt == nil {
		s.Target = sha1.Sum(s.K[:])
	} else {
		s.Target = sha1.Sum(append(s.K[:], s.Salt...))
	}

	bts := s.bufferToSign()
	copy(s.Sig[:], ed25519.Sign(s.PrivateKey, bts))
	return nil
}

func (s *StorageItem) IsMutable() bool {
	var empty32 [32]byte
	return s.K != empty32
}

func (s *StorageItem) Check() error {
	if !s.IsMutable() {
		m, ok := bencode.Marshal(s.V)
		if ok != nil {
			return ok
		}
		if s.Target == sha1.Sum(m) {
			return nil
		}
		return errors.New("Bad Item.")
	}
	bts := s.bufferToSign()
	if ed25519.Verify(s.K[:], bts, s.Sig[:]) {
		return nil
	}
	return errors.New("Bad Item.")
}

func (s *StorageItem) bufferToSign() []byte {
	var bts []byte
	if s.Salt != nil {
		bts = append(bts, []byte("4:salt")...)
		x := bencode.MustMarshal(s.Salt)
		bts = append(bts, x...)
	}
	bts = append(bts, []byte(fmt.Sprintf("3:seqi%de1:v", s.Seq))...)
	bts = append(bts, bencode.MustMarshal(s.V)...)
	return bts
}

func (s *Server) AddStorageItem(si StorageItem) bool {

	ok := si.Check()
	if ok != nil {
		return false
	}
	storeIT := false
	if !si.IsMutable() {
		storeIT = true
	} else {
		stored, ok := s.GetStorageItem(si.Target)
		if ok && si.Seq > stored.Seq {
			storeIT = true
			if si.PrivateKey == nil {
				si.PrivateKey = stored.PrivateKey
			}
		}
		if ok && si.Seq == stored.Seq && si.V == stored.V {
			storeIT = true
			if si.PrivateKey == nil {
				si.PrivateKey = stored.PrivateKey
			}
		}
		if !ok {
			storeIT = true
		}
	}
	if storeIT {
		s.muDb.Lock()
		defer s.muDb.Unlock()
		//si.lastUpdate = time.Now()
		s.storageItems[int160FromByteArray(si.Target)] = si
		return true
	}
	return false
}

func (s *Server) GetStorageItem(itemN [20]byte) (StorageItem, bool) {
	s.muDb.Lock()
	defer s.muDb.Unlock()
	newItem, ok := s.storageItems[int160FromByteArray(itemN)]
	return newItem, ok
}
