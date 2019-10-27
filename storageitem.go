package dht

import (
	"crypto/sha1"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/exp/errors"

	"github.com/anacrolix/torrent/bencode"

	"fmt"
)

type StorageItem struct {
        Target [20]byte
        V interface{}
	K ed25519.PublicKey
	Salt string
	Sig [64]byte
	Seq uint64

	PrivateKey ed25519.PrivateKey

	owner bool
}

func (s *StorageItem) Calc() error{
	v,ok := bencode.Marshal(s.V)
	if ok != nil {
        	return ok
        }

	if len(v)>1000 {
		return errors.New("message (v field) too big.")
	}

        if s.PrivateKey == nil {
                s.Target = sha1.Sum(v)
                return nil
        }

//	target:=bencode.MustMarshal(s.K)
//	seq:=bencode.MustMarshal(s.Seq)


	return nil
}

func (s *StorageItem) Check() error{
        if s.K == nil {
		m,ok := bencode.Marshal(s.V)
		if ok != nil {
			return ok
		}
		if (s.Target == sha1.Sum(m)) {
			return nil
		}
	fmt.Printf("error SIcheck: %s\t%s\n",s.Target,m)
	return errors.New("Bad Item.")
	}

	return errors.New("Bad Item.")
}

func (s *Server) AddStorageItem(si StorageItem) bool {

	ok:= si.Check()
	if ok!=nil {
		return false
	}

        s.muDb.Lock()
        defer s.muDb.Unlock()
        s.storageItems[si.Target]=si
        return true
}

func (s *Server) GetStorageItem(itemN [20]byte) (StorageItem, bool){
        s.muDb.Lock()
        defer s.muDb.Unlock()
        newItem,ok := s.storageItems[itemN]
/*      if ok {
                *si = newItem
        }*/
	return newItem,ok
}

