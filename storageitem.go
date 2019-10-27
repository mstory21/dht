package dht

import (
	"crypto/sha1"

	"github.com/fluturenet/ed25519"
	"golang.org/x/exp/errors"

	"github.com/anacrolix/torrent/bencode"

	"fmt"
)

type StorageItem struct {
        Target [20]byte
        V interface{}
	K ed25519.PublicKey
	Salt []byte
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

	s.K = s.PrivateKey.Public().(ed25519.PublicKey)
	if s.Salt == nil {
		s.Target = sha1.Sum(s.K)
	} else {
		s.Target = sha1.Sum(append(s.K,s.Salt...))
	}

	bts := s.bufferToSign()
	copy(s.Sig[:],ed25519.Sign(s.PrivateKey,bts))
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
	return errors.New("Bad Item.")
	}

	return errors.New("Bad Item.")
}

func (s *StorageItem) bufferToSign() []byte {
	var bts []byte
	if s.Salt != nil {
		bts = append(bts,[]byte("4:salt")...)
		x := bencode.MustMarshal(s.Salt)
		bts = append(bts,x...)
	}
	bts = append(bts,[]byte(fmt.Sprintf("3:seqi%de1:v",s.Seq))...)
	bts = append(bts,bencode.MustMarshal(s.V)...)
	return bts
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
	return newItem,ok
}

