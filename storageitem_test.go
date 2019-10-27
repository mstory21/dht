package dht

import (
	"testing"
	"encoding/hex"
)

func TestImmutable (t *testing.T) {
	t.Log("Testing Immutable Item")

	si := StorageItem {
		V:"Hello World!",
		}

	if si.Check()==nil {
		t.Error("check with wrong checksum should report an error")
	}

	si.Calc()

	hx,_ := hex.DecodeString("e5f96f6f38320f0f33959cb4d3d656452117aadb")
	var ht [20]byte
	copy(ht[:],hx)
	if si.Target != ht {
		t.Error("target checksum mismatch")
	}
}

func TestMutable(t *testing.T){
	t.Log("Testing Mutable Item.")

	var pubKey  [32]byte
	var privKey []byte
	var sig     [64]byte
	var target  [20]byte

	t0,_  := hex.DecodeString("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548")
	copy(pubKey[:],t0)
	privKey,_ = hex.DecodeString("e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74db7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d")
	//copy(privKey[:],t1)
	t2,_ := hex.DecodeString("305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01")
	copy(sig[:],t2)
	t3,_ := hex.DecodeString("4a533d47ec9c7d95b1ad75f576cffc641853b750")
	copy(target[:],t3)

        si := StorageItem {
                V:          "Hello World!",
		PrivateKey: privKey,
		Seq:        1,
                }

	si.Calc()

	if si.Target != target {
		t.Errorf("Wrong Target %v %v",si.Target,target)
	}

	if si.Sig != sig {
		t.Error("Bad Signature")
	}
}

func TestMutableWithSalt(t *testing.T){
        t.Log("Testing Mutable Item with Salt.")

        var pubKey  [32]byte
        var privKey []byte
        var sig     [64]byte
        var target  [20]byte

        t0,_  := hex.DecodeString("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548")
        copy(pubKey[:],t0)
        privKey,_ = hex.DecodeString("e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74db7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d")
        t2,_ := hex.DecodeString("6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08")
        copy(sig[:],t2)
        t3,_ := hex.DecodeString("411eba73b6f087ca51a3795d9c8c938d365e32c1")
        copy(target[:],t3)

        si := StorageItem {
                V:          "Hello World!",
                PrivateKey: privKey,
                Seq:        1,
		Salt:       []byte("foobar"),
                }

        si.Calc()

        if si.Target != target {
                t.Errorf("Wrong Target %v %v",si.Target,target)
        }

        if si.Sig != sig {
                t.Error("Bad Signature")
        }
}
