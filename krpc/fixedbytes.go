package krpc

import (
	"fmt"

	"github.com/anacrolix/torrent/bencode"
)

type Bytes32 [32]byte

var (
	_ interface {
		bencode.Unmarshaler
	} = (*Bytes32)(nil)
	_ bencode.Marshaler = Bytes32{}
)


func (bs Bytes32) MarshalBencode() ([]byte, error) {
	return []byte("32:" + string(bs[:])), nil
}

func (bs *Bytes32) UnmarshalBencode(b []byte) error {
	var s string
	if err := bencode.Unmarshal(b, &s); err != nil {
		return err
	}
	if n := copy(bs[:], s); n != 32 {
		return fmt.Errorf("string has wrong length: %d", n)
	}
	return nil
}

type Bytes64 [64]byte

var (
     	_ interface {
                bencode.Unmarshaler
        } = (*Bytes64)(nil)
        _ bencode.Marshaler = Bytes32{}
)


func (bs Bytes64) MarshalBencode() ([]byte, error) {
        return []byte("64:" + string(bs[:])), nil
}

func (bs *Bytes64) UnmarshalBencode(b []byte) error {
        var s string
        if err := bencode.Unmarshal(b, &s); err != nil {
                return err
        }
	if n := copy(bs[:], s); n != 64 {
                return fmt.Errorf("string has wrong length: %d", n)
        }
	return nil
}
