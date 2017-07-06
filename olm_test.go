package olm

import "testing"

import (
	"encoding/json"
)

func TestOlm(t *testing.T) {
	major, minor, patch := Version()
	t.Log("Version():", major, minor, patch)
}

func TestAccount(t *testing.T) {
	a1, err := NewAccount()
	if err != nil {
		t.Error(err)
	}
	//t.Log("Size():", a.Size())
	pickled1, err := a1.Pickle([]byte("HELLO"))
	if err != nil {
		t.Error(err)
	}
	t.Log("Pickle():", pickled1)

	a11, _ := NewAccount()
	pickled11, _ := a11.Pickle([]byte("HELLO"))
	if pickled1 == pickled11 {
		t.Error("Two new accounts pickle to the same string")
	}

	a2, err := AccountFromPickled(pickled1, []byte("HELLO"))
	if err != nil {
		t.Error(err)
	}
	pickled2, err := a2.Pickle([]byte("HELLO"))
	if err != nil {
		t.Error(err)
	}
	t.Log("Pickle():", pickled2)
	a3, err := AccountFromPickled(pickled2, []byte("HELLO"))
	if err != nil {
		t.Error(err)
	}
	if pickled1 != pickled2 {
		t.Error("pickle(unpickle(pickle)) != pickle")
	}
	identityKeys, err := a1.IdentityKeys()
	if err != nil {
		t.Error(err)
	}
	t.Log("IdentityKeys():", identityKeys)
	signature, err := a1.Sign("HELLO WORLD")
	if err != nil {
		t.Error(err)
	}
	t.Log("a1.Sign():", signature)
	maxNumberOfOneTimeKeys := a1.MaxNumberOfOneTimeKeys()
	err = a1.GenOneTimeKeys(maxNumberOfOneTimeKeys)
	if err != nil {
		t.Error(err)
	}
	oneTimeKeys, err := a1.OneTimeKeys()
	if err != nil {
		t.Error(err)
	}
	t.Log("a1.OneTimeKeys():", oneTimeKeys)
	t.Log("a1.Clear():", a1.Clear())
	t.Log("a2.Clear():", a2.Clear())
	t.Log("a3.Clear():", a3.Clear())
}

type OneTimeKeys struct {
	Curve25519 map[string]string `json:"curve25519"`
}

type IdentityKeys struct {
	Curve25519 string `json:"curve25519"`
	Ed25519    string `json:"ed25519"`
}

func TestSession(t *testing.T) {
	a1, _ := NewAccount()
	a2, _ := NewAccount()

	a2.GenOneTimeKeys(a2.MaxNumberOfOneTimeKeys())
	a2OneTimeKeysJSON, _ := a2.OneTimeKeys()
	var a2OneTimeKeys OneTimeKeys
	json.Unmarshal([]byte(a2OneTimeKeysJSON), &a2OneTimeKeys)
	//t.Log("Marshaled:", a2OneTimeKeysJSON)
	//t.Logf("Unmarshaled: %+v", a2OneTimeKeys)
	// Pick one One Time Key
	var a2OneTimeKey string
	for _, v := range a2OneTimeKeys.Curve25519 {
		a2OneTimeKey = v
		break
	}

	a2IdentityKeysJSON, _ := a2.IdentityKeys()
	var a2IdentityKeys IdentityKeys
	json.Unmarshal([]byte(a2IdentityKeysJSON), &a2IdentityKeys)
	t.Log("a2IdentityKeys:", a2IdentityKeys)
	t.Log("a2OneTimeKey:", a2OneTimeKey)
	s1, err := a1.NewOutboundSession(a2IdentityKeys.Curve25519, a2OneTimeKey)
	if err != nil {
		t.Error(err)
	}
	pickled1, err := s1.Pickle([]byte("HELLO"))
	if err != nil {
		t.Error(err)
	}
	t.Log("Pickle():", pickled1)
}

func TestUtility(t *testing.T) {
	//var olmUtility Utility
	//t.Log("Size():", olmUtility.Size())
}
