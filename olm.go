package olm

// #cgo LDFLAGS: -lolm -lstdc++ -L/home/dev/git/olm/build/
// #cgo CFLAGS: -I/home/dev/git/olm/include/
// #include <olm/olm.h>
// #include <olm/outbound_group_session.h>
// #include <olm/inbound_group_session.h>
// #include <olm/megolm.h>
import "C"

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/fatih/structs"
	"unsafe"
)

// Signatures is the data structure used to sign JSON objects.  It maps from
// userID to a map from <algorithm:deviceID> to signature.
type Signatures map[string]map[string]string

// SessionID is the identifier of an Olm/Megolm session
type SessionID string

// Ed25519 is the base64 representation of an Ed25519 public key
type Ed25519 string

// Curve25519 is the base64 representation of an Curve25519 public key
type Curve25519 string

// Version returns the version number of the olm library.
func Version() (major, minor, patch uint8) {
	C.olm_get_library_version(
		(*C.uint8_t)(&major),
		(*C.uint8_t)(&minor),
		(*C.uint8_t)(&patch))
	return
}

// errorVal returns the value that olm functions return if there was an error.
func errorVal() C.size_t {
	return C.olm_error()
}

// Session stores an end to end encrypted messaging session.
type Session C.OlmSession

// sessionSize is the size of a session object in bytes.
func sessionSize() uint {
	return uint(C.olm_session_size())
}

// lastError returns an error describing the most recent error to happen to a
// session.
func (s *Session) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_session_last_error((*C.OlmSession)(s))))
}

// Clear clears the memory used to back this Session.
func (s *Session) Clear() error {
	r := C.olm_clear_session((*C.OlmSession)(s))
	if r == errorVal() {
		return s.lastError()
	} else {
		return nil
	}
}

// pickleLen returns the number of bytes needed to store a session.
func (s *Session) pickleLen() uint {
	return uint(C.olm_pickle_session_length((*C.OlmSession)(s)))
}

// createOutboundRandomLen returns the number of random bytes needed to create
// an outbound session.
func (s *Session) createOutboundRandomLen() uint {
	return uint(C.olm_create_outbound_session_random_length((*C.OlmSession)(s)))
}

// idLen returns the length of the buffer needed to return the id for this
// session.
func (s *Session) idLen() uint {
	return uint(C.olm_session_id_length((*C.OlmSession)(s)))
}

// encryptRandomLen returns the number of random bytes needed to encrypt the
// next message.
func (s *Session) encryptRandomLen() uint {
	return uint(C.olm_encrypt_random_length((*C.OlmSession)(s)))
}

// encryptMsgLen returns the size of the next message in bytes for the given
// number of plain-text bytes.
func (s *Session) encryptMsgLen(plainTextLen int) uint {
	return uint(C.olm_encrypt_message_length((*C.OlmSession)(s), C.size_t(plainTextLen)))
}

// decryptMaxPlaintextLen returns the maximum number of bytes of plain-text a
// given message could decode to.  The actual size could be different due to
// padding.  Returns error on failure.  If the message base64 couldn't be
// decoded then the error will be "INVALID_BASE64".  If the message is for an
// unsupported version of the protocol then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then the error
// will be "BAD_MESSAGE_FORMAT".
func (s *Session) decryptMaxPlaintextLen(message string, msgType MsgType) (uint, error) {
	if len(message) == 0 {
		return 0, fmt.Errorf("Empty input")
	}
	r := C.olm_decrypt_max_plaintext_length(
		(*C.OlmSession)(s),
		C.size_t(msgType),
		unsafe.Pointer(C.CString(message)),
		C.size_t(len(message)))
	if r == errorVal() {
		return 0, s.lastError()
	} else {
		return uint(r), nil
	}
}

// Pickle returns a Session as a base64 string.  Encrypts the Session using the
// supplied key.
func (s *Session) Pickle(key []byte) string {
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&key[0]),
		//unsafe.Pointer(key),
		C.size_t(lenKey),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return string(pickled[:r])
	}
}

// Id returns an identifier for this Session.  Will be the same for both ends
// of the conversation.
func (s *Session) ID() SessionID {
	id := make([]byte, s.idLen())
	r := C.olm_session_id(
		(*C.OlmSession)(s),
		unsafe.Pointer(&id[0]),
		C.size_t(len(id)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return SessionID(id)
	}
}

// HasReceivedMessage returns true if this session has received any message.
func (s *Session) HasReceivedMessage() bool {
	switch C.olm_session_has_received_message((*C.OlmSession)(s)) {
	case 0:
		return false
	default:
		return true
	}
}

// MatchesInboundSession checks if the PRE_KEY message is for this in-bound
// Session.  This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply.  Returns true if the session
// matches.  Returns false if the session does not match.  Returns error on
// failure.  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".  If the message was for an unsupported protocol version
// then the error will be "BAD_MESSAGE_VERSION".  If the message couldn't be
// decoded then then the error will be "BAD_MESSAGE_FORMAT".
func (s *Session) MatchesInboundSession(oneTimeKeyMsg string) (bool, error) {
	if len(oneTimeKeyMsg) == 0 {
		return false, fmt.Errorf("Empty input")
	}
	r := C.olm_matches_inbound_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg))[0]),
		C.size_t(len(oneTimeKeyMsg)))
	if r == 1 {
		return true, nil
	} else if r == 0 {
		return false, nil
	} else { // if r == errorVal()
		return false, s.lastError()
	}
}

// MatchesInboundSessionFrom checks if the PRE_KEY message is for this in-bound
// Session.  This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply.  Returns true if the session
// matches.  Returns false if the session does not match.  Returns error on
// failure.  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".  If the message was for an unsupported protocol version
// then the error will be "BAD_MESSAGE_VERSION".  If the message couldn't be
// decoded then then the error will be "BAD_MESSAGE_FORMAT".
func (s *Session) MatchesInboundSessionFrom(theirIdentityKey, oneTimeKeyMsg string) (bool, error) {
	if len(theirIdentityKey) == 0 || len(oneTimeKeyMsg) == 0 {
		return false, fmt.Errorf("Empty input")
	}
	r := C.olm_matches_inbound_session_from(
		(*C.OlmSession)(s),
		unsafe.Pointer(&([]byte(theirIdentityKey))[0]),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg))[0]),
		C.size_t(len(oneTimeKeyMsg)))
	if r == 1 {
		return true, nil
	} else if r == 0 {
		return false, nil
	} else { // if r == errorVal()
		return false, s.lastError()
	}
}

type Algorithm string

const (
	AlgorithmNone     Algorithm = ""
	AlgorithmOlmV1    Algorithm = "m.olm.v1.curve25519-aes-sha2"
	AlgorithmMegolmV1 Algorithm = "m.megolm.v1.aes-sha2"
)

type MsgType uint

// cgo doesn't handle static const
const (
	MsgTypePreKey MsgType = 0
	MsgTypeMsg    MsgType = 1
)

// EncryptMsgType returns the type of the next message that Encrypt will
// return.  Returns MsgTypePreKey if the message will be a PRE_KEY message.
// Returns MsgTypeMsg if the message will be a normal message.  Returns error
// on failure.
func (s *Session) EncryptMsgType() MsgType {
	switch C.olm_encrypt_message_type((*C.OlmSession)(s)) {
	case C.size_t(MsgTypePreKey):
		return MsgTypePreKey
	case C.size_t(MsgTypeMsg):
		return MsgTypeMsg
	default:
		panic("olm_encrypt_message_type returned invalid result")
	}
}

// Encrypt encrypts a message using the Session.  Returns the encrypted message
// as base64.
func (s *Session) Encrypt(plaintext string) (MsgType, string) {
	if len(plaintext) == 0 {
		plaintext = " "
	}
	// Make the slice be at least length 1
	random := make([]byte, s.encryptRandomLen()+1)
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	messageType := s.EncryptMsgType()
	message := make([]byte, s.encryptMsgLen(len(plaintext)))
	r := C.olm_encrypt(
		(*C.OlmSession)(s),
		unsafe.Pointer(&([]byte(plaintext))[0]),
		C.size_t(len(plaintext)),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return messageType, string(message[:r])
	}
}

// Decrypt decrypts a message using the Session.  Returns the the plain-text on
// success.  Returns error on failure.  If the base64 couldn't be decoded then
// the error will be "INVALID_BASE64".  If the message is for an unsupported
// version of the protocol then the error will be "BAD_MESSAGE_VERSION".  If
// the message couldn't be decoded then the error will be BAD_MESSAGE_FORMAT".
// If the MAC on the message was invalid then the error will be
// "BAD_MESSAGE_MAC".
func (s *Session) Decrypt(message string, msgType MsgType) (string, error) {
	if len(message) == 0 {
		return "", fmt.Errorf("Empty input")
	}
	decryptMaxPlaintextLen, err := s.decryptMaxPlaintextLen(message, msgType)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, decryptMaxPlaintextLen)
	r := C.olm_decrypt(
		(*C.OlmSession)(s),
		C.size_t(msgType),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)),
		unsafe.Pointer(&([]byte(plaintext))[0]),
		C.size_t(len(plaintext)))
	if r == errorVal() {
		return "", s.lastError()
	} else {
		return string(plaintext[:r]), nil
	}
}

// SessionFromPickled loads a Session from a pickled base64 string.  Decrypts
// the Session using the supplied key.  Returns error on failure.  If the key
// doesn't match the one used to encrypt the Session then the error will be
// "BAD_SESSION_KEY".  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".
func SessionFromPickled(pickled string, key []byte) (*Session, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	s := newSession()
	r := C.olm_unpickle_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&key[0]),
		C.size_t(lenKey),
		unsafe.Pointer(&([]byte(pickled))[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// newSession initialises an empty Session.
func newSession() *Session {
	memory := make([]byte, sessionSize())
	return (*Session)(C.olm_session(unsafe.Pointer(&memory[0])))
}

// Account stores a device account for end to end encrypted messaging.
type Account C.OlmAccount

// accountSize returns the size of an account object in bytes.
func accountSize() uint {
	return uint(C.olm_account_size())
}

// lastError returns an error describing the most recent error to happen to an
// account.
func (a *Account) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_account_last_error((*C.OlmAccount)(a))))
}

// Clear clears the memory used to back this Account.
func (a *Account) Clear() error {
	r := C.olm_clear_account((*C.OlmAccount)(a))
	if r == errorVal() {
		return a.lastError()
	} else {
		return nil
	}
}

// pickleLen returns the number of bytes needed to store an Account.
func (a *Account) pickleLen() uint {
	return uint(C.olm_pickle_account_length((*C.OlmAccount)(a)))
}

// createRandomLen returns the number of random bytes needed to create an
// Account.
func (a *Account) createRandomLen() uint {
	return uint(C.olm_create_account_random_length((*C.OlmAccount)(a)))
}

// identityKeysLen returns the size of the output buffer needed to hold the
// identity keys.
func (a *Account) identityKeysLen() uint {
	return uint(C.olm_account_identity_keys_length((*C.OlmAccount)(a)))
}

// signatureLen returns the length of an ed25519 signature encoded as base64.
func (a *Account) signatureLen() uint {
	return uint(C.olm_account_signature_length((*C.OlmAccount)(a)))
}

// oneTimeKeysLen returns the size of the output buffer needed to hold the one
// time keys.
func (a *Account) oneTimeKeysLen() uint {
	return uint(C.olm_account_one_time_keys_length((*C.OlmAccount)(a)))
}

// genOneTimeKeysRandomLen returns the number of random bytes needed to
// generate a given number of new one time keys.
func (a *Account) genOneTimeKeysRandomLen(num uint) uint {
	return uint(C.olm_account_generate_one_time_keys_random_length(
		(*C.OlmAccount)(a),
		C.size_t(num)))
}

// Pickle returns an Account as a base64 string. Encrypts the Account using the
// supplied key.
func (a *Account) Pickle(key []byte) string {
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	pickled := make([]byte, a.pickleLen())
	r := C.olm_pickle_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&key[0]),
		C.size_t(lenKey),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		return string(pickled[:r])
	}
}

// AccountFromPickled loads an Account from a pickled base64 string.  Decrypts
// the Account using the supplied key.  Returns error on failure.  If the key
// doesn't match the one used to encrypt the Account then the error will be
// "BAD_ACCOUNT_KEY".  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".
func AccountFromPickled(pickled string, key []byte) (*Account, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	a := newAccount()
	r := C.olm_unpickle_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&key[0]),
		C.size_t(lenKey),
		unsafe.Pointer(&([]byte(pickled))[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		return nil, a.lastError()
	} else {
		return a, nil
	}
}

// newAccount initialises an empty Account.
func newAccount() *Account {
	memory := make([]byte, accountSize())
	return (*Account)(C.olm_account(unsafe.Pointer(&memory[0])))
}

// NewAccount creates a new Account.
func NewAccount() *Account {
	a := newAccount()
	random := make([]byte, a.createRandomLen()+1)
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_create_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		return a
	}
}

// IdentityKeysJSON returns the public parts of the identity keys for the Account.
func (a *Account) IdentityKeysJSON() string {
	identityKeys := make([]byte, a.identityKeysLen())
	r := C.olm_account_identity_keys(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&identityKeys[0]),
		C.size_t(len(identityKeys)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		return string(identityKeys)
	}
}

// IdentityKeys returns the public parts of the Ed25519 and Curve25519 identity
// keys for the Account.
func (a *Account) IdentityKeys() (Ed25519, Curve25519) {
	identityKeysJSON := a.IdentityKeysJSON()
	identityKeys := map[string]string{}
	err := json.Unmarshal([]byte(identityKeysJSON), &identityKeys)
	if err != nil {
		panic(err)
	}
	return Ed25519(identityKeys["ed25519"]), Curve25519(identityKeys["curve25519"])
}

// Sign returns the signature of a message using the ed25519 key for this
// Account.
func (a *Account) Sign(message string) string {
	if len(message) == 0 {
		message = " "
	}
	signature := make([]byte, a.signatureLen())
	r := C.olm_account_sign(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)),
		unsafe.Pointer(&signature[0]),
		C.size_t(len(signature)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		return string(signature)
	}
}

// SignJSON signs the JSON object _obj following the Matrix specification:
// https://matrix.org/speculator/spec/drafts%2Fe2e/appendices.html#signing-json
// If the _obj is a struct, the `json` tags will be honored.
func (a *Account) SignJSON(_obj interface{}, userID, deviceID string) (interface{}, error) {
	s := structs.New(_obj)
	s.TagName = "json"
	obj := s.Map()
	_signatures, ok := obj["signatures"]
	if ok {
		delete(obj, "signatures")
	}
	signatures, ok := _signatures.(Signatures)
	if !ok {
		return nil, fmt.Errorf("signatures key of JSON object is an invalid type")
	}
	if signatures == nil {
		signatures = make(map[string]map[string]string)
	}
	unsigned, ok := obj["unsigned"]
	if ok {
		delete(obj, "unsigned")
	}
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("\n\n%v\n\n", obj)
	//fmt.Printf("\n\n%v\n\n", string(objJSON))
	signature := a.Sign(string(objJSON))
	algorithmDeviceID := fmt.Sprintf("ed25519:%s", deviceID)
	signatures[userID] = map[string]string{algorithmDeviceID: signature}
	obj["signatures"] = signatures
	if unsigned != nil {
		obj["unsigned"] = unsigned
	}

	return obj, nil
}

type OTKs struct {
	Curve25519 map[string]Curve25519 `json:"curve25519"`
}

// OneTimeKeys returns the public parts of the unpublished one time keys for
// the Account.
//
// The returned data is a struct with the single value "Curve25519", which is
// itself an object mapping key id to base64-encoded Curve25519 key.  For
// example:
// 	{
// 	    Curve25519: {
// 	        "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
// 	        "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
// 	    }
// 	}
func (a *Account) OneTimeKeys() OTKs {
	oneTimeKeysJSON := make([]byte, a.oneTimeKeysLen())
	r := C.olm_account_one_time_keys(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&oneTimeKeysJSON[0]),
		C.size_t(len(oneTimeKeysJSON)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		var oneTimeKeys OTKs
		err := json.Unmarshal(oneTimeKeysJSON, &oneTimeKeys)
		if err != nil {
			panic(err)
		}
		return oneTimeKeys
	}
}

// MarkKeysAsPublished marks the current set of one time keys as being
// published.
func (a *Account) MarkKeysAsPublished() {
	C.olm_account_mark_keys_as_published((*C.OlmAccount)(a))
}

// MaxNumberOfOneTimeKeys returns the largest number of one time keys this
// Account can store.
func (a *Account) MaxNumberOfOneTimeKeys() uint {
	return uint(C.olm_account_max_number_of_one_time_keys((*C.OlmAccount)(a)))
}

// GenOneTimeKeys generates a number of new one time keys.  If the total number
// of keys stored by this Account exceeds MaxNumberOfOneTimeKeys then the old
// keys are discarded.
func (a *Account) GenOneTimeKeys(num uint) {
	random := make([]byte, a.genOneTimeKeysRandomLen(num)+1)
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_account_generate_one_time_keys(
		(*C.OlmAccount)(a),
		C.size_t(num),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		panic(a.lastError())
	}
}

// NewOutboundSession creates a new out-bound session for sending messages to a
// given curve25519 identityKey and oneTimeKey.  Returns error on failure.  If the
// keys couldn't be decoded as base64 then the error will be "INVALID_BASE64"
func (a *Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey Curve25519) (*Session, error) {
	if len(theirIdentityKey) == 0 || len(theirOneTimeKey) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	s := newSession()
	random := make([]byte, s.createOutboundRandomLen()+1)
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_create_outbound_session(
		(*C.OlmSession)(s),
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(theirIdentityKey)[0])),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(theirOneTimeKey)[0])),
		C.size_t(len(theirOneTimeKey)),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// NewInboundSession creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message.  Returns error on failure.  If
// the base64 couldn't be decoded then the error will be "INVALID_BASE64".  If
// the message was for an unsupported protocol version then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then then the
// error will be "BAD_MESSAGE_FORMAT".  If the message refers to an unknown one
// time key then the error will be "BAD_MESSAGE_KEY_ID".
func (a *Account) NewInboundSession(oneTimeKeyMsg string) (*Session, error) {
	if len(oneTimeKeyMsg) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	s := newSession()
	r := C.olm_create_inbound_session(
		(*C.OlmSession)(s),
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg)[0])),
		C.size_t(len(oneTimeKeyMsg)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// NewInboundSessionFrom creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message.  Returns error on failure.  If
// the base64 couldn't be decoded then the error will be "INVALID_BASE64".  If
// the message was for an unsupported protocol version then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then then the
// error will be "BAD_MESSAGE_FORMAT".  If the message refers to an unknown one
// time key then the error will be "BAD_MESSAGE_KEY_ID".
func (a *Account) NewInboundSessionFrom(theirIdentityKey Curve25519, oneTimeKeyMsg string) (*Session, error) {
	if len(theirIdentityKey) == 0 || len(oneTimeKeyMsg) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	s := newSession()
	r := C.olm_create_inbound_session_from(
		(*C.OlmSession)(s),
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(theirIdentityKey)[0])),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg)[0])),
		C.size_t(len(oneTimeKeyMsg)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// RemoveOneTimeKeys removes the one time keys that the session used from the
// Account.  Returns error on failure.  If the Account doesn't have any
// matching one time keys then the error will be "BAD_MESSAGE_KEY_ID".
func (a *Account) RemoveOneTimeKeys(s *Session) error {
	r := C.olm_remove_one_time_keys(
		(*C.OlmAccount)(a),
		(*C.OlmSession)(s))
	if r == errorVal() {
		return a.lastError()
	} else {
		return nil
	}
}

// Utility stores the necessary state to perform hash and signature
// verification operations.
type Utility C.OlmUtility

// utilitySize returns the size of a utility object in bytes.
func utilitySize() uint {
	return uint(C.olm_utility_size())
}

// sha256Len returns the length of the buffer needed to hold the SHA-256 hash.
func (u *Utility) sha256Len() uint {
	return uint(C.olm_sha256_length((*C.OlmUtility)(u)))
}

// lastError returns an error describing the most recent error to happen to a
// utility.
func (u *Utility) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_utility_last_error((*C.OlmUtility)(u))))
}

// Clear clears the memory used to back this utility.
func (u *Utility) Clear() error {
	r := C.olm_clear_utility((*C.OlmUtility)(u))
	if r == errorVal() {
		return u.lastError()
	} else {
		return nil
	}
}

// NewUtility creates a new utility.
func NewUtility() *Utility {
	memory := make([]byte, utilitySize())
	//(*C.OlmAccount)(a).memory = unsafe.Pointer(&memory[0])
	return (*Utility)(C.olm_utility(unsafe.Pointer(&memory[0])))
}

// Sha256 calculates the SHA-256 hash of the input and encodes it as base64.
func (u *Utility) Sha256(input string) string {
	if len(input) == 0 {
		input = " "
	}
	output := make([]byte, u.sha256Len())
	r := C.olm_sha256(
		(*C.OlmUtility)(u),
		unsafe.Pointer(&([]byte(input)[0])),
		C.size_t(len(input)),
		unsafe.Pointer(&([]byte(output)[0])),
		C.size_t(len(output)))
	if r == errorVal() {
		panic(u.lastError())
	} else {
		return string(output)
	}
}

// VerifySignature verifies an ed25519 signature.  Returns true if the verification
// suceeds or false otherwise.  Returns error on failure.  If the key was too
// small then the error will be "INVALID_BASE64".
func (u *Utility) VerifySignature(message string, key Ed25519, signature string) (bool, error) {
	if len(message) == 0 || len(key) == 0 || len(signature) == 0 {
		return false, fmt.Errorf("Empty input")
	}
	r := C.olm_ed25519_verify(
		(*C.OlmUtility)(u),
		unsafe.Pointer(&([]byte(key)[0])),
		C.size_t(len(key)),
		unsafe.Pointer(&([]byte(message)[0])),
		C.size_t(len(message)),
		unsafe.Pointer(&([]byte(signature)[0])),
		C.size_t(len(signature)))
	if r == errorVal() {
		err := u.lastError()
		if err.Error() == "BAD_MESSAGE_MAC" {
			return false, nil
		} else {
			return false, u.lastError()
		}
	} else {
		return true, nil
	}
}

// VerifySignatureJSON verifies the signature in the JSON object _obj following
// the Matrix specification:
// https://matrix.org/speculator/spec/drafts%2Fe2e/appendices.html#signing-json
// If the _obj is a struct, the `json` tags will be honored.
func (u *Utility) VerifySignatureJSON(_obj interface{}, userID, deviceID string, key Ed25519) (bool, error) {
	s := structs.New(_obj)
	s.TagName = "json"
	obj := s.Map()
	_signatures, ok := obj["signatures"]
	if !ok {
		return false, fmt.Errorf("JSON object doesn't contain signatures key")
	}
	signatures, ok := _signatures.(map[string]map[string]string)
	if !ok {
		return false, fmt.Errorf("signatures key of JSON object is an invalid type")
	}
	signatureDevices, ok := signatures[userID]
	if !ok {
		return false, fmt.Errorf("JSON object isn't signed by user %s", userID)
	}
	signature, ok := signatureDevices[fmt.Sprintf("ed25519:%s", deviceID)]
	if !ok {
		return false, fmt.Errorf("JSON object isn't signed by user's device %s", deviceID)
	}
	delete(obj, "unsigned")
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return false, err
	}
	return u.VerifySignature(string(objJSON), key, signature)
}

// VerifySignatureJSON verifies the signature in the JSON object _obj following
// the Matrix specification:
// https://matrix.org/speculator/spec/drafts%2Fe2e/appendices.html#signing-json
// This function is a wrapper over Utility.VerifySignatureJSON that creates and
// destroys the Utility object transparently.
// If the _obj is a struct, the `json` tags will be honored.
func VerifySignatureJSON(_obj interface{}, userID, deviceID string, key Ed25519) (bool, error) {
	u := NewUtility()
	defer u.Clear()
	return u.VerifySignatureJSON(_obj, userID, deviceID, key)
}

// OutboundGroupSession stores an outbound encrypted messaging session for a
// group.
type OutboundGroupSession C.OlmOutboundGroupSession

// outboundGroupSessionSize is the size of an outbound group session object in
// bytes.
func outboundGroupSessionSize() uint {
	return uint(C.olm_outbound_group_session_size())
}

// newOutboundGroupSession initialises an empty OutboundGroupSession.
func newOutboundGroupSession() *OutboundGroupSession {
	memory := make([]byte, outboundGroupSessionSize())
	return (*OutboundGroupSession)(C.olm_outbound_group_session(unsafe.Pointer(&memory[0])))
}

// lastError returns an error describing the most recent error to happen to an
// outbound group session.
func (s *OutboundGroupSession) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_outbound_group_session_last_error((*C.OlmOutboundGroupSession)(s))))
}

// Clear clears the memory used to back this OutboundGroupSession.
func (s *OutboundGroupSession) Clear() error {
	r := C.olm_clear_outbound_group_session((*C.OlmOutboundGroupSession)(s))
	if r == errorVal() {
		return s.lastError()
	} else {
		return nil
	}
}

// pickleLen returns the number of bytes needed to store an outbound group
// session.
func (s *OutboundGroupSession) pickleLen() uint {
	return uint(C.olm_pickle_outbound_group_session_length((*C.OlmOutboundGroupSession)(s)))
}

// Pickle returns an OutboundGroupSession as a base64 string.  Encrypts the
// OutboundGroupSession using the supplied key.
func (s *OutboundGroupSession) Pickle(key []byte) string {
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_outbound_group_session(
		(*C.OlmOutboundGroupSession)(s),
		unsafe.Pointer(&key[0]),
		//unsafe.Pointer(key),
		C.size_t(lenKey),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return string(pickled[:r])
	}
}

// OutboundGroupSessionFromPickled loads an OutboundGroupSession from a pickled
// base64 string.  Decrypts the OutboundGroupSession using the supplied key.
// Returns error on failure.  If the key doesn't match the one used to encrypt
// the OutboundGroupSession then the error will be "BAD_SESSION_KEY".  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".
func OutboundGroupSessionFromPickled(pickled string, key []byte) (*OutboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	s := newOutboundGroupSession()
	r := C.olm_unpickle_outbound_group_session(
		(*C.OlmOutboundGroupSession)(s),
		unsafe.Pointer(&key[0]),
		C.size_t(lenKey),
		unsafe.Pointer(&([]byte(pickled))[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// createRandomLen returns the number of random bytes needed to create an
// Account.
func (s *OutboundGroupSession) createRandomLen() uint {
	return uint(C.olm_init_outbound_group_session_random_length((*C.OlmOutboundGroupSession)(s)))
}

// NewOutboundGroupSession creates a new outbound group session.
func NewOutboundGroupSession() *OutboundGroupSession {
	s := newOutboundGroupSession()
	random := make([]byte, s.createRandomLen()+1)
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_init_outbound_group_session(
		(*C.OlmOutboundGroupSession)(s),
		(*C.uint8_t)(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return s
	}
}

// encryptMsgLen returns the size of the next message in bytes for the given
// number of plain-text bytes.
func (s *OutboundGroupSession) encryptMsgLen(plainTextLen int) uint {
	return uint(C.olm_group_encrypt_message_length((*C.OlmOutboundGroupSession)(s), C.size_t(plainTextLen)))
}

// Encrypt encrypts a message using the Session.  Returns the encrypted message
// as base64.
func (s *OutboundGroupSession) Encrypt(plaintext string) string {
	if len(plaintext) == 0 {
		plaintext = " "
	}
	message := make([]byte, s.encryptMsgLen(len(plaintext)))
	r := C.olm_group_encrypt(
		(*C.OlmOutboundGroupSession)(s),
		(*C.uint8_t)(&([]byte(plaintext))[0]),
		C.size_t(len(plaintext)),
		(*C.uint8_t)(&([]byte(message))[0]),
		C.size_t(len(message)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return string(message[:r])
	}
}

// sessionIdLen returns the number of bytes needed to store a session ID.
func (s *OutboundGroupSession) sessionIdLen() uint {
	return uint(C.olm_outbound_group_session_id_length((*C.OlmOutboundGroupSession)(s)))
}

// ID returns a base64-encoded identifier for this session.
func (s *OutboundGroupSession) ID() SessionID {
	sessionId := make([]byte, s.sessionIdLen())
	r := C.olm_outbound_group_session_id(
		(*C.OlmOutboundGroupSession)(s),
		(*C.uint8_t)(&sessionId[0]),
		C.size_t(len(sessionId)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return SessionID(sessionId[:r])
	}
}

// MessageIndex returns the message index for this session.  Each message is
// sent with an increasing index; this returns the index for the next message.
func (s *OutboundGroupSession) MessageIndex() uint {
	return uint(C.olm_outbound_group_session_message_index((*C.OlmOutboundGroupSession)(s)))
}

// sessionKeyLen returns the number of bytes needed to store a session key.
func (s *OutboundGroupSession) sessionKeyLen() uint {
	return uint(C.olm_outbound_group_session_key_length((*C.OlmOutboundGroupSession)(s)))
}

// SessionKey returns the base64-encoded current ratchet key for this session.
func (s *OutboundGroupSession) SessionKey() string {
	sessionKey := make([]byte, s.sessionKeyLen())
	r := C.olm_outbound_group_session_key(
		(*C.OlmOutboundGroupSession)(s),
		(*C.uint8_t)(&sessionKey[0]),
		C.size_t(len(sessionKey)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return string(sessionKey[:r])
	}
}

// InboundGroupSession stores an inbound encrypted messaging session for a
// group.
type InboundGroupSession C.OlmInboundGroupSession

// inboundGroupSessionSize is the size of an inbound group session object in
// bytes.
func inboundGroupSessionSize() uint {
	return uint(C.olm_inbound_group_session_size())
}

// newInboundGroupSession initialises an empty InboundGroupSession.
func newInboundGroupSession() *InboundGroupSession {
	memory := make([]byte, inboundGroupSessionSize())
	return (*InboundGroupSession)(C.olm_inbound_group_session(unsafe.Pointer(&memory[0])))
}

// lastError returns an error describing the most recent error to happen to an
// inbound group session.
func (s *InboundGroupSession) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_inbound_group_session_last_error((*C.OlmInboundGroupSession)(s))))
}

// Clear clears the memory used to back this InboundGroupSession.
func (s *InboundGroupSession) Clear() error {
	r := C.olm_clear_inbound_group_session((*C.OlmInboundGroupSession)(s))
	if r == errorVal() {
		return s.lastError()
	} else {
		return nil
	}
}

// pickleLen returns the number of bytes needed to store an inbound group
// session.
func (s *InboundGroupSession) pickleLen() uint {
	return uint(C.olm_pickle_inbound_group_session_length((*C.OlmInboundGroupSession)(s)))
}

// Pickle returns an InboundGroupSession as a base64 string.  Encrypts the
// InboundGroupSession using the supplied key.
func (s *InboundGroupSession) Pickle(key []byte) string {
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_inbound_group_session(
		(*C.OlmInboundGroupSession)(s),
		unsafe.Pointer(&key[0]),
		//unsafe.Pointer(key),
		C.size_t(lenKey),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return string(pickled[:r])
	}
}

// InboundGroupSessionFromPickled loads an InboundGroupSession from a pickled
// base64 string.  Decrypts the InboundGroupSession using the supplied key.
// Returns error on failure.  If the key doesn't match the one used to encrypt
// the InboundGroupSession then the error will be "BAD_SESSION_KEY".  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".
func InboundGroupSessionFromPickled(pickled string, key []byte) (*InboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	s := newInboundGroupSession()
	r := C.olm_unpickle_inbound_group_session(
		(*C.OlmInboundGroupSession)(s),
		unsafe.Pointer(&key[0]),
		C.size_t(lenKey),
		unsafe.Pointer(&([]byte(pickled))[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// NewInboundGroupSession creates a new inbound group session from a key
// exported from OutboundGroupSession.SessionKey().  Returns error on failure.
// If the sessionKey is not valid base64 the error will be
// "OLM_INVALID_BASE64".  If the session_key is invalid the error will be
// "OLM_BAD_SESSION_KEY".
func NewInboundGroupSession(sessionKey []byte) (*InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		sessionKey = []byte(" ")
	}
	s := newInboundGroupSession()
	r := C.olm_init_inbound_group_session(
		(*C.OlmInboundGroupSession)(s),
		(*C.uint8_t)(&sessionKey[0]),
		C.size_t(len(sessionKey)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// InboundGroupSessionImport imports an inbound group session from a previous
// export.  Returns error on failure.  If the sessionKey is not valid base64
// the error will be "OLM_INVALID_BASE64".  If the session_key is invalid the
// error will be "OLM_BAD_SESSION_KEY".
func InboundGroupSessionImport(sessionKey []byte) (*InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		sessionKey = []byte(" ")
	}
	s := newInboundGroupSession()
	r := C.olm_import_inbound_group_session(
		(*C.OlmInboundGroupSession)(s),
		(*C.uint8_t)(&sessionKey[0]),
		C.size_t(len(sessionKey)))
	if r == errorVal() {
		return nil, s.lastError()
	} else {
		return s, nil
	}
}

// decryptMaxPlaintextLen returns the maximum number of bytes of plain-text a
// given message could decode to.  The actual size could be different due to
// padding.  Returns error on failure.  If the message base64 couldn't be
// decoded then the error will be "INVALID_BASE64".  If the message is for an
// unsupported version of the protocol then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then the error
// will be "BAD_MESSAGE_FORMAT".
func (s *InboundGroupSession) decryptMaxPlaintextLen(message string) (uint, error) {
	if len(message) == 0 {
		return 0, fmt.Errorf("Empty input")
	}
	r := C.olm_group_decrypt_max_plaintext_length(
		(*C.OlmInboundGroupSession)(s),
		(*C.uint8_t)(&([]byte(message))[0]),
		C.size_t(len(message)))
	if r == errorVal() {
		return 0, s.lastError()
	} else {
		return uint(r), nil
	}
}

// Decrypt decrypts a message using the InboundGroupSession.  Returns the the
// plain-text and message index on success.  Returns error on failure.  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".  If the
// message is for an unsupported version of the protocol then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then the error
// will be BAD_MESSAGE_FORMAT".  If the MAC on the message was invalid then the
// error will be "BAD_MESSAGE_MAC".  If we do not have a session key
// corresponding to the message's index (ie, it was sent before the session key
// was shared with us) the error will be "OLM_UNKNOWN_MESSAGE_INDEX".
func (s *InboundGroupSession) Decrypt(message string) (string, uint32, error) {
	if len(message) == 0 {
		return "", 0, fmt.Errorf("Empty input")
	}
	decryptMaxPlaintextLen, err := s.decryptMaxPlaintextLen(message)
	if err != nil {
		return "", 0, err
	}
	plaintext := make([]byte, decryptMaxPlaintextLen)
	var messageIndex uint32
	r := C.olm_group_decrypt(
		(*C.OlmInboundGroupSession)(s),
		(*C.uint8_t)(&([]byte(message))[0]),
		C.size_t(len(message)),
		(*C.uint8_t)(&([]byte(plaintext))[0]),
		C.size_t(len(plaintext)),
		(*C.uint32_t)(&messageIndex))
	if r == errorVal() {
		return "", 0, s.lastError()
	} else {
		return string(plaintext[:r]), messageIndex, nil
	}
}

// sessionIdLen returns the number of bytes needed to store a session ID.
func (s *InboundGroupSession) sessionIdLen() uint {
	return uint(C.olm_inbound_group_session_id_length((*C.OlmInboundGroupSession)(s)))
}

// ID returns a base64-encoded identifier for this session.
func (s *InboundGroupSession) ID() SessionID {
	sessionId := make([]byte, s.sessionIdLen())
	r := C.olm_inbound_group_session_id(
		(*C.OlmInboundGroupSession)(s),
		(*C.uint8_t)(&sessionId[0]),
		C.size_t(len(sessionId)))
	if r == errorVal() {
		panic(s.lastError())
	} else {
		return SessionID(sessionId[:r])
	}
}

// FirstKnownIndex returns the first message index we know how to decrypt.
func (s *InboundGroupSession) FirstKnownIndex() uint {
	return uint(C.olm_inbound_group_session_first_known_index((*C.OlmInboundGroupSession)(s)))
}

// IsVerified check if the session has been verified as a valid session.  (A
// session is verified either because the original session share was signed, or
// because we have subsequently successfully decrypted a message.)
func (s *InboundGroupSession) IsVerified() uint {
	return uint(C.olm_inbound_group_session_is_verified((*C.OlmInboundGroupSession)(s)))
}

// exportLen returns the number of bytes needed to export an inbound group
// session.
func (s *InboundGroupSession) exportLen() uint {
	return uint(C.olm_export_inbound_group_session_length((*C.OlmInboundGroupSession)(s)))
}

// Export returns the base64-encoded ratchet key for this session, at the given
// index, in a format which can be used by
// InboundGroupSession.InboundGroupSessionImport().  Encrypts the
// InboundGroupSession using the supplied key.  Returns error on failure.
// if we do not have a session key corresponding to the given index (ie, it was
// sent before the session key was shared with us) the error will be
// "OLM_UNKNOWN_MESSAGE_INDEX".
func (s *InboundGroupSession) Export(messageIndex uint32) (string, error) {
	key := make([]byte, s.exportLen())
	r := C.olm_export_inbound_group_session(
		(*C.OlmInboundGroupSession)(s),
		(*C.uint8_t)(&key[0]),
		C.size_t(len(key)),
		C.uint32_t(messageIndex))
	if r == errorVal() {
		return "", s.lastError()
	} else {
		return string(key[:r]), nil
	}
}

// NOTE: Is the megolm class even used anywhere?
//
// // Megolm stores the Megolm multi-part ratchet used in group chats.
// type Megolm C.Megolm
//
// // NewMegolm creates a new Megolm ratchet.
// func NewMegolm() *Megolm {
// 	var m Megolm
// 	random := make([]byte, C.MEGOLM_RATCHET_PART_LENGTH+1)
// 	_, err := crand.Read(random)
// 	if err != nil {
// 		panic("Couldn't get enough randomness from crypto/rand")
// 	}
// 	C.megolm_init(
// 		(*C.Megolm)(&m),
// 		(*C.uint8_t)(&random[0]),
// 		(C.uint32_t)(0))
// 	return &m
// }
//
// // pickleLen returns the number of bytes needed to store a megolm.
// func (m *Megolm) pickleLen() uint {
// 	return uint(C.megolm_pickle_length((*C.Megolm)(m)))
// }
