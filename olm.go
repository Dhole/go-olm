package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	crand "crypto/rand"
	"fmt"
	"unsafe"
)

// Version returns the version number of the olm library.
func Version() (major, minor, patch byte) {
	C.olm_get_library_version(
		(*C.uint8_t)(&major),
		(*C.uint8_t)(&minor),
		(*C.uint8_t)(&patch))
	return
}

// Error returns the value that olm functions return if there was an error.
func Error() C.size_t {
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
	if r == Error() {
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
	r := C.olm_decrypt_max_plaintext_length(
		(*C.OlmSession)(s),
		C.size_t(msgType),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)))
	if r == Error() {
		return 0, s.lastError()
	} else {
		return uint(r), nil
	}
}

// Pickle returns a Session as a base64 string.  Encrypts the Session using the
// supplied key.
func (s *Session) Pickle(key []byte) string {
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&key[0]),
		//unsafe.Pointer(key),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == Error() {
		panic(s.lastError())
	} else {
		return string(pickled)
	}
}

// Id returns an identifier for this Session.  Will be the same for both ends
// of the conversation.
func (s *Session) Id() string {
	id := make([]byte, s.idLen())
	r := C.olm_session_id(
		(*C.OlmSession)(s),
		unsafe.Pointer(&id[0]),
		C.size_t(len(id)))
	if r == Error() {
		panic(s.lastError())
	} else {
		return string(id)
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
	r := C.olm_matches_inbound_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg))[0]),
		C.size_t(len(oneTimeKeyMsg)))
	if r == 1 {
		return true, nil
	} else if r == 0 {
		return false, nil
	} else { // if r == Error()
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
	} else { // if r == Error()
		return false, s.lastError()
	}
}

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
func (s *Session) EncryptMsgType() (MsgType, error) {
	switch C.olm_encrypt_message_type((*C.OlmSession)(s)) {
	case C.size_t(MsgTypePreKey):
		return MsgTypePreKey, nil
	case C.size_t(MsgTypeMsg):
		return MsgTypeMsg, nil
	default:
		//panic("olm_encrypt_message_type returned invalid result")
		return MsgTypePreKey, s.lastError()
	}
}

// Encrypt encrypts a message using the Session.  Returns the encrypted message
// as base64.
func (s *Session) Encrypt(plaintext string) string {
	random := make([]byte, s.encryptRandomLen())
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	message := make([]byte, s.encryptMsgLen(len(plaintext)))
	r := C.olm_encrypt(
		(*C.OlmSession)(s),
		unsafe.Pointer(&([]byte(plaintext))[0]),
		C.size_t(len(plaintext)),
		unsafe.Pointer(&(random)[0]),
		C.size_t(len(random)),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)))
	if r == Error() {
		panic(s.lastError())
	} else {
		return string(message)
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
	if r == Error() {
		return "", s.lastError()
	} else {
		return string(plaintext), nil
	}
}

// SessionFromPickled loads a Session from a pickled base64 string.  Decrypts
// the Session using the supplied key.  Returns error on failure.  If the key
// doesn't match the one used to encrypt the Session then the error will be
// "BAD_SESSION_KEY".  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".
func SessionFromPickled(pickled string, key []byte) (*Session, error) {
	s := newSession()
	r := C.olm_unpickle_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&([]byte(pickled))[0]),
		C.size_t(len(pickled)))
	if r == Error() {
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
	if r == Error() {
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
	pickled := make([]byte, a.pickleLen())
	r := C.olm_pickle_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == Error() {
		panic(a.lastError())
	} else {
		return string(pickled)
	}
}

// AccountFromPickled loads an Account from a pickled base64 string.  Decrypts
// the Account using the supplied key.  Returns error on failure.  If the key
// doesn't match the one used to encrypt the Account then the error will be
// "BAD_ACCOUNT_KEY".  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".
func AccountFromPickled(pickled string, key []byte) (*Account, error) {
	//var a *Account
	a := newAccount()
	r := C.olm_unpickle_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&([]byte(pickled))[0]),
		C.size_t(len(pickled)))
	if r == Error() {
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
	random := make([]byte, a.createRandomLen())
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_create_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == Error() {
		panic(a.lastError())
	} else {
		return a
	}
}

// IdentityKeys returns the public parts of the identity keys for the Account.
func (a *Account) IdentityKeys() string {
	identityKeys := make([]byte, a.identityKeysLen())
	r := C.olm_account_identity_keys(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&identityKeys[0]),
		C.size_t(len(identityKeys)))
	if r == Error() {
		panic(a.lastError())
	} else {
		return string(identityKeys)
	}
}

// Sign returns the signature of a message using the ed25519 key for this
// Account.
func (a *Account) Sign(message string) string {
	signature := make([]byte, a.signatureLen())
	r := C.olm_account_sign(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)),
		unsafe.Pointer(&signature[0]),
		C.size_t(len(signature)))
	if r == Error() {
		panic(a.lastError())
	} else {
		return string(signature)
	}
}

// OneTimeKeys returns the public parts of the unpublished one time keys for
// the Account.
//
// The returned data is a JSON-formatted object with the single property
// "curve25519", which is itself an object mapping key id to base64-encoded
// Curve25519 key.  For example:
// 	{
// 	    curve25519: {
// 	        "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
// 	        "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
// 	    }
// 	}
func (a *Account) OneTimeKeys() string {
	oneTimeKeys := make([]byte, a.oneTimeKeysLen())
	r := C.olm_account_one_time_keys(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&oneTimeKeys[0]),
		C.size_t(len(oneTimeKeys)))
	if r == Error() {
		panic(a.lastError())
	} else {
		return string(oneTimeKeys)
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
	random := make([]byte, a.genOneTimeKeysRandomLen(num))
	_, err := crand.Read(random)
	if err != nil {
		panic("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_account_generate_one_time_keys(
		(*C.OlmAccount)(a),
		C.size_t(num),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == Error() {
		panic(a.lastError())
	}
}

// NewOutboundSession creates a new out-bound session for sending messages to a
// given identityKey and oneTimeKey.  Returns error on failure.  If the keys
// couldn't be decoded as base64 then the error will be "INVALID_BASE64"
func (a *Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey string) (*Session, error) {
	s := newSession()
	random := make([]byte, s.createOutboundRandomLen())
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
	if r == Error() {
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
	s := newSession()
	r := C.olm_create_inbound_session(
		(*C.OlmSession)(s),
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg)[0])),
		C.size_t(len(oneTimeKeyMsg)))
	if r == Error() {
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
func (a *Account) NewInboundSessionFrom(theirIdentityKey, oneTimeKeyMsg string) (*Session, error) {
	s := newSession()
	r := C.olm_create_inbound_session_from(
		(*C.OlmSession)(s),
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(theirIdentityKey)[0])),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg)[0])),
		C.size_t(len(oneTimeKeyMsg)))
	if r == Error() {
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
	if r == Error() {
		return a.lastError()
	} else {
		return nil
	}
}

// Session stores the necessary state to perform hash and signature
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
	return fmt.Errorf("%s", C.olm_utility_last_error((*C.OlmUtility)(u)))
}

// Clear clears the memory used to back this utility.
func (u *Utility) Clear() error {
	r := C.olm_clear_utility((*C.OlmUtility)(u))
	if r == Error() {
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
	output := make([]byte, u.sha256Len())
	r := C.olm_sha256(
		(*C.OlmUtility)(u),
		unsafe.Pointer(&([]byte(input)[0])),
		C.size_t(len(input)),
		unsafe.Pointer(&([]byte(output)[0])),
		C.size_t(len(output)))
	if r == Error() {
		panic(u.lastError())
	} else {
		return string(output)
	}
}

// Ed25519 verifies an ed25519 signature.  Returns true if the verification
// suceeds or false otherwise.  Returns error on failure.  If the key was too
// small then the error will be "INVALID_BASE64".
func (u *Utility) Ed25519Verify(message, key, signature string) (bool, error) {
	r := C.olm_ed25519_verify(
		(*C.OlmUtility)(u),
		unsafe.Pointer(&([]byte(key)[0])),
		C.size_t(len(key)),
		unsafe.Pointer(&([]byte(message)[0])),
		C.size_t(len(message)),
		unsafe.Pointer(&([]byte(signature)[0])),
		C.size_t(len(signature)))
	if r == Error() {
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
