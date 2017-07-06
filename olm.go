package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	crand "crypto/rand"
	"fmt"
	"unsafe"
)

/** Get the version number of the library.
 * Arguments will be updated if non-null.
 */
func Version() (major, minor, patch byte) {
	C.olm_get_library_version(
		(*C.uint8_t)(&major),
		(*C.uint8_t)(&minor),
		(*C.uint8_t)(&patch))
	return
}

/** The value that olm will return from a function if there was an error */
func Error() C.size_t {
	return C.olm_error()
}

type Session C.OlmSession

/** The size of a session object in bytes */
func sessionSize() uint {
	return uint(C.olm_session_size())
}

/** A null terminated string describing the most recent error to happen to a
 * session */
func (s *Session) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_session_last_error((*C.OlmSession)(s))))
}

/** Clears the memory used to back this session */
func (s *Session) Clear() error {
	r := C.olm_clear_session((*C.OlmSession)(s))
	if r == Error() {
		return s.lastError()
	} else {
		return nil
	}
}

/** Returns the number of bytes needed to store a session */
func (s *Session) pickleLen() uint {
	return uint(C.olm_pickle_session_length((*C.OlmSession)(s)))
}

/** The number of random bytes needed to create an outbound session */
func (s *Session) createOutboundRandomLen() uint {
	return uint(C.olm_create_outbound_session_random_length((*C.OlmSession)(s)))
}

/** The length of the buffer needed to return the id for this session. */
func (s *Session) idLen() uint {
	return uint(C.olm_session_id_length((*C.OlmSession)(s)))
}

/** The number of random bytes needed to encrypt the next message. */
func (s *Session) encryptRandomLen() uint {
	return uint(C.olm_encrypt_random_length((*C.OlmSession)(s)))
}

/** The size of the next message in bytes for the given number of plain-text
 * bytes. */
func (s *Session) encryptMsgLen(plainTextLen int) uint {
	return uint(C.olm_encrypt_message_length((*C.OlmSession)(s), C.size_t(plainTextLen)))
}

/** The maximum number of bytes of plain-text a given message could decode to.
 * The actual size could be different due to padding. The input message buffer
 * is destroyed. Returns olm_error() on failure. If the message base64
 * couldn't be decoded then olm_session_last_error() will be
 * "INVALID_BASE64". If the message is for an unsupported version of the
 * protocol then olm_session_last_error() will be "BAD_MESSAGE_VERSION".
 * If the message couldn't be decoded then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
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

/** Stores a session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the pickled session on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_session_length() then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
func (s *Session) Pickle(key []byte) (string, error) {
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_session(
		(*C.OlmSession)(s),
		unsafe.Pointer(&key[0]),
		//unsafe.Pointer(key),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == Error() {
		return "", s.lastError()
	} else {
		return string(pickled), nil
	}
}

/** An identifier for this session. Will be the same for both ends of the
 * conversation. If the id buffer is too small then olm_session_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". */
func (s *Session) Id() (string, error) {
	id := make([]byte, s.idLen())
	r := C.olm_session_id(
		(*C.OlmSession)(s),
		unsafe.Pointer(&id[0]),
		C.size_t(len(id)))
	if r == Error() {
		return "", s.lastError()
	} else {
		return string(id), nil
	}
}

// ???
func (s *Session) HasReceivedMessage() int {
	return int(C.olm_session_has_received_message((*C.OlmSession)(s)))
}

/** Checks if the PRE_KEY message is for this in-bound session. This can happen
 * if multiple messages are sent to this account before this account sends a
 * message in reply. Returns 1 if the session matches. Returns 0 if the session
 * does not match. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
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

/** Checks if the PRE_KEY message is for this in-bound session. This can happen
 * if multiple messages are sent to this account before this account sends a
 * message in reply. Returns 1 if the session matches. Returns 0 if the session
 * does not match. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
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

/** The type of the next message that olm_encrypt() will return. Returns
 * OLM_MESSAGE_TYPE_PRE_KEY if the message will be a PRE_KEY message.
 * Returns OLM_MESSAGE_TYPE_MESSAGE if the message will be a normal message.
 * Returns olm_error on failure. */
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

/** Encrypts a message using the session. Returns the length of the message in
 * bytes on success. Writes the message as base64 into the message buffer.
 * Returns olm_error() on failure. If the message buffer is too small then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". If there
 * weren't enough random bytes then olm_session_last_error() will be
 * "NOT_ENOUGH_RANDOM". */
func (s *Session) Encrypt(plaintext string) (string, error) {
	random := make([]byte, s.encryptRandomLen())
	_, err := crand.Read(random)
	if err != nil {
		return "", fmt.Errorf("Couldn't get enough randomness from crypto/rand")
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
		return "", s.lastError()
	} else {
		return string(message), nil
	}
}

/** Decrypts a message using the session. The input message buffer is destroyed.
 * Returns the length of the plain-text on success. Returns olm_error() on
 * failure. If the plain-text buffer is smaller than
 * olm_decrypt_max_plaintext_length() then olm_session_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". If the base64 couldn't be decoded then
 * olm_session_last_error() will be "INVALID_BASE64". If the message is for
 * an unsupported version of the protocol then olm_session_last_error() will
 *  be "BAD_MESSAGE_VERSION". If the message couldn't be decoded then
 *  olm_session_last_error() will be BAD_MESSAGE_FORMAT".
 *  If the MAC on the message was invalid then olm_session_last_error() will
 *  be "BAD_MESSAGE_MAC". */
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

/** Loads a session from a pickled base64 string. Decrypts the session using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_session_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_session_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
func SessionFromPickled(pickled string, key []byte) (*Session, error) {
	//var s *Session
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

/** Initialise a session object using the supplied memory
 *  The supplied memory must be at least olm_session_size() bytes */
func newSession() *Session {
	memory := make([]byte, sessionSize())
	//(*C.OlmAccount)(a).memory = unsafe.Pointer(&memory[0])
	return (*Session)(C.olm_session(unsafe.Pointer(&memory[0])))
}

type Account C.OlmAccount

/** The size of an account object in bytes */
func accountSize() uint {
	return uint(C.olm_account_size())
}

/** A null terminated string describing the most recent error to happen to an
 * account */
func (a *Account) lastError() error {
	return fmt.Errorf("%s", C.GoString(C.olm_account_last_error((*C.OlmAccount)(a))))
}

/** Clears the memory used to back this account */
func (a *Account) Clear() error {
	r := C.olm_clear_account((*C.OlmAccount)(a))
	if r == Error() {
		return a.lastError()
	} else {
		return nil
	}
}

/** Returns the number of bytes needed to store an account */
func (a *Account) pickleLen() uint {
	return uint(C.olm_pickle_account_length((*C.OlmAccount)(a)))
}

/** The number of random bytes needed to create an account.*/
func (a *Account) createRandomLen() uint {
	return uint(C.olm_create_account_random_length((*C.OlmAccount)(a)))
}

/** The size of the output buffer needed to hold the identity keys */
func (a *Account) identityKeysLen() uint {
	return uint(C.olm_account_identity_keys_length((*C.OlmAccount)(a)))
}

/** The length of an ed25519 signature encoded as base64. */
func (a *Account) signatureLen() uint {
	return uint(C.olm_account_signature_length((*C.OlmAccount)(a)))
}

/** The size of the output buffer needed to hold the one time keys */
func (a *Account) oneTimeKeysLen() uint {
	return uint(C.olm_account_one_time_keys_length((*C.OlmAccount)(a)))
}

/** The number of random bytes needed to generate a given number of new one
 * time keys. */
func (a *Account) genOneTimeKeysRandomLen(num uint) uint {
	return uint(C.olm_account_generate_one_time_keys_random_length(
		(*C.OlmAccount)(a),
		C.size_t(num)))
}

/** Stores an account as a base64 string. Encrypts the account using the
 * supplied key. Returns the length of the pickled account on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_account_length() then
 * olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
func (a *Account) Pickle(key []byte) (string, error) {
	pickled := make([]byte, a.pickleLen())
	r := C.olm_pickle_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == Error() {
		return "", a.lastError()
	} else {
		return string(pickled), nil
	}
}

/** Loads an account from a pickled base64 string. Decrypts the account using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_account_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_account_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
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

/** Initialise an account object using the supplied memory
 *  The supplied memory must be at least olm_account_size() bytes */
func newAccount() *Account {
	memory := make([]byte, accountSize())
	//(*C.OlmAccount)(a).memory = unsafe.Pointer(&memory[0])
	return (*Account)(C.olm_account(unsafe.Pointer(&memory[0])))
}

/** Creates a new account. Returns olm_error() on failure. If weren't
 * enough random bytes then olm_account_last_error() will be
 * "NOT_ENOUGH_RANDOM" */
func NewAccount() (*Account, error) {
	//var a *Account
	a := newAccount()
	random := make([]byte, a.createRandomLen())
	_, err := crand.Read(random)
	if err != nil {
		return nil, fmt.Errorf("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_create_account(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == Error() {
		return nil, a.lastError()
	} else {
		return a, nil
	}
}

/** Writes the public parts of the identity keys for the account into the
 * identity_keys output buffer. Returns olm_error() on failure. If the
 * identity_keys buffer was too small then olm_account_last_error() will be
 * "OUTPUT_BUFFER_TOO_SMALL". */
func (a *Account) IdentityKeys() (string, error) {
	identityKeys := make([]byte, a.identityKeysLen())
	r := C.olm_account_identity_keys(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&identityKeys[0]),
		C.size_t(len(identityKeys)))
	if r == Error() {
		return "", a.lastError()
	} else {
		return string(identityKeys), nil
	}
}

/** Signs a message with the ed25519 key for this account. Returns olm_error()
 * on failure. If the signature buffer was too small then
 * olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
func (a *Account) Sign(message string) (string, error) {
	signature := make([]byte, a.signatureLen())

	r := C.olm_account_sign(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&([]byte(message))[0]),
		C.size_t(len(message)),
		unsafe.Pointer(&signature[0]),
		C.size_t(len(signature)))
	if r == Error() {
		return "", a.lastError()
	} else {
		return string(signature), nil
	}
}

/** Writes the public parts of the unpublished one time keys for the account
 * into the one_time_keys output buffer.
 * <p>
 * The returned data is a JSON-formatted object with the single property
 * <tt>curve25519</tt>, which is itself an object mapping key id to
 * base64-encoded Curve25519 key. For example:
 * <pre>
 * {
 *     curve25519: {
 *         "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
 *         "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
 *     }
 * }
 * </pre>
 * Returns olm_error() on failure.
 * <p>
 * If the one_time_keys buffer was too small then olm_account_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". */
func (a *Account) OneTimeKeys() (string, error) {
	oneTimeKeys := make([]byte, a.oneTimeKeysLen())
	r := C.olm_account_one_time_keys(
		(*C.OlmAccount)(a),
		unsafe.Pointer(&oneTimeKeys[0]),
		C.size_t(len(oneTimeKeys)))
	if r == Error() {
		return "", a.lastError()
	} else {
		return string(oneTimeKeys), nil
	}
}

/** Marks the current set of one time keys as being published. */
func (a *Account) MarkKeysAsPublished() {
	C.olm_account_mark_keys_as_published((*C.OlmAccount)(a))
}

/** The largest number of one time keys this account can store. */
func (a *Account) MaxNumberOfOneTimeKeys() uint {
	return uint(C.olm_account_max_number_of_one_time_keys((*C.OlmAccount)(a)))
}

/** Generates a number of new one time keys. If the total number of keys stored
 * by this account exceeds max_number_of_one_time_keys() then the old keys are
 * discarded. Returns olm_error() on error. If the number of random bytes is
 * too small then olm_account_last_error() will be "NOT_ENOUGH_RANDOM". */
func (a *Account) GenOneTimeKeys(num uint) error {
	random := make([]byte, a.genOneTimeKeysRandomLen(num))
	_, err := crand.Read(random)
	if err != nil {
		return fmt.Errorf("Couldn't get enough randomness from crypto/rand")
	}
	r := C.olm_account_generate_one_time_keys(
		(*C.OlmAccount)(a),
		C.size_t(num),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == Error() {
		return a.lastError()
	} else {
		return nil
	}
}

/** Creates a new out-bound session for sending messages to a given identity_key
 * and one_time_key. Returns olm_error() on failure. If the keys couldn't be
 * decoded as base64 then olm_session_last_error() will be "INVALID_BASE64"
 * If there weren't enough random bytes then olm_session_last_error() will
 * be "NOT_ENOUGH_RANDOM". */
func (a *Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey string) (*Session, error) {
	s := newSession()
	random := make([]byte, s.createOutboundRandomLen())
	_, err := crand.Read(random)
	if err != nil {
		return nil, fmt.Errorf("Couldn't get enough randomness from crypto/rand")
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

/** Create a new in-bound session for sending/receiving messages from an
 * incoming PRE_KEY message. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
 * key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID". */
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

/** Create a new in-bound session for sending/receiving messages from an
 * incoming PRE_KEY message. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
 * key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID". */
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

/** Removes the one time keys that the session used from the account. Returns
 * olm_error() on failure. If the account doesn't have any matching one time
 * keys then olm_account_last_error() will be "BAD_MESSAGE_KEY_ID". */
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

type Utility C.OlmUtility

/** The size of a utility object in bytes */
func utilitySize() uint {
	return uint(C.olm_utility_size())
}

/** The length of the buffer needed to hold the SHA-256 hash. */
func (u *Utility) sha256Len() uint {
	return uint(C.olm_sha256_length((*C.OlmUtility)(u)))
}

/** A null terminated string describing the most recent error to happen to a
 * utility */
func (u *Utility) lastError() error {
	return fmt.Errorf("%s", C.olm_utility_last_error((*C.OlmUtility)(u)))
}

/** Clears the memory used to back this utility */
func (u *Utility) Clear() error {
	r := C.olm_clear_utility((*C.OlmUtility)(u))
	if r == Error() {
		return u.lastError()
	} else {
		return nil
	}
}

/** Initialise a utility object using the supplied memory
 *  The supplied memory must be at least olm_utility_size() bytes */
func NewUtility() *Utility {
	memory := make([]byte, utilitySize())
	//(*C.OlmAccount)(a).memory = unsafe.Pointer(&memory[0])
	return (*Utility)(C.olm_utility(unsafe.Pointer(&memory[0])))
}

/** Calculates the SHA-256 hash of the input and encodes it as base64. If the
 * output buffer is smaller than olm_sha256_length() then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". */
func (u *Utility) Sha256(input string) (string, error) {
	output := make([]byte, u.sha256Len())
	r := C.olm_sha256(
		(*C.OlmUtility)(u),
		unsafe.Pointer(&([]byte(input)[0])),
		C.size_t(len(input)),
		unsafe.Pointer(&([]byte(output)[0])),
		C.size_t(len(output)))
	if r == Error() {
		return "", u.lastError()
	} else {
		return string(output), nil
	}
}

/** Verify an ed25519 signature. If the key was too small then
 * olm_session_last_error will be "INVALID_BASE64". If the signature was invalid
 * then olm_session_last_error() will be "BAD_MESSAGE_MAC". */
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
