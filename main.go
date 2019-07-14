package main

//go:generate cp /usr/local/go/misc/wasm/wasm_exec.js .

// compile with
// GOOS=js GOARCH=wasm go build -o main.wasm

//
// index.html
//
// <html>
// <head>
//     <meta charset="utf-8">
//     <script src="wasm_exec.js"></script>
//     <script>
//     const go = new Go();
//     WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject).then((result) => {
//         go.run(result.instance);
//     });
//     </script>
// </head>
// <body></body>
// </html>

// to run
//
// bob = pakeInit("pass1","0");
// jane = pakeInit("pass1","1");
// jane = pakeUpdate(jane,pakePublic(bob));
// bob = pakeUpdate(bob,pakePublic(jane));
// jane = pakeUpdate(jane,pakePublic(bob));
// console.log(pakeSessionKey(bob))
// console.log(pakeSessionKey(jane))

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"syscall/js"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// PAKE

// EllipticCurve is a general curve which allows other
// elliptic curves to be used with PAKE.
type EllipticCurve interface {
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	IsOnCurve(x, y *big.Int) bool
}

// Pake keeps public and private variables by
// only transmitting between parties after marshaling.
//
// This method follows
// https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf
// Figure 21/15
// http://www.lothar.com/~warner/MagicWormhole-PyCon2016.pdf
// Slide 11
type Pake struct {
	// Public variables
	Role     int
	Uᵤ, Uᵥ   *big.Int
	Vᵤ, Vᵥ   *big.Int
	Xᵤ, Xᵥ   *big.Int
	Yᵤ, Yᵥ   *big.Int
	HkA, HkB []byte

	// Private variables
	curve      EllipticCurve
	Pw         []byte
	Vpwᵤ, Vpwᵥ *big.Int
	Upwᵤ, Upwᵥ *big.Int
	Aα         []byte
	Aαᵤ, Aαᵥ   *big.Int
	Zᵤ, Zᵥ     *big.Int
	K          []byte

	IsVerifiedBool bool
	TimeToHash     time.Duration
}

func (p *Pake) Public() *Pake {
	return &Pake{
		Role: p.Role,
		Uᵤ:   p.Uᵤ,
		Uᵥ:   p.Uᵥ,
		Vᵤ:   p.Vᵤ,
		Vᵥ:   p.Vᵥ,
		Xᵤ:   p.Xᵤ,
		Xᵥ:   p.Xᵥ,
		Yᵤ:   p.Yᵤ,
		Yᵥ:   p.Yᵥ,
		HkA:  p.HkA,
		HkB:  p.HkB,
	}
}

// InitCurve will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be siec,  p521, p256, p384
func InitCurve(pw []byte, role int, curve string, timeToHash ...time.Duration) (p *Pake, err error) {
	var ellipticCurve EllipticCurve
	switch curve {
	case "p521":
		ellipticCurve = elliptic.P521()
	case "p256":
		ellipticCurve = elliptic.P256()
	case "p384":
		ellipticCurve = elliptic.P384()
	default:
		err = errors.New("no such curve")
		return
	}
	if len(timeToHash) > 0 {
		return Init(pw, role, ellipticCurve, timeToHash[0])
	} else {
		return Init(pw, role, ellipticCurve)
	}
}

// Init will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be any elliptic curve.
func Init(pw []byte, role int, curve EllipticCurve, timeToHash ...time.Duration) (p *Pake, err error) {
	p = new(Pake)
	if len(timeToHash) > 0 {
		p.TimeToHash = timeToHash[0]
	} else {
		p.TimeToHash = 1 * time.Second
	}
	if role == 1 {
		p.Role = 1
		p.curve = curve
		p.Pw = pw
	} else {
		p.Role = 0
		p.curve = curve
		p.Pw = pw
		rand1 := make([]byte, 8)
		rand2 := make([]byte, 8)
		_, err = rand.Read(rand1)
		if err != nil {
			return
		}
		_, err = rand.Read(rand2)
		if err != nil {
			return
		}
		p.Uᵤ, p.Uᵥ = p.curve.ScalarBaseMult(rand1)
		p.Vᵤ, p.Vᵥ = p.curve.ScalarBaseMult(rand2)
		if !p.curve.IsOnCurve(p.Uᵤ, p.Uᵥ) {
			err = errors.New("U values not on curve")
			return
		}
		if !p.curve.IsOnCurve(p.Vᵤ, p.Vᵥ) {
			err = errors.New("V values not on curve")
			return
		}

		// STEP: A computes X
		p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.Pw)
		p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.Pw)
		p.Aα = make([]byte, 8) // randomly generated secret
		_, err = rand.Read(p.Aα)
		if err != nil {
			return
		}
		p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
		p.Xᵤ, p.Xᵥ = p.curve.Add(p.Upwᵤ, p.Upwᵥ, p.Aαᵤ, p.Aαᵥ) // "X"
		// now X should be sent to B
	}
	return
}

// Bytes just marshalls the PAKE structure so that
// private variables are hidden.
func (p *Pake) Bytes() []byte {
	b, _ := json.Marshal(p)
	return b
}

// Update will update itself with the other parties
// PAKE and automatically determine what stage
// and what to generate.
func (p *Pake) Update(qBytes []byte) (err error) {
	var q *Pake
	err = json.Unmarshal(qBytes, &q)
	if err != nil {
		return
	}
	if p.Role == q.Role {
		err = errors.New("can't have its own role")
		return
	}

	if p.Role == 1 {
		// initial step for B
		if p.Uᵤ == nil && q.Uᵤ != nil {
			// copy over public variables
			p.Uᵤ, p.Uᵥ = q.Uᵤ, q.Uᵥ
			p.Vᵤ, p.Vᵥ = q.Vᵤ, q.Vᵥ
			p.Xᵤ, p.Xᵥ = q.Xᵤ, q.Xᵥ

			// confirm that U,V are on curve
			if !p.curve.IsOnCurve(p.Uᵤ, p.Uᵥ) {
				err = errors.New("U values not on curve")
				return
			}
			if !p.curve.IsOnCurve(p.Vᵤ, p.Vᵥ) {
				err = errors.New("V values not on curve")
				return
			}

			// STEP: B computes Y
			p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.Pw)
			p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.Pw)
			p.Aα = make([]byte, 8) // randomly generated secret
			rand.Read(p.Aα)
			p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
			p.Yᵤ, p.Yᵥ = p.curve.Add(p.Vpwᵤ, p.Vpwᵥ, p.Aαᵤ, p.Aαᵥ) // "Y"
			// STEP: B computes Z
			p.Zᵤ, p.Zᵥ = p.curve.Add(p.Xᵤ, p.Xᵥ, p.Upwᵤ, new(big.Int).Neg(p.Upwᵥ))
			p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
			// STEP: B computes k
			// H(pw,id_P,id_Q,X,Y,Z)
			HB := sha256.New()
			HB.Write(p.Pw)
			HB.Write(p.Xᵤ.Bytes())
			HB.Write(p.Xᵥ.Bytes())
			HB.Write(p.Yᵤ.Bytes())
			HB.Write(p.Yᵥ.Bytes())
			HB.Write(p.Zᵤ.Bytes())
			HB.Write(p.Zᵥ.Bytes())
			// STEP: B computes k
			p.K = HB.Sum(nil)
			p.HkB, err = hashK(p.K, p.TimeToHash)
		} else if p.HkA == nil && q.HkA != nil {
			p.HkA = q.HkA
			// verify
			err = checkKHash(p.HkA, p.K)
			if err == nil {
				p.IsVerifiedBool = true
			}
		}
	} else {
		if p.HkB == nil && q.HkB != nil {
			p.HkB = q.HkB
			p.Yᵤ, p.Yᵥ = q.Yᵤ, q.Yᵥ

			// STEP: A computes Z
			p.Zᵤ, p.Zᵥ = p.curve.Add(p.Yᵤ, p.Yᵥ, p.Vpwᵤ, new(big.Int).Neg(p.Vpwᵥ))
			p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
			// STEP: A computes k
			// H(pw,id_P,id_Q,X,Y,Z)
			HA := sha256.New()
			HA.Write(p.Pw)
			HA.Write(p.Xᵤ.Bytes())
			HA.Write(p.Xᵥ.Bytes())
			HA.Write(p.Yᵤ.Bytes())
			HA.Write(p.Yᵥ.Bytes())
			HA.Write(p.Zᵤ.Bytes())
			HA.Write(p.Zᵥ.Bytes())
			p.K = HA.Sum(nil)
			p.HkA, err = hashK(p.K, p.TimeToHash)

			// STEP: A verifies that its session key matches B's
			// session key
			err = checkKHash(p.HkB, p.K)
			if err == nil {
				p.IsVerifiedBool = true
			}
		}
	}
	return
}

// hashK generates a bcrypt hash of the password using work factor 12.
func hashK(k []byte, durationToWork time.Duration) (b []byte, err error) {
	for i := 1; i < 24; i++ {
		s := time.Now()
		b, err = bcrypt.GenerateFromPassword(k, i)
		if time.Since(s) > durationToWork {
			return
		}
	}
	return
}

// checkKHash securely compares a bcrypt hashed password with its possible
// plaintext equivalent.  Returns nil on success, or an error on failure.
func checkKHash(hash, k []byte) error {
	return bcrypt.CompareHashAndPassword(hash, k)
}

// IsVerified returns whether or not the k has been
// generated AND it confirmed to be the same as partner
func (p *Pake) IsVerified() bool {
	return p.IsVerifiedBool
}

// SessionKey is returned, unless it is not generated
// in which is returns an error. This function does
// not check if it is verifies.
func (p *Pake) SessionKey() ([]byte, error) {
	var err error
	if p.K == nil {
		err = errors.New("session key not generated")
	}
	return p.K, err
}

// ENCRYPTION

type Encryption struct {
	key        []byte
	passphrase []byte
	salt       []byte
}

// New generates a new Encryption, using the supplied passphrase and
// an optional supplied salt.
// Passing nil passphrase will not use decryption.
func NewEncryption(passphrase []byte, salt []byte) (e Encryption, err error) {
	if passphrase == nil {
		e = Encryption{nil, nil, nil}
		return
	}
	e.passphrase = passphrase
	if salt == nil {
		e.salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(e.salt)
	} else {
		e.salt = salt
	}
	e.key = pbkdf2.Key([]byte(passphrase), e.salt, 100, 32, sha256.New)
	return
}

func (e Encryption) Salt() []byte {
	return e.salt
}

// Encrypt will generate an Encryption, prefixed with the IV
func (e Encryption) Encrypt(plaintext []byte) (encrypted []byte, err error) {
	if e.passphrase == nil {
		encrypted = plaintext
		return
	}
	// generate a random iv each time
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	ivBytes := make([]byte, 12)
	rand.Read(ivBytes)
	b, err := aes.NewCipher(e.key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	encrypted = aesgcm.Seal(nil, ivBytes, plaintext, nil)
	encrypted = append(ivBytes, encrypted...)
	return
}

// Decrypt an Encryption
func (e Encryption) Decrypt(encrypted []byte) (plaintext []byte, err error) {
	if e.passphrase == nil {
		plaintext = encrypted
		return
	}
	b, err := aes.NewCipher(e.key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	plaintext, err = aesgcm.Open(nil, encrypted[:12], encrypted[12:], nil)
	return
}

// encrypt(message,password,salt)
func encrypt(this js.Value, inputs []js.Value) interface{} {
	if len(inputs) != 3 {
		return js.Global().Get("Error").New("not enough inputs")
	}
	e, err := NewEncryption([]byte(inputs[1].String()), []byte(inputs[2].String()))
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	enc, err := e.Encrypt([]byte(inputs[0].String()))
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return hex.EncodeToString(enc)
}

// decrypt(message,password,salt)
func decrypt(this js.Value, inputs []js.Value) interface{} {
	e, err := NewEncryption([]byte(inputs[1].String()), []byte(inputs[2].String()))
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	decBytes, err := hex.DecodeString(inputs[0].String())
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	dec, err := e.Decrypt(decBytes)
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return string(dec)
}

// initPake(weakPassphrase, role)
// returns: pakeBytes
func pakeInit(this js.Value, inputs []js.Value) interface{} {
	// initialize sender P ("0" indicates sender)
	if len(inputs) != 2 {
		return js.Global().Get("Error").New("need weakPassphrase, role")
	}
	role := 0
	if inputs[1].String() == "1" {
		role = 1
	}
	P, err := Init([]byte(inputs[0].String()), role, elliptic.P521(), 1*time.Millisecond)
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return string(P.Bytes())
}

// pakeUpdate(pakeBytes,otherPublicPakeBytes)
func pakeUpdate(this js.Value, inputs []js.Value) interface{} {
	if len(inputs) != 2 {
		return js.Global().Get("Error").New("need two input")
	}
	var P, Q *Pake
	err := json.Unmarshal([]byte(inputs[0].String()), &P)
	P.curve = elliptic.P521()
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	err = json.Unmarshal([]byte(inputs[1].String()), &Q)
	Q.curve = elliptic.P521()
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	P.Update(Q.Bytes())
	return string(P.Bytes())
}

// pakePublic(pakeBytes)
func pakePublic(this js.Value, inputs []js.Value) interface{} {
	var P *Pake
	err := json.Unmarshal([]byte(inputs[0].String()), &P)
	P.curve = elliptic.P521()
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return string(P.Public().Bytes())
}

// pakeSessionKey(pakeBytes)
func pakeSessionKey(this js.Value, inputs []js.Value) interface{} {
	var P *Pake
	err := json.Unmarshal([]byte(inputs[0].String()), &P)
	P.curve = elliptic.P521()
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	key, err := P.SessionKey()
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return hex.EncodeToString(key)
}

func main() {
	c := make(chan bool)
	fmt.Println("starting")
	js.Global().Set("encrypt", js.FuncOf(encrypt))
	js.Global().Set("decrypt", js.FuncOf(decrypt))
	js.Global().Set("pakeInit", js.FuncOf(pakeInit))
	js.Global().Set("pakePublic", js.FuncOf(pakePublic))
	js.Global().Set("pakeUpdate", js.FuncOf(pakeUpdate))
	js.Global().Set("pakeSessionKey", js.FuncOf(pakeSessionKey))
	fmt.Println("Initiated")
	<-c
}
