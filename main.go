package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
)

func main() {

	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privatekey.PublicKey

	/*
			A hashing function, chosen so that even if the input is changed slightly, the output hash changes completely.
			The SHA256/512 algorithm is suitable for this
		A random reader used for generating random bits so that the same input doesn’t give the same output twice
		The public key generated previously
		The message we want to encrypt
		An optional label (which we will omit in this case)
	*/
	encryptedBytes, err := rsa.EncryptOAEP(
		sha512.New(),
		rand.Reader,
		&publicKey,
		[]byte("super secret message"),
		nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("encrypted bytes len: ", len(encryptedBytes))
	fmt.Println("you may print encrypted bytes but it is not readable data")

	/*
		The *rsa.PrivateKey struct comes with a Decrypt method which we will use
		to get the original information back from the encrypted data.
		The data we have to provide for decryption is:
		The encrypted data (called the cipher text)
		The hash that we used to encrypt the data
	*/
	decryptedBytes, err := privatekey.Decrypt(
		nil,                                   // reader
		encryptedBytes,                        // encrypted or cipher text
		&rsa.OAEPOptions{Hash: crypto.SHA512}, // hash used earlier while encryption
	)
	if err != nil {
		panic(err)
	}

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	fmt.Println("decrypted message: ", string(decryptedBytes))

	// Next we see example of Signing and Sign Verification
	//Anyone who has the signature, the message, and the public key, can use RSA verification to make sure that the message actually came from the party by whom the public key is issued. If the data or signature don’t match, the verification process fails.
	msg := []byte(" message to verify for integrity")
	msgHash := sha512.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	// calculate msghashSum or message digest
	msgHashSum := msgHash.Sum(nil)
	// fmt.Println("msgHash: ", msgHash)
	fmt.Println("msgHashSum or message digest len ", len(msgHashSum))

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, privatekey, crypto.SHA512, msgHashSum, nil)
	fmt.Println("Signature len is :", len(signature))
	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err = rsa.VerifyPSS(&publicKey, crypto.SHA512, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	fmt.Println("signature verified")
}
