package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Provider access and refresh tokens live server-side in the session row so
// the app can re-check the role mid-session. Encrypted, so a copied SQLite
// file does not hand over working tokens.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("DATA_ENCRYPTION_KEY muss 32 Byte lang sein, ist %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) seal(plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func (s *Store) open(ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	n := s.aead.NonceSize()
	if len(ciphertext) < n {
		return "", errors.New("verschlüsselter Wert ist zu kurz")
	}
	plaintext, err := s.aead.Open(nil, ciphertext[:n], ciphertext[n:], nil)
	if err != nil {
		// Almost always a rotated DATA_ENCRYPTION_KEY. The session can then no
		// longer be revalidated and is discarded.
		return "", fmt.Errorf("Wert nicht entschlüsselbar (DATA_ENCRYPTION_KEY gewechselt?): %w", err)
	}
	return string(plaintext), nil
}
