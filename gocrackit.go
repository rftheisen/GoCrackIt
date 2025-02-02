package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/hmac"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"github.com/fatih/color"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// hashString hashes the input with the specified algorithm
func hashString(input, algo string) string {
	switch algo {
	case "md5":
		h := md5.Sum([]byte(input))
		return hex.EncodeToString(h[:])
	case "sha1":
		h := sha1.Sum([]byte(input))
		return hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(input))
		return hex.EncodeToString(h[:])
	case "sha512":
		h := sha512.Sum512([]byte(input))
		return hex.EncodeToString(h[:])
	case "bcrypt":
		h, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal("Error generating bcrypt hash")
		}
		return string(h)
	case "scrypt":
		h, err := scrypt.Key([]byte(input), []byte("salt"), 16384, 8, 1, 32)
		if err != nil {
			log.Fatal("Error generating scrypt hash")
		}
		return hex.EncodeToString(h)
	case "hmac-sha256":
		key := []byte("secret-key")
		h := hmac.New(sha256.New, key)
		h.Write([]byte(input))
		return hex.EncodeToString(h.Sum(nil))
	case "ntlm":
		h := md4.New()
		h.Write([]byte(input))
		return hex.EncodeToString(h.Sum(nil))
	case "sha512-crypt":
		h, err := ssh.NewSignerFromKey([]byte(input))
		if err != nil {
			log.Fatal("Error generating sha512-crypt hash")
		}
		return hex.EncodeToString(h.PublicKey().Marshal())
	case "argon2id":
		h := argon2.IDKey([]byte(input), []byte("salt"), 1, 64*1024, 4, 32)
		return hex.EncodeToString(h)
	case "pbkdf2-sha256":
		h := pbkdf2.Key([]byte(input), []byte("salt"), 4096, 32, sha256.New)
		return hex.EncodeToString(h)
	case "pbkdf2-sha512":
		h := pbkdf2.Key([]byte(input), []byte("salt"), 4096, 64, sha512.New)
		return hex.EncodeToString(h)
	default:
		log.Fatal("Unsupported hash algorithm")
	}
	return ""
}

// crackHash attempts to find the plaintext corresponding to the hash
func crackHash(hash, algo, wordlistPath string) {
	data, err := ioutil.ReadFile(wordlistPath)
	if err != nil {
		log.Fatalf("Failed to read wordlist: %v", err)
	}

	words := strings.Split(string(data), "\n")
	var wg sync.WaitGroup
	found := make(chan string, 1) // Channel to signal when a match is found

	color.Cyan("[+] Starting hash cracking...")
	tStart := time.Now()

	for _, word := range words {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			w = strings.TrimSpace(w)
			if hashString(w, algo) == hash {
				found <- w
			}
		}(word)
	}

	// Wait for completion
	go func() {
		wg.Wait()
		close(found)
	}()

	// Check for results
	if result, ok := <-found; ok {
		color.Green("[✔] Hash cracked: %s", result)
	} else {
		color.Red("[-] No match found")
	}

	tElapsed := time.Since(tStart)
	color.Yellow("[*] Cracking completed in %s", tElapsed)
}

func main() {
	if len(os.Args) != 4 {
		color.Red("Usage: go run gocrackit.go <hash> <algorithm> <wordlist>")
		color.Yellow("Supported algorithms: md5, sha1, sha256, sha512, bcrypt, scrypt, hmac-sha256, ntlm, sha512-crypt, argon2id, pbkdf2-sha256, pbkdf2-sha512")
		os.Exit(1)
	}

	hash := os.Args[1]
	algo := strings.ToLower(os.Args[2])
	wordlist := os.Args[3]

	crackHash(hash, algo, wordlist)
}
