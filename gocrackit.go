package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"github.com/fatih/color"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"github.com/jgillich/go-opencl"
)

// OpenCL Kernel for GPU-based hashing
const openCLKernel = `
__kernel void hash_md5(__global char* passwords, __global char* hashes, int count) {
    int id = get_global_id(0);
    if (id < count) {
        char hash[16];
        md5(passwords[id], hash);
        if (memcmp(hash, hashes, 16) == 0) {
            // Password matched, return result
        }
    }
}`

// GPU-accelerated hash function using OpenCL
func hashWithGPU(wordlist []string, targetHash string, algo string) string {
	platforms, err := opencl.GetPlatforms()
	if err != nil || len(platforms) == 0 {
		log.Fatal("No OpenCL platforms found")
	}

	// Select the first available platform
	platform := platforms[0]
	devices, err := platform.GetDevices(opencl.DeviceTypeGPU)
	if err != nil || len(devices) == 0 {
		log.Fatal("No OpenCL GPU devices found")
	}

	device := devices[0]
	context, err := opencl.CreateContext([]*opencl.Device{device})
	if err != nil {
		log.Fatal("Failed to create OpenCL context")
	}
	source := openCLKernel
	program, err := context.CreateProgramWithSource([]string{source})
	if err != nil {
		log.Fatal("Failed to create OpenCL program")
	}

	if err := program.Build(); err != nil {
		log.Fatal("Failed to build OpenCL program")
	}

	// Execute kernel
	queue, err := context.CreateCommandQueue(device)
	if err != nil {
		log.Fatal("Failed to create command queue")
	}

	kernel, err := program.CreateKernel("hash_md5")
	if err != nil {
		log.Fatal("Failed to create kernel")
	}

	// Load wordlist into GPU memory
	wordlistBuffer, err := context.CreateBuffer(opencl.MemReadOnly, len(wordlist)*64, nil) // Max word length assumed to be 64
	if err != nil {
		log.Fatal("Failed to create buffer for wordlist")
	}
	targetBuffer, err := context.CreateBuffer(opencl.MemReadOnly, len(targetHash), nil)
	if err != nil {
		log.Fatal("Failed to create buffer for target hash")
	}

	// Copy data to GPU
	queue.EnqueueWriteBuffer(wordlistBuffer, true, 0, len(wordlist)*64, wordlist, nil, nil)
	queue.EnqueueWriteBuffer(targetBuffer, true, 0, len(targetHash), []byte(targetHash), nil, nil)

	kernel.SetArgBuffer(0, wordlistBuffer)
	kernel.SetArgBuffer(1, targetBuffer)
	kernel.SetArgInt32(2, int32(len(wordlist)))

	// Run kernel
	queue.EnqueueNDRangeKernel(kernel, nil, []int{len(wordlist)}, nil, nil)
	queue.Finish()

	// Read back result
	results := make([]byte, 64)
	queue.EnqueueReadBuffer(targetBuffer, true, 0, 64, results, nil, nil)

	return string(results)
}

// crackHash attempts to find the plaintext using CPU or GPU
func crackHash(hash, algo, wordlistPath string, useGPU bool) {
	data, err := ioutil.ReadFile(wordlistPath)
	if err != nil {
		log.Fatalf("Failed to read wordlist: %v", err)
	}

	words := strings.Split(string(data), "\n")
	if useGPU {
		result := hashWithGPU(words, hash, algo)
		if result != "" {
			color.Green("[✔] Hash cracked: %s", result)
		} else {
			color.Red("[-] No match found")
		}
	} else {
		var wg sync.WaitGroup
		found := make(chan string, 1)
		color.Cyan("[+] Starting CPU-based hash cracking...")
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

		go func() {
			wg.Wait()
			close(found)
		}()

		if result, ok := <-found; ok {
			color.Green("[✔] Hash cracked: %s", result)
		} else {
			color.Red("[-] No match found")
		}
		tElapsed := time.Since(tStart)
		color.Yellow("[*] Cracking completed in %s", tElapsed)
	}
}

func main() {
	if len(os.Args) != 5 {
		color.Red("Usage: go run gocrackit.go <hash> <algorithm> <wordlist> <gpu|cpu>")
		os.Exit(1)
	}

	hash := os.Args[1]
	algo := strings.ToLower(os.Args[2])
	wordlist := os.Args[3]
	mode := strings.ToLower(os.Args[4])

	useGPU := mode == "gpu"
	crackHash(hash, algo, wordlist, useGPU)
}
