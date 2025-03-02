package main

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lOpenCL
#include <CL/cl.h>
#include <stdlib.h>
*/
import "C"

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
	"unsafe"
	"github.com/fatih/color"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// GPU-accelerated hash function using OpenCL with CGO
func hashWithGPU(wordlist []string, targetHash string, algo string) string {
	var platform C.cl_platform_id
	var device C.cl_device_id
	var context C.cl_context
	var queue C.cl_command_queue
	var program C.cl_program
	var kernel C.cl_kernel
	var err C.cl_int

	// Get Platform
	err = C.clGetPlatformIDs(1, &platform, nil)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to get OpenCL platform")
	}

	// Get Device
	err = C.clGetDeviceIDs(platform, C.CL_DEVICE_TYPE_GPU, 1, &device, nil)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to get OpenCL device")
	}

	// Create Context
	context = C.clCreateContext(nil, 1, &device, nil, nil, &err)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to create OpenCL context")
	}

	// Create Command Queue
	queue = C.clCreateCommandQueue(context, device, 0, &err)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to create command queue")
	}

	// OpenCL kernel source code
	source := `
	__kernel void hash_md5(__global char* passwords, __global char* hashes, int count) {
	    int id = get_global_id(0);
	    if (id < count) {
	        char hash[16];
	        md5(passwords[id], hash);
	        if (memcmp(hash, hashes, 16) == 0) {
	            // Password matched
	        }
	    }
	}`

	sourceStr := C.CString(source)
	defer C.free(unsafe.Pointer(sourceStr))

	program = C.clCreateProgramWithSource(context, 1, &sourceStr, nil, &err)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to create OpenCL program")
	}

	err = C.clBuildProgram(program, 1, &device, nil, nil, nil)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to build OpenCL program")
	}

	kernel = C.clCreateKernel(program, C.CString("hash_md5"), &err)
	if err != C.CL_SUCCESS {
		log.Fatal("Failed to create kernel")
	}

	// GPU processing logic goes here (memory allocation, execution, etc.)
	log.Println("[+] OpenCL kernel compiled successfully, but further implementation needed for full GPU acceleration.")

	return ""
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
