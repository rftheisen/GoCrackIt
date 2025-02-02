# gocrackit

gocrackit is a powerful and multithreaded hash cracking tool written in Go. It supports multiple hashing algorithms and dictionary-based attacks to crack hashes efficiently. This is to be used for learning and research purposes only.

## Features
- Supports various hashing algorithms:
  - MD5
  - SHA-1
  - SHA-256
  - SHA-512
  - Bcrypt
  - Scrypt
  - HMAC-SHA256
  - NTLM
  - SHA512-Crypt
  - Argon2id
  - PBKDF2-SHA256
  - PBKDF2-SHA512
- Multithreaded execution for fast performance
- Colorful output with timing analysis
- Uses a wordlist to attempt hash decryption

## Installation
Ensure you have Go installed, then clone this repository and build the tool:

```sh
git clone https://github.com/rftheisen/gocrackit.git
cd gocrackit
go build -o gocrackit gocrackit.go
```

## Usage

Run the tool with the following syntax:

```sh
./gocrackit <hash> <algorithm> <wordlist>
```

### Example:
To crack an MD5 hash:

```sh
./gocrackit 5f4dcc3b5aa765d61d8327deb882cf99 md5 wordlist.txt
```

To crack a SHA-256 hash:

```sh
./gocrackit 5e884898da28047151d0e56f8dc6292773603d0d6aabbdddbb8f00a08a3b981b sha256 wordlist.txt
```

To crack a bcrypt hash:

```sh
./gocrackit "$2b$12$3jRn9tDZyvl3X/bsbKSmNeEo8qbmGhHkm8.QyH5IcVhCNk34E1TZi" bcrypt wordlist.txt
```

## Wordlist
The wordlist should be a plaintext file with one password per line:

```
123456
password
admin
qwerty
letmein
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## TODO
- Add GPU acceleration (start with CUDA)
## License
MIT License

