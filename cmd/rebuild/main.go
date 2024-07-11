package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/tink/go/streamingaead/subtle"
	"github.com/jackwilsdon/seedvault-extractor/internal"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	typeKVBackup   = 1
	typeFullBackup = 2
)

func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s path-to-backup mnemonic\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	backupPath := os.Args[1]
	metadataPath := ".backup.metadata"

	metadataFile, err := os.Create(metadataPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to create %q: %s\n", metadataPath, err)
		os.Exit(1)
	}
	defer func() {
		_ = metadataFile.Close()
	}()

	metadataWriter := bufio.NewWriter(metadataFile)
	version := byte(1)
	if err := metadataWriter.WriteByte(version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to write version: %s\n", err)
		os.Exit(1)
	}

	debug := os.Getenv("DEBUG") == "1"
	if debug {
		fmt.Printf("version: %d\n", version)
	}

	backupName := filepath.Base(backupPath)
	token, err := strconv.ParseUint(backupName, 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to parse backup name %q: %s\n", backupName, err)
		os.Exit(1)
	}

	if debug {
		fmt.Printf("token: %d\n", token)
	}

	seed, err := mnemonicToSeed(os.Args[2])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to read seed from mnemonic: %s\n", err)
		os.Exit(1)
	}
	if debug {
		fmt.Printf("seed: %s\n", hex.EncodeToString(seed))
	}

	key := hkdfExpand(seed[32:], []byte("app data key"), 32)
	if debug {
		fmt.Printf("key: %s\n", hex.EncodeToString(key))
	}

	associatedData := make([]byte, 10)
	associatedData[0] = version
	binary.BigEndian.PutUint64(associatedData[2:], token)
	err = encrypt(metadataWriter, key, associatedData, os.Stdin)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to decrypt metadata: %s\n", err)
		os.Exit(1)
	}

}

func mnemonicToSeed(mnemonic string) ([]byte, error) {
	phrases := strings.Split(mnemonic, " ")

	if len(phrases) != 12 {
		return nil, fmt.Errorf("12 mnemonics needed, yet %d given", len(phrases))
	}

	for _, phrase := range phrases {
		if _, ok := internal.Bip39Words[phrase]; !ok {
			return nil, fmt.Errorf("invalid mnemonic given (case-sensitive): %s", phrase)
		}
	}

	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New), nil
}

func hkdfExpand(secretKey, info []byte, outLengthBytes int64) []byte {
	r := hkdf.Expand(sha256.New, secretKey, info)
	k := make([]byte, outLengthBytes)
	if _, err := io.ReadFull(r, k); err != nil {
		panic("failed to read HKDF: " + err.Error())
	}
	return k
}

func getAdditionalData(version byte, type_ byte, packageName string) []byte {
	ad := make([]byte, 2+len(packageName))
	ad[0] = version
	ad[1] = type_
	copy(ad[2:], packageName)
	return ad
}

func encrypt(w *bufio.Writer, key []byte, associatedData []byte, plaintextReader io.Reader) error {
	a, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 1<<20, 0)
	if err != nil {
		return fmt.Errorf("failed to create AESGCMHKDF: %w", err)
	}

	dw, err := a.NewEncryptingWriter(w, associatedData)
	if err != nil {
		return fmt.Errorf("failed to create encrypting reader: %w", err)
	}

	_, err = io.Copy(dw, plaintextReader)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	if err := dw.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
        }

	return nil
}
