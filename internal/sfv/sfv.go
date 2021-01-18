/*
Copyright © 2021 Robin Helgelin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package sfv

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"

	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"

	"hash"
	"hash/crc32"

	"github.com/cheggaaa/pb/v3"
)

var (
	Commit  string
	Version string
)

type ChecksumType int
type ChecksumStatus int

type ChecksumFile struct {
	ChecksumType ChecksumType
	Status       ChecksumStatus
	Filename     string
	Filesize     int64
	Checksum     string
	ChecksumWant string
}

type hasherInfo struct {
	buf 		[]byte
	hash    hash.Hash
	hash32 	hash.Hash32
}

const (
	StatusUnknown ChecksumStatus = iota
	StatusOK
	StatusCheckSumOK
	StatusCheckSumNoMatch
	StatusFailedCheckSum
	StatusNotFound
	StatusNotFile
	StatusStatFailed
)

const (
	TypeUnknown ChecksumType = iota
	TypeCRC32
	TypeMD5
	TypeSHA1
	TypeSHA256
)

func StringToType(t string) ChecksumType {
	switch t {
	case "crc32":
		return TypeCRC32
	case "md5":
		return TypeMD5
	case "sha1":
		return TypeSHA1
	case "sha256":
		return TypeSHA256
	default:
		return TypeUnknown
	}
}

func StatusTypeToString(s ChecksumStatus) string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusCheckSumOK:
		return "Checksum OK"
	case StatusCheckSumNoMatch:
		return "Checksum doesn't match"
	case StatusFailedCheckSum:
		return "Checksum calculation failed"
	case StatusNotFound:
		return "File not found"
	case StatusNotFile:
		return "File not a file"
	case StatusStatFailed:
		return "File stat failed"
	default:
		return "Unknown"
	}
}

func Create(t ChecksumType, files []string) []ChecksumFile {
	var totalFileSize int64
	checksumFiles := make([]ChecksumFile, len(files))
	for i, file := range files {
		checksumFiles[i] = createChecksumFile(t, file)

		totalFileSize += checksumFiles[i].Filesize
	}

	bar := pb.New64(totalFileSize)
	bar.Set(pb.Bytes, true)
	bar.Start()

	for i, _ := range checksumFiles {
		calculateChecksum(&checksumFiles[i], bar)
	}

	bar.Finish()

	return checksumFiles
}

func Verify(file string) []ChecksumFile {
	totalFileSize, checksumFiles := parseSfvFile(file)

	bar := pb.New64(totalFileSize)
	bar.Set(pb.Bytes, true)
	bar.Start()

	for i, _ := range checksumFiles {
		calculateChecksum(&checksumFiles[i], bar)

		if checksumFiles[i].Status == StatusCheckSumOK &&
		   checksumFiles[i].Checksum != checksumFiles[i].ChecksumWant {
			checksumFiles[i].Status = StatusCheckSumNoMatch
		}
	}

	bar.Finish()

	return checksumFiles
}

func parseSfvFile(filename string) (int64, []ChecksumFile) {
	var totalFileSize int64
	var file *os.File
	var err error

	if filename != "" {
		file, err = os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()
	} else {
		file = os.Stdin
	}

	checksumFiles := make([]ChecksumFile, 0)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	reCrc32  := regexp.MustCompile(`^([\w\.]+) ([\w]{8})$`)
	reMd5    := regexp.MustCompile(`^MD5 \(([\w\.]+)\) = ([\w]{32})$`)
	reSha1   := regexp.MustCompile(`^([\w]{40})  ([\w\.]+)$`)
	reSha256 := regexp.MustCompile(`^([\w]{64})  ([\w\.]+)$`)

	for scanner.Scan() {
		line := scanner.Text()
		if line[0:1] == ";" {
			continue
		}

		var checksumFile ChecksumFile
		if reCrc32.MatchString(line) {
			matches := reCrc32.FindStringSubmatch(line)

			checksumFile.ChecksumType = TypeCRC32
			checksumFile.Filename     = matches[1]
			checksumFile.ChecksumWant = matches[2]
		} else if reMd5.MatchString(line) {
			matches := reMd5.FindStringSubmatch(line)

			checksumFile.ChecksumType = TypeMD5
			checksumFile.Filename     = matches[1]
			checksumFile.ChecksumWant = matches[2]
		} else if reSha1.MatchString(line) {
			matches := reSha1.FindStringSubmatch(line)

			checksumFile.ChecksumType = TypeSHA1
			checksumFile.Filename     = matches[2]
			checksumFile.ChecksumWant = matches[1]
		} else if reSha256.MatchString(line) {
			matches := reSha256.FindStringSubmatch(line)

			checksumFile.ChecksumType = TypeSHA256
			checksumFile.Filename     = matches[2]
			checksumFile.ChecksumWant = matches[1]
		} else {
			// Unknown checksum type
			continue
		}

		verifyChecksumFile(&checksumFile)
		totalFileSize += checksumFile.Filesize

		checksumFiles = append(checksumFiles, checksumFile)
	}

	return totalFileSize, checksumFiles
}

func WriteToFile(checksumFiles []ChecksumFile, filename string) {
	var file *os.File
	var err error

	if filename != "" {
		file, err = os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()
	} else {
		file = os.Stdout
	}

	date := time.Now().UTC().Format(time.RFC3339)
	file.WriteString(fmt.Sprintf("; Generated by gosfv version %s(%s) at %s\n", Version, Commit, date))
	for _, checksumFile := range checksumFiles {
		if checksumFile.Status == StatusCheckSumOK {
			switch checksumFile.ChecksumType {
			case TypeCRC32:
				_, err = file.WriteString(fmt.Sprintf("%s %s\n", checksumFile.Filename, checksumFile.Checksum))
			case TypeMD5:
				_, err = file.WriteString(fmt.Sprintf("MD5 (%s) = %s\n", checksumFile.Filename, checksumFile.Checksum))
			case TypeSHA1:
				_, err = file.WriteString(fmt.Sprintf("%s  %s\n", checksumFile.Checksum, checksumFile.Filename))
			case TypeSHA256:
				_, err = file.WriteString(fmt.Sprintf("%s  %s\n", checksumFile.Checksum, checksumFile.Filename))
			}

			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func calculateChecksum(checksumFile *ChecksumFile, pb *pb.ProgressBar) {
	if checksumFile.Status != StatusOK {
		return
	}

	// Initial stat of file have already been handled, so no need to verify errors
	// of opening the file
	file, _ := os.Open(checksumFile.Filename)
	defer file.Close()

	var hasher hasherInfo
	switch checksumFile.ChecksumType {
	case TypeCRC32:
		hasher.hash32 = crc32.NewIEEE()
		hasher.buf = make([]byte, hasher.hash32.BlockSize())
	case TypeMD5:
		hasher.hash = md5.New()
		hasher.buf = make([]byte, md5.BlockSize)
	case TypeSHA1:
		hasher.hash = sha1.New()
		hasher.buf = make([]byte, sha1.BlockSize)
	case TypeSHA256:
		hasher.hash = sha256.New()
		hasher.buf = make([]byte, sha256.BlockSize)
	}

	reader := bufio.NewReader(file)
	for {
		count, err := reader.Read(hasher.buf)
		if err != nil {
			if err != io.EOF {
				checksumFile.Status = StatusFailedCheckSum
			}
			break
		}

		switch checksumFile.ChecksumType {
		case TypeCRC32:
			hasher.hash32.Write(hasher.buf[:count])
		case TypeMD5:
			hasher.hash.Write(hasher.buf[:count])
		case TypeSHA1:
			hasher.hash.Write(hasher.buf[:count])
		case TypeSHA256:
			hasher.hash.Write(hasher.buf[:count])
		}

		pb.Add(count)
	}

	switch checksumFile.ChecksumType {
	case TypeCRC32:
		checksumFile.Status = StatusCheckSumOK
		checksumFile.Checksum = fmt.Sprintf("%x", hasher.hash32.Sum32())
	case TypeMD5:
		checksumFile.Status = StatusCheckSumOK
		checksumFile.Checksum = fmt.Sprintf("%x", hasher.hash.Sum(nil))
	case TypeSHA1:
		checksumFile.Status = StatusCheckSumOK
		checksumFile.Checksum = fmt.Sprintf("%x", hasher.hash.Sum(nil))
	case TypeSHA256:
		checksumFile.Status = StatusCheckSumOK
		checksumFile.Checksum = fmt.Sprintf("%x", hasher.hash.Sum(nil))
	}
}

func verifyChecksumFile(checksumFile *ChecksumFile) {
	file, err := os.Open(checksumFile.Filename)
	defer file.Close()
	if err != nil {
		checksumFile.Status = StatusNotFound
		return
	}

	fileInfo, err := file.Stat()
	if err != nil {
		checksumFile.Status = StatusStatFailed
		return
	}

	if fileInfo.IsDir() {
		checksumFile.Status = StatusNotFile
		return
	}

	checksumFile.Status   = StatusOK
	checksumFile.Filesize = fileInfo.Size()
}

func createChecksumFile(t ChecksumType, filename string) ChecksumFile {
	checksumFile := ChecksumFile{t, StatusUnknown, filename, 0, "", ""}

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		checksumFile.Status = StatusNotFound
	} else {
		fileInfo, err := file.Stat()
		if err != nil {
			checksumFile.Status = StatusStatFailed
			goto end
		}

		if fileInfo.IsDir() {
			checksumFile.Status = StatusNotFile
			goto end
		}

		checksumFile.Status   = StatusOK
		checksumFile.Filesize = fileInfo.Size()
	}

end:
	return checksumFile
}