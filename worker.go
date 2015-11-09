package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/iron-io/iron_go3/api"
	"github.com/iron-io/iron_go3/worker"
)

func dockerLogin(w *worker.Worker, args *map[string]string) (msg string, err error) {

	data, err := json.Marshal(args)
	reader := bytes.NewReader(data)

	req, err := http.NewRequest("POST", api.Action(w.Settings, "credentials").URL.String(), reader)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip/deflate")
	req.Header.Set("Authorization", "OAuth "+w.Settings.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", w.Settings.UserAgent)

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if err = api.ResponseAsError(response); err != nil {
		return "", err
	}

	var res struct {
		Msg string `json:"msg"`
	}

	err = json.NewDecoder(response.Body).Decode(&res)
	return res.Msg, err

}

// create code package (zip) from parsed .worker info
func pushCodes(zipName string, w *worker.Worker, args worker.Code) (*worker.Code, error) {
	// TODO i don't get why i can't write from disk to wire, but I give up
	var body bytes.Buffer
	mWriter := multipart.NewWriter(&body)
	mMetaWriter, err := mWriter.CreateFormField("data")
	if err != nil {
		return nil, err
	}

	jEncoder := json.NewEncoder(mMetaWriter)
	if err := jEncoder.Encode(args); err != nil {
		return nil, err
	}

	if zipName != "" {
		r, err := zip.OpenReader(zipName)
		if err != nil {
			return nil, err
		}
		defer r.Close()

		mFileWriter, err := mWriter.CreateFormFile("file", "worker.zip")
		if err != nil {
			return nil, err
		}
		zWriter := zip.NewWriter(mFileWriter)

		for _, f := range r.File {
			fWriter, err := zWriter.Create(f.Name)
			if err != nil {
				return nil, err
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			_, err = io.Copy(fWriter, rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
		}

		zWriter.Close()
	}
	mWriter.Close()

	req, err := http.NewRequest("POST", api.Action(w.Settings, "codes").URL.String(), &body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip/deflate")
	req.Header.Set("Authorization", "OAuth "+w.Settings.Token)
	req.Header.Set("Content-Type", mWriter.FormDataContentType())
	req.Header.Set("User-Agent", w.Settings.UserAgent)

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if err = api.ResponseAsError(response); err != nil {
		return nil, err
	}

	var data worker.Code
	err = json.NewDecoder(response.Body).Decode(&data)
	return &data, err
}

// TODO we should probably support other functions at
// some point so that people have a choice.
//
// - expects a hex encoded key of length 16, 24, or 32 bytes [decoded]
//   to select AES-128, AES-192, or AES-256.
// - returns a base64 ciphertext with a new, random iv in the first 16 bytes
//   of the cipher
func aesEncrypt(publicKeyHex, payloadPlain string) (string, error) {
	key, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	pbytes := []byte(payloadPlain)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(pbytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], pbytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
