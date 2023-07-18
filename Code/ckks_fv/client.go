package ckks_fv

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ldsec/lattigo/v2/utils"
)

type Client interface {
	EncryptMessage(message [][]float64, key []uint64) ([]*PlaintextRingT, []*Ciphertext)
	GenerateRandomKey() []uint64
	EncryptTemplate(template Template, key []uint64) ([]*PlaintextRingT, []*Ciphertext)
	EncryptMultipleTemplates(templates []Template, key []uint64, rows int, columns int) ([]*PlaintextRingT, []*Ciphertext)
	EncryptMultipleTemplatesTiming(templates []Template, key []uint64, rows int, columns int) ([]*PlaintextRingT, []*Ciphertext, float64, float64)
	//DataToComplex(data [][]float64) []complex128
}
type client struct {
	hera        MFVHera
	shared      Shared
	ckksEncoder CKKSEncoder
	needReset   bool
}

func NewClient(shared Shared) Client {
	nclient := new(client)
	nclient.shared = shared
	nclient.hera = NewMFVHera(shared.GetNumRounds(), shared.GetParams(), shared.GetFvEncoder(), shared.GetFvEncryptor(), shared.GetFvEvaluator(), shared.GetHeraModDown()[0])
	nclient.ckksEncoder = NewCKKSEncoder(shared.GetParams())
	nclient.needReset = false
	return nclient
}

func (client *client) generateKeyStreamFromNoncesAndKey(numRound int, nonces [][]byte, key []uint64, plainModulus uint64) [][]uint64 {
	keystream := make([][]uint64, client.shared.GetMessagesSize())
	for i := 0; i < client.shared.GetMessagesSize(); i++ {
		keystream[i] = plHera(numRound, nonces[i], key, plainModulus)
	}
	return keystream
}

func (client *client) GenerateRandomKey() []uint64 {
	maxKey := 99999999999
	if client.shared.GetFullCoeffs() {
		maxKey = 999
	}
	//var key []uint64
	key := make([]uint64, 16)
	for i := 0; i < 16; i++ {
		//key[i] = uint64(i + 2) // Use (1, ..., 16) for testing
		key[i] = uint64(rand.Intn(maxKey)) // if we use randint it get's too big and the result is far off (result is like 299 instead of 13)
	}
	return key
}
func (client *client) generateCoeffsFromData(data [][]float64) [][]float64 {
	coeffs := make([][]float64, 16)
	for s := 0; s < 16; s++ {
		coeffs[s] = make([]float64, client.shared.GetParams().N())
	}

	for s := 0; s < 16; s++ {
		for i := 0; i < client.shared.GetMessagesSize()/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(client.shared.GetParams().logN-1))
			coeffs[s][j] = data[s][i]
			coeffs[s][j+uint64(client.shared.GetParams().N()/2)] = data[s][i+client.shared.GetMessagesSize()/2]
		}
	}
	return coeffs
}

func (client *client) encCoeffsKeystreamToCkksPtRing(coeffs [][]float64, keystream [][]uint64) []*PlaintextRingT {
	var plainCKKSRingTs []*PlaintextRingT
	//var ckksEncoder CKKSEncoder

	plainCKKSRingTs = make([]*PlaintextRingT, 16)

	for s := 0; s < 16; s++ {
		plainCKKSRingTs[s] = client.ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], client.shared.GetMessageScaling())
		poly := plainCKKSRingTs[s].Value()[0]
		for i := 0; i < client.shared.GetMessagesSize(); i++ {
			j := utils.BitReverse64(uint64(i), uint64(client.shared.GetParams().LogN()))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % client.shared.GetParams().PlainModulus()
		}
	}
	return plainCKKSRingTs
}

func (client *client) encryptPlain(message [][]float64, key []uint64) []*PlaintextRingT {
	keystream := client.generateKeyStreamFromNoncesAndKey(client.shared.GetNumRounds(), client.shared.GetNonces(), key, client.shared.GetParams().plainModulus)
	coeffs := client.generateCoeffsFromData(message)
	plainCKKSRingTs := client.encCoeffsKeystreamToCkksPtRing(coeffs, keystream)
	return plainCKKSRingTs
}

func (client *client) encCoeffsHeraCt(coeffs [][]float64, keystream []*Ciphertext) []*PlaintextRingT {
	var plainCKKSRingTs []*PlaintextRingT
	//var ckksEncoder CKKSEncoder

	plainCKKSRingTs = make([]*PlaintextRingT, 16)
	for s := 0; s < 16; s++ {
		plainCKKSRingTs[s] = client.ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], client.shared.GetMessageScaling())
		poly := plainCKKSRingTs[s].Value()[0]
		for i := 0; i < client.shared.GetMessagesSize(); i++ {
			j := utils.BitReverse64(uint64(i), uint64(client.shared.GetParams().LogN()))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j]) % client.shared.GetParams().PlainModulus()
			//poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % client.shared.Params().PlainModulus()
		}
	}
	return plainCKKSRingTs
}

func (client *client) EncryptMessage(message [][]float64, key []uint64) ([]*PlaintextRingT, []*Ciphertext) {
	//call reset before encrypting a second message
	//if !client.needReset {
	//	client.hera.Reset(client.shared.HeraModDown()[0])
	//}
	encKey := client.hera.EncKey(key)
	client.needReset = true
	fmt.Printf("Key plain: %v \nKey HeraEnc: %v\n", key, encKey)
	return client.encryptPlain(message, key), encKey
}

func (client *client) TemplateToData(template []float64, rows int, columns int) [][]float64 {
	data := make([][]float64, 16)
	for s := 0; s < 16; s++ {
		data[s] = make([]float64, client.shared.GetMessagesSize())
		for i := 0; i < client.shared.GetMessagesSize(); i++ {
			if s >= rows || i >= columns {
				data[s][i] = 0.0
				//if fullCoeffs are used there will be 16 ct of length 2**15(=32768) and template fits into 1. ct
			} else if client.shared.GetFullCoeffs() {
				if s == 0 && i < len(template) {

					data[s][i] = template[i]
					//fmt.Printf("data[%v][%v] %6.3f == template[%v] %6.3f\n", s, i, data[s][i], i, template.GetData()[i])
				} else {
					data[s][i] = 0.0
				}
				//if !fullCoeffs then template needs to be put into 16x16 format
			} else {
				t := s*client.shared.GetMessagesSize() + i
				if t < len(template) {
					data[s][i] = template[t]
				} else {
					data[s][i] = 0.0
				}
			}
		}
	}
	return data
}

func (client *client) EncryptTemplate(template Template, key []uint64) ([]*PlaintextRingT, []*Ciphertext) {
	templen := 16
	if client.shared.GetFullCoeffs() {
		templen = len(template.GetData())
	}
	data := client.TemplateToData(template.GetData(), 16, templen)
	//println("template Converted: ", data)
	encKey := client.hera.EncKey(key)
	client.needReset = true
	fmt.Printf("Key plain: %v \nKey HeraEnc: %v\n", key, encKey)
	return client.encryptPlain(data, key), encKey
}

func (client *client) EncryptTemplatRowsColumns(template Template, key []uint64, rows int, columns int) ([]*PlaintextRingT, []*Ciphertext) {
	data := client.TemplateToData(template.GetData(), rows, columns)
	//println("template Converted: ", data)
	encKey := client.hera.EncKey(key)
	client.needReset = true
	fmt.Printf("Key plain: %v \nKey HeraEnc: %v\n", key, encKey)
	return client.encryptPlain(data, key), encKey
}

func (client *client) EncryptMultipleTemplates(templates []Template, key []uint64, rows int, columns int) ([]*PlaintextRingT, []*Ciphertext) {
	data := client.TemplateToData(ConnectTemplates(templates), rows, columns)
	//println("template Converted: ", data)
	encKey := client.hera.EncKey(key)
	client.needReset = true
	fmt.Printf("Key plain: %v \nKey HeraEnc: %v\n", key, encKey)
	return client.encryptPlain(data, key), encKey
}

//sym, encKey, symTime, heTime
func (client *client) EncryptMultipleTemplatesTiming(templates []Template, key []uint64, rows int, columns int) ([]*PlaintextRingT, []*Ciphertext, float64, float64) {
	data := client.TemplateToData(ConnectTemplates(templates), rows, columns)
	//println("template Converted: ", data)
	start := time.Now()
	encKey := client.hera.EncKey(key)
	heTime := time.Since(start).Seconds()
	start = time.Now()
	sym := client.encryptPlain(data, key)
	symTime := time.Since(start).Seconds()
	client.needReset = true
	//fmt.Printf("Key plain: %v \nKey HeraEnc: %v\n", key, encKey)
	return sym, encKey, symTime, heTime
}
