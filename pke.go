/*
 * Copyright (c) 2017 AlexRuzin (stan.ruzin@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package websock

import (
    "github.com/AlexRuzin/util"
    "time"
    "crypto/md5"
    "crypto/rand"
    "encoding/hex"
    "bytes"
    "encoding/gob"
    "github.com/AlexRuzin/cryptog"
    "hash/crc64"
    "strings"
    "net/http"
)

func encryptData(data []byte, secret []byte, directionFlags FlagVal, otherFlags FlagVal, clientId string) (encrypted []byte, err error) {
    if len(data) == 0 {
        return nil, util.RetErrStr("Invalid parameters for encryptData")
    }
    err = util.RetErrStr("encryptData: Unknown error")

    /* Transmission object */
    tx := &TransferUnit{
        ClientID:           clientId,
        TimeStamp: func () string {
            return time.Now().String()
        } (),
        Data: make([]byte, len(data)),
        DecryptedSum: func (p []byte) string {
            dataSum := md5.Sum(data)
            return hex.EncodeToString(dataSum[:])
        } (data),
        Direction:          directionFlags,
        Flags:              otherFlags,
    }
    copy(tx.Data, data)

    txStream, err := func(tx TransferUnit) ([]byte, error) {
        b := new(bytes.Buffer)
        e := gob.NewEncoder(b)
        if err := e.Encode(tx); err != nil {
            return nil, err
        }
        return b.Bytes(), nil
    } (*tx)
    if err != nil {
        return nil, err
    }

    output, err := cryptog.RC4_Encrypt(txStream, cryptog.RC4_PrepareKey(secret))
    if err != nil {
        return nil, err
    }
    encrypted = output
    err = nil

    return
}

func (f *NetChannelClient) genTxPool(pubKeyMarshalled []byte) ([]byte, error) {
    /***********************************************************************************************
     * Transmits the public key ECDH key to server. The transmission buffer contains:              *
     *  b64([8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2])  *
     ***********************************************************************************************/
    var pool = bytes.Buffer{}
    xorKey := make([]byte, crc64.Size)
    rand.Read(xorKey)
    pool.Write(xorKey)
    marshalEncrypted := make([]byte, len(pubKeyMarshalled))
    copy(marshalEncrypted, pubKeyMarshalled)
    counter := 0
    for k := range marshalEncrypted {
        if counter == len(xorKey) {
            counter = 0
        }
        marshalEncrypted[k] ^= xorKey[counter]
        counter += 1
    }
    pool.Write(marshalEncrypted)
    poolSum := md5.Sum(pool.Bytes())
    pool.Write(poolSum[:])

    b64Buf := util.B64E(pool.Bytes())
    return []byte(b64Buf), nil
}

func encodeKeyValue (high int) string {
    return func (h int) string {
        return util.B64E([]byte(util.RandomString(util.RandInt(1, high))))
    } (high)
}

func (f *NetChannelClient) checkForKeyCollision(key string, char_set string) (out bool) {
    /* FIXME -- this should be consolidated code */
    out = false
    var keyVector = make([]string, len(char_set))
    for i := len(char_set) - 1; i >= 0; i -= 1 {
        keyVector[i] = util.B64E([]byte(string(char_set[i])))
    }

    for i := range keyVector {
        if bytes.Equal([]byte(key), []byte(keyVector[i])) {
            out = true
            break
        }
    }

    return
}

func getClientPublicKey(buffer string) (marshalledPublicKey []byte, err error) {
    /*
     * Read in an HTTP request in the following format:
     *  b64([8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2])
     */
    b64Decoded, err := util.B64D(buffer)
    if err != nil {
        return nil, err
    }
    var xorKey = make([]byte, crc64.Size)
    copy(xorKey, b64Decoded[:crc64.Size])
    var marshalXor = make([]byte, len(b64Decoded) - crc64.Size - md5.Size)
    var sum = make([]byte, md5.Size)
    copy(sum, b64Decoded[len(xorKey) + len(marshalXor):])

    sumBuffer := make([]byte, len(b64Decoded) - md5.Size)
    copy(sumBuffer, b64Decoded[:len(b64Decoded) - md5.Size])
    newSum := md5.Sum(sumBuffer)
    if !bytes.Equal(newSum[:], sum) {
        return nil, util.RetErrStr("Data integrity mismatch")
    }

    copy(marshalXor, b64Decoded[crc64.Size:len(b64Decoded) - md5.Size])
    marshalled := func (key []byte, pool []byte) []byte {
        var output = make([]byte, len(pool))
        copy(output, pool)

        counter := 0
        for k := range pool {
            if counter == 8 {
                counter = 0
            }
            output[k] = output[k] ^ key[counter]
            counter += 1
        }

        return output
    } (xorKey, marshalXor)

    return marshalled, nil
}

func decryptData(b64Encoded string, secret []byte) (clientId string, rawData []byte, txUnit *TransferUnit, status error) {
    status      = util.RetErrStr("decryptData: Unknown error")
    clientId    = ""
    rawData     = nil
    txUnit      = nil

    b64Decoded, err := util.B64D(b64Encoded)
    if err != nil {
        status = err
        return
    }

    decrypted, err := cryptog.RC4_Decrypt(b64Decoded, cryptog.RC4_PrepareKey(secret))
    if err != nil {
        status = err
        return
    }

    var decodeStatus error = nil
    txUnit, decodeStatus = func(raw []byte) (*TransferUnit, error) {
        output := new(TransferUnit)

        p := &bytes.Buffer{}
        p.Write(raw)
        d := gob.NewDecoder(p)
        if err := d.Decode(output); err != nil {
            return nil, err
        }

        return output, nil
    } (decrypted)
    if decodeStatus != nil || txUnit == nil {
        status = decodeStatus
        return
    }

    newSum := func (p []byte) string {
        dataSum := md5.Sum(p)
        return hex.EncodeToString(dataSum[:])
    } (txUnit.Data)
    if strings.Compare(newSum, txUnit.DecryptedSum) != 0 {
        status = util.RetErrStr("decryptData: Data corruption")
        return
    }

    rawData     = txUnit.Data
    clientId    = txUnit.ClientID
    status      = nil
    return
}

/* Send back server pub key */
func sendPubKey(writer http.ResponseWriter, marshalled []byte, clientId []byte) error {
    var pool = bytes.Buffer{}
    var xorKey = make([]byte, crc64.Size)
    rand.Read(xorKey)
    pool.Write(xorKey)
    marshaledXor := make([]byte, len(marshalled))
    copy(marshaledXor, marshalled)
    counter := 0
    for k := range marshaledXor {
        if counter == len(xorKey) {
            counter = 0
        }

        marshaledXor[k] ^= xorKey[counter]
        counter += 1
    }
    pool.Write(marshaledXor)
    pool.Write(clientId)

    if err := sendResponse(writer, pool.Bytes()); err != nil {
        return err
    }

    return nil
}

/* EOF */
