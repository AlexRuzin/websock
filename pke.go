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
    "time"
    "bytes"
    "strings"
    "crypto"
    "crypto/md5"
    "crypto/rand"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/gob"
    "hash/crc64"
    "net/http"

    "github.com/wsddn/go-ecdh"

    "github.com/AlexRuzin/cryptog"
    "github.com/AlexRuzin/util"
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

func (f *NetChannelClient) decodeServerPubkeyGenSecret(publicKeyRaw []byte, privateKey crypto.PrivateKey, curve ecdh.ECDH) (
    secret []byte, err error) {

    decoded, err := util.B64D(string(publicKeyRaw))
    if err != nil {
        return nil, err
    }

    var responsePool = bytes.Buffer{}
    responsePool.Write(decoded)

    var xorKey = make([]byte, crc64.Size)
    var xordMarshaled = make([]byte, len(decoded) - crc64.Size - md5.Size)
    var clientId = make([]byte, md5.Size)

    responsePool.Read(xorKey)
    responsePool.Read(xordMarshaled)
    marshalled := func (xorKey []byte, encoded []byte) []byte {
        output := make([]byte, len(encoded))
        copy(output, encoded)
        counter := 0
        for k := range output {
            if counter == len(xorKey) {
                counter = 0
            }

            output[k] ^= xorKey[counter]
            counter += 1
        }
        return output
    } (xorKey, xordMarshaled)
    responsePool.Read(clientId)

    f.clientId = clientId
    f.clientIdString = hex.EncodeToString(f.clientId)

    serverPubKey, ok := curve.Unmarshal(marshalled)
    if !ok {
        return nil, util.RetErrStr("Failed to unmarshal server-side public key")
    }

    /* Generate the secret finally */
    var secretGenStatus error = nil
    secret, secretGenStatus = curve.GenerateSharedSecret(privateKey, serverPubKey)
    if err != secretGenStatus || len(secret) == 0 {
        return nil, secretGenStatus
    }

    return secret, nil
}

func (f *NetChannelClient) generateCurvePostRequest(config *ProtocolConfig) (
    ec ecdh.ECDH,
    req map[string]string,
    privateKey crypto.PrivateKey,
    genStatus error) {

    genStatus = nil

    /*
     * Generate the ECDH keys based on the EllipticP384 Curve/create keypair
     */
    var publicKey crypto.PublicKey
    curve := ecdh.NewEllipticECDH(elliptic.P384())
    var keypairStatus error = nil
    privateKey, publicKey, keypairStatus = curve.GenerateKey(rand.Reader)
    if keypairStatus != nil {
        return nil, nil, nil, keypairStatus
    }
    var pubKeyMarshalled = curve.Marshal(publicKey)

    /*
     * Generate the b64([xor][marshalled][md5sum]) buffer
     */
    postPool, err := f.genTxPool(pubKeyMarshalled)
    if err != nil || len(postPool) < 1 {
        return nil, nil, nil, err
    }

    /* generate fake key/value pools */
    outMap := make(map[string]string)
    numOfParameters := util.RandInt(3, config.PostBodyJunkLen)

    magicNumber := numOfParameters / 2
    for i := numOfParameters; i != 0; i -= 1 {
        var pool, key string
        if config.PostBodyValueLength != -1 {
            pool = encodeKeyValue(config.PostBodyValueLength)
        } else {
            pool = encodeKeyValue(len(string(postPool)) * 2)
        }
        key = encodeKeyValue(config.PostBodyKeyLength)

        /* This value must not be any of the b64 encoded POST_BODY_KEY_CHARSET values -- true == collision */
        if collision := f.checkForKeyCollision(key, config.PostBodyKeyCharset); collision == true {
            i += 1 /* Fix the index */
            continue
        }

        if i == magicNumber {
            parameter := string(config.PostBodyKeyCharset[util.RandInt(0, len(config.PostBodyKeyCharset))])
            outMap[util.B64E([]byte(parameter))] = string(postPool)
            continue
        }

        outMap[key] = pool
    }

    ec          = curve
    req         = outMap
    genStatus   = nil
    return
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

/* Sanity test for POST_BODY_KEY_CHARSET */
func testCharSetPKE(charset string) bool {

    var elementCount = 0
    for _, k := range charset {
        elementCount = 0
        for _, c := range charset {
            if k == c {
                elementCount += 1
            }
        }

        if elementCount != 1 {
            return false
        }
    }

    return true
}

/* EOF */
