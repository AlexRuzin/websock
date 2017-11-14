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

package netcp

import (
    "errors"
    "io"
    "bytes"
    "net/http"
    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/md5"
    "hash/crc64"
    "encoding/base64"
)

/************************************************************
 * netcp Server objects and methods                         *
 ************************************************************/

type NetChannelService struct {
    Port int16
    Flags int
    PathGate string
}

// Server processor methods
type ServerProcessor struct {}

/* Create circuit -OR- process gate requests */
func handleClientRequest(writer http.ResponseWriter, reader *http.Request) {
    serverProcessor := ServerProcessor{}

    /* Get remote client public key structure */
    body_raw, err := reader.GetBody()
    if err != nil {
        serverProcessor.sendBadErrorCode(writer, err)
        return
    }
    body_raw_vector := make([]byte, reader.ContentLength)
    body_raw.Read(body_raw_vector)

    /* Parse client-side public ECDH key*/
    marshalled, err := serverProcessor.getMarshalledPubKey(body_raw_vector)
    if err != nil || len(marshalled) == 0 {
        serverProcessor.sendBadErrorCode(writer, err)
        return
    }

    curve := ecdh.NewEllipticECDH(elliptic.P384())
    clientPrivateKey, _, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        serverProcessor.sendBadErrorCode(writer, err)
        return
    }
    clientPublicKey, ok := curve.Unmarshal(marshalled)
    if !ok {
        serverProcessor.sendBadErrorCode(writer, errors.New("unmarshalling failed"))
        return
    }

    secret, err := curve.GenerateSharedSecret(clientPrivateKey, clientPublicKey)
    if len(secret) == 0 {
        serverProcessor.sendBadErrorCode(writer, errors.New("unmarshalling failed"))
        return
    }
}

func (ServerProcessor) getMarshalledPubKey(buffer []byte) (marshalled []byte, err error) {
    /*
     * Read in an HTTP request in the following format:
     *  b64([8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2])
     */
    b64_decoded, err := base64.StdEncoding.DecodeString(string(buffer))
    if err != nil {
        return nil, err
    }

    var raw_buffer = bytes.Buffer{}
    raw_buffer.Write(b64_decoded)

    var xor_key = make([]byte, crc64.Size)
    r, err := raw_buffer.Read(xor_key)
    if err != nil || r != len(xor_key) {
        return nil, err
    }

    var marshal_buf = make([]byte, raw_buffer.Len() - md5.Size)
    r, err = raw_buffer.Read(marshal_buf)
    if err != nil || r != (len(b64_decoded) - md5.Size) {
        return nil, err
    }

    var sum = make([]byte, md5.Size)
    r, err = raw_buffer.Read(sum)
    if err != io.EOF || r != md5.Size {
        return nil, err
    }

    sum_status := func (key []byte, marshal_buf []byte, known_sum []byte) bool {
        tmp := bytes.Buffer{}
        tmp.Write(key)
        tmp.Write(marshal_buf)
        new_sum := md5.Sum(tmp.Bytes())
        if bytes.Equal(new_sum[:], known_sum) {
            return true
        }
        return false
    } (xor_key, marshal_buf, sum)
    if sum_status == false {
        return nil, util.ThrowError("Corrupt client ECDH key buffer")
    }

    out_buf := func (key []byte, pool []byte) []byte {
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
    } (xor_key, marshal_buf)
    return out_buf, nil
}

/* HTTP 500 - Internal Server Error */
func (ServerProcessor) sendBadErrorCode(writer http.ResponseWriter, err error) {
    writer.WriteHeader(http.StatusInternalServerError)
    writer.Write([]byte("500 - " + err.Error()))
    return
}

/* HTTP 200 OK */
func (ServerProcessor) sendGoodErrorCode(writer http.ResponseWriter) {
    writer.WriteHeader(http.StatusOK)
    return
}

func CreateNetCPServer(path_gate string, port int16, flags int) (*NetChannelService, error) {
    var io_server = &NetChannelService{
        Port: port,
        Flags: flags,
        PathGate: path_gate,
    }

    go func(svc *NetChannelService) {
        http.HandleFunc(io_server.PathGate, handleClientRequest)
        util.DebugOut("[+] Handling request for path :" + svc.PathGate)
        if err := http.ListenAndServe(":" + util.IntToString(int(io_server.Port)),nil); err != nil {
            util.ThrowN("panic: Failure in loading httpd")
        }
    } (io_server)

    return io_server, nil
}