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
    _"io"
    "bytes"
    "net/http"
    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/md5"
    "hash/crc64"
    "encoding/base64"
    "crypto"
)

/************************************************************
 * netcp Server objects and methods                         *
 ************************************************************/
// Server processor methods
type ServerProcessor struct {}

type NetChannelService struct {
    Port int16
    Flags int
    PathGate string
    PrivateKey *crypto.PrivateKey
    PublicKey *crypto.PublicKey
    ClientPublicKey *crypto.PublicKey
    serverProcessor ServerProcessor
}

/* Create circuit -OR- process gate requests */
func handleClientRequest(writer http.ResponseWriter, reader *http.Request) {
    service := NetChannelService{
        Port:  80,
        Flags: 0,
        PathGate: reader.URL.Path,
        PrivateKey: nil,
        PublicKey: nil,
        ClientPublicKey: nil,
        serverProcessor: ServerProcessor{},
    }

    /* Get remote client public key base64 marshalled string */
    if err := reader.ParseForm(); err != nil {
        util.DebugOut(err.Error())
        return
    }
    const cs = POST_BODY_KEY_CHARSET
    var b64_marshalled_client_pub_key *string = nil
    for key := range reader.Form {
        for i := len(POST_BODY_KEY_CHARSET); i != 0; i -= 1 {
            var tmp_key = string(cs[i - 1])
            if tmp_key == key {
                b64_marshalled_client_pub_key = &reader.Form[key][0]
                break
            }
        }
        if b64_marshalled_client_pub_key != nil {
            break
        }
    }

    /* Parse client-side public ECDH key*/
    client_pubkey, elliptic, err := service.serverProcessor.getClientPublicKey(*b64_marshalled_client_pub_key, &service)
    if err != nil || client_pubkey == nil {
        service.serverProcessor.sendBadErrorCode(writer, err)
        util.DebugOut(err.Error())
        return
    }
    service.ClientPublicKey = client_pubkey

    /*
     * Since the client public key is nominal return generate
     *  our own keypair
     */
    serverPrivateKey, serverPublicKey, err := elliptic.GenerateKey(rand.Reader)
    if err != nil {
        service.serverProcessor.sendBadErrorCode(writer, err)
        return
    }
    service.PublicKey = &serverPublicKey
    service.PrivateKey = &serverPrivateKey

    /* Transmit the server public key */

    /* Generate the secret */
    secret, err := elliptic.GenerateSharedSecret(service.PrivateKey, service.ClientPublicKey)
    if len(secret) == 0 {
        service.serverProcessor.sendBadErrorCode(writer, errors.New("unmarshalling failed"))
        return
    }

    util.DebugOut("done")
}

func (ServerProcessor) getClientPublicKey(buffer string,
    server *NetChannelService) (pubkey *crypto.PublicKey, curve ecdh.ECDH, err error) {
    /*
     * Read in an HTTP request in the following format:
     *  b64([8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2])
     */
    b64_decoded, err := base64.StdEncoding.DecodeString(buffer)
    if err != nil {
        return nil, nil, err
    }
    var xor_key = make([]byte, crc64.Size)
    copy(xor_key, b64_decoded[:crc64.Size])
    var marshal_xor = make([]byte, len(b64_decoded) - crc64.Size - md5.Size)
    var sum = make([]byte, md5.Size)
    copy(sum, b64_decoded[len(xor_key) + len(marshal_xor):])

    sum_buffer := make([]byte, len(b64_decoded) - md5.Size)
    copy(sum_buffer, b64_decoded[:len(b64_decoded) - md5.Size])
    new_sum := md5.Sum(sum_buffer)
    if !bytes.Equal(new_sum[:], sum) {
        return nil, nil, errors.New("error: Data integrity mismatch")
    }

    copy(marshal_xor, b64_decoded[crc64.Size:len(b64_decoded) - md5.Size])
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
    } (xor_key, marshal_xor)

    ecurve := ecdh.NewEllipticECDH(elliptic.P384())
    clientPublicKey, ok := ecurve.Unmarshal(marshalled)
    if !ok {
        return nil, nil, errors.New("unmarshalling failed")

    }

    return &clientPublicKey, ecurve,nil
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