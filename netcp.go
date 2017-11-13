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
    "net/http"
    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
    "net/url"
    "errors"
    "strings"
    "crypto/elliptic"
    "crypto/rand"
    "bytes"
    "hash/crc64"
    "crypto/md5"
    "encoding/base64"
    "time"
    "io"
)

/*
 * Configuration
 */
const POST_PARAM_NAME = "l"
const USE_METHOD_GET = false
const USE_METHOD_POST = true

/*
 * Constants
 */
const METHOD_GET = "GET"
const METHOD_POST = "POST"

/*
 * Writer objects
 */
type Writer struct {
    s int
}

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
func requestHandlerGate(writer http.ResponseWriter, reader *http.Request) {
    serverProcessor := ServerProcessor{}

    body_raw, err := reader.GetBody()
    if err != nil {
        serverProcessor.sendBadErrorCode(writer, err)
        return
    }
    body_raw_vector := make([]byte, reader.ContentLength)
    body_raw.Read(body_raw_vector)
    marshalled, err := serverProcessor.getMarshalledPubKey(body_raw_vector)
    if err != nil || len(marshalled) == 0 {
        serverProcessor.sendBadErrorCode(writer, err)
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

    var xor_key = make([]byte, 8)
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

    return nil, nil
}

/* HTTP 500 - Internal Server Error */
func (ServerProcessor) sendBadErrorCode(writer http.ResponseWriter, err error) {
    writer.WriteHeader(http.StatusInternalServerError)
    writer.Write([]byte("500 - " + err.Error()))
    return
}

/* HTTP 200 OK */
func (ServerProcessor) sendGoodErrorCOde(writer http.ResponseWriter) {
    writer.WriteHeader(http.StatusOK)
    return
}

func CreateNetCPServer(path_gate string, port int16, flags int) (*NetChannelService, error) {
    if err := configCheck(); err != nil {
        return nil, err
    }

    var io_server = &NetChannelService{
        Port: port,
        Flags: flags,
        PathGate: path_gate,
    }

    go func(svc *NetChannelService) {
        http.HandleFunc(io_server.PathGate, requestHandlerGate)
        util.DebugOut("[+] Handling request for path :" + svc.PathGate)
        if err := http.ListenAndServe(":" + util.IntToString(int(io_server.Port)),nil); err != nil {
            util.ThrowN("panic: Failure in loading httpd")
        }
    } (io_server)

    return io_server, nil
}


/************************************************************
 * netcp Client objects and methods                         *
 ************************************************************/

type NetChannelClient struct {
    InputURI string
    Port int16
    Flags int
    Connected bool
    Path string
    Host string
    URL *url.URL
}

func BuildNetCPChannel(gate_uri string, port int16, flags int) (*NetChannelClient, error) {
    if err := configCheck(); err != nil {
        return nil, err
    }

    url, err := url.Parse(gate_uri)
    if err != nil {
        return nil, err
    }
    if url.Scheme != "http" {
        return nil, errors.New("error: HTTP scheme must not use TLS")
    }

    var io_channel = &NetChannelClient{
        URL: url,
        InputURI: gate_uri,
        Port: port,
        Flags: 0,
        Connected: false,
        Path: url.Path,
        Host: url.Host,
    }

    return io_channel, nil
}

/*
 * Check if the TCP port is reachcable, then attempt to determine
 *  if our service is running on it
 */
func (f *NetChannelClient) InitializeCircuit() error {
    /*
     * Configuration for HTTP communication
     */
    var POST_STRING string
    if USE_METHOD_POST == true {
        POST_STRING = METHOD_POST
    } else {
        POST_STRING = METHOD_GET
    }

    post_pool, err := f.genTxPool()
    if err != nil || len(post_pool) < 1 {
        return err
    }

    form := url.Values{}
    form.Add(POST_PARAM_NAME, base64.StdEncoding.EncodeToString(post_pool))
    //form.Encode()

    /* Perform HTTP TX */
    resp, tx_err := func(method string, URI string, body io.Reader) (response *http.Response, err error) {
        hc := http.Client{}
        req, err := http.NewRequest(POST_STRING, f.InputURI, strings.NewReader(form.Encode()))
        if err != nil {
            return nil, err
        }

        req.Header.Add("Content-Type", "text/html")

        resp, err := hc.Do(req)
        if err != nil {
            return nil, err
        }

        return resp, nil
    } (POST_STRING, f.InputURI, strings.NewReader(form.Encode()))
    if tx_err != nil {
        return tx_err
    }

    time.Sleep(1000)

    if resp.Status != "200 OK" {
        return errors.New("HTTP 200 OK not returned")
    }

    return nil
}

func (f *NetChannelClient) genTxPool() ([]byte, error) {
    /*
     * Generate the ECDH keys based on the EllipticP384 Curve
     */
    curve := ecdh.NewEllipticECDH(elliptic.P384())
    _, clientPublicKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }

    /***********************************************************************************************
     * Tranmis the public key ECDH key to server. The transmission buffer contains:                *
     *  b64([8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2])  *
     ***********************************************************************************************/
    var pubKeyMarshalled = curve.Marshal(clientPublicKey)
    var pool = bytes.Buffer{}
    tmp := make([]byte, crc64.Size)
    rand.Read(tmp)
    pool.Write(tmp)
    marshal_encrypted := make([]byte, len(pubKeyMarshalled))
    copy(marshal_encrypted, pubKeyMarshalled)
    counter := 0
    for k, _ := range marshal_encrypted {
        if counter == len(tmp) {
            counter = 0
        }
        marshal_encrypted[k] ^= tmp[counter]
        counter += 1
    }
    pool.Write(marshal_encrypted)
    pool_sum := md5.Sum(pool.Bytes())
    pool.Write(pool_sum[:])

    b64_buf := base64.StdEncoding.EncodeToString(pool.Bytes())
    return []byte(b64_buf), nil
}

func configCheck() error {
    if USE_METHOD_GET == true && USE_METHOD_POST == true {
        errors.New("invalid HTTPd METHOD configuration used")
    }

    return nil
}