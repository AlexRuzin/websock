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
    "fmt"
    "net/http"
    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
    "net/url"
    "errors"
    "strings"
    "crypto/elliptic"
    "crypto/rand"
    "os"
    "bytes"
    "unicode"
    "hash/crc64"
    "crypto/md5"
    "io"
)

/*
 * Configuration
 */
const RSA_KEY_PAIR_LEN = 2048
const TX_ECDH_BUF_XOR_KEY_LEN = 32 // 32-bit XOR key encrypted the marshalled
                                   //  ecdh public key

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

/* Create circuit -OR- process gate requests */
func requestHandlerGate(writer http.ResponseWriter, reader *http.Request) {
    fmt.Fprintf(writer, "Testing Testing %s", reader.URL.Path[:])
    os.Exit(0)
}

func CreateNetCPServer(path_gate string, port int16, flags int) (*NetChannelService, error) {
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
    post_pool, err := f.genTxPool()
    if err != nil || len(post_pool) < 1 {
        return err
    }

    form := url.Values{}
    form.Encode()

    hc := http.Client{}
    req, err := http.NewRequest("POST", f.InputURI, strings.NewReader(form.Encode()))
    if err != nil {
        return err
    }

    req.PostForm = form
    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    resp, err := hc.Do(req)
    if err != nil {
        return err
    }
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

    /******************************************************************************************
     * Tranmis the public key ECDH key to server. The transmission buffer contains:           *
     *  [8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2]  *
     ******************************************************************************************/
    var pubKeyMarshalled = curve.Marshal(clientPublicKey)
    var pool = bytes.Buffer{}
    tmp := make([]byte, crc64.Size)
    rand.Read(tmp)
    pool.Write(tmp)
    marshal_encrypted := make([]byte, len(pubKeyMarshalled))
    copy(marshal_encrypted, pubKeyMarshalled)
    counter := 0
    for k, _ := range marshal_encrypted {
        marshal_encrypted[k] ^= tmp[counter]
        counter += 1
        if counter > len(tmp) {
            counter = 0
        }
    }
    pool.Write(marshal_encrypted)
    pool_sum := md5.Sum(pool.Bytes())
    pool.Write(pool_sum[:])

    return pool.Bytes(), nil
}

