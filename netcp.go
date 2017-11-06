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
    "net/url"
    "errors"
    "strings"
)

/*
 * Configuration
 */
const RSA_KEY_PAIR_LEN = 2048

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
}

func CreateNetCPServer(path_gate string, port int16, flags int) (*NetChannelService, error) {
    var io_server = &NetChannelService{
        Port: port,
        Flags: flags,
        PathGate: path_gate,
    }

    go func(svc *NetChannelService) {
        http.HandleFunc(io_server.PathGate, requestHandlerGate)
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
    /*
     * Generate a private/public key pair. Create a pool of the public key,
     *  along with an md5 of the public key appended to the end. The server
     *  returns its own public key with an md5 as well.
     *
     * The md5 sent by the client will identify the connection and act as
     *  the key in the hash table.
     */






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

