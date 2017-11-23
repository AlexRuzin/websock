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
    "io"
    "strings"
    "bytes"
    "net/url"
    "net/http"
    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
    "crypto/elliptic"
    "hash/crc64"
    "crypto/md5"
    "crypto/rand"
    "io/ioutil"
)

/************************************************************
 * netcp Client objects and methods                         *
 ************************************************************/
const (
    FLAG_OK                         int = 1 << iota
    FLAG_DEBUG                      int = 1 << iota
    FLAG_DIRECTION_TO_SERVER        int = 1 << iota
    FLAG_DIRECTION_TO_CLIENT        int = 1 << iota
    FLAG_TERMINATE_CONNECTION       int = 1 << iota
    FLAG_BLOCKING                   int = 1 << iota
    FLAG_NONBLOCKING                int = 1 << iota
    FLAG_KEEPALIVE                  int = 1 << iota
    FLAG_COMPRESSION                int = 1 << iota
)

type NetChannelClient struct {
    InputURI        string
    Port            int16
    Flags           int
    Connected       bool
    Path            string
    Host            string
    URL             *url.URL
    Secret          []byte
}

func BuildNetCPChannel(gate_uri string, port int16, flags int) (*NetChannelClient, error) {
    /* The connection must be either blocking or non-blocking */
    if !((flags & FLAG_NONBLOCKING) > 1 || (flags & FLAG_BLOCKING) > 1) {
        return nil, util.RetErrStr("Atomic: Either FLAG_BLOCKING or FLAG_NONBLOCKING must be set")
    }

    main_url, err := url.Parse(gate_uri)
    if err != nil {
        return nil, err
    }
    if main_url.Scheme != "http" {
        return nil, util.RetErrStr("HTTP scheme must not use TLS")
    }

    var io_channel = &NetChannelClient{
        URL: main_url,
        InputURI: gate_uri,
        Port: port,
        Flags: 0,
        Connected: false,
        Path: main_url.Path,
        Host: main_url.Host,
        Secret: nil,
    }

    return io_channel, nil
}

/*
 * Check if the TCP port is reachcable, then attempt to determine
 *  if our service is running on it
 */
func encodeKeyValue (high int) string {
    return func (h int) string {
    	return util.B64E([]byte(util.RandomString(util.RandInt(1, high))))
	} (high)
}

func (f *NetChannelClient) InitializeCircuit() error {
    /*
     * Generate the ECDH keys based on the EllipticP384 Curve/create keypair
     */
    curve := ecdh.NewEllipticECDH(elliptic.P384())
    clientPrivateKey, clientPublicKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        return err
    }
    var pubKeyMarshalled = curve.Marshal(clientPublicKey)

    /*
	 * Generate the b64([xor][marshalled][md5sum]) buffer
	 */
    post_pool, err := f.genTxPool(pubKeyMarshalled)
    if err != nil || len(post_pool) < 1 {
        return err
    }

    /* generate fake key/value pools */
    var parm_map = make(map[string]string)
    num_of_parameters := util.RandInt(3, POST_BODY_JUNK_MAX_PARAMETERS)

    magic_number := num_of_parameters / 2
    for i := num_of_parameters; i != 0; i -= 1 {
        var pool, key string
        if POST_BODY_VALUE_LEN != -1 {
            pool = encodeKeyValue(POST_BODY_VALUE_LEN)
        } else {
            pool = encodeKeyValue(len(string(post_pool)) * 2)
        }
        key = encodeKeyValue(POST_BODY_KEY_LEN)

        /* This value must not be any of the b64 encoded POST_BODY_KEY_CHARSET values -- true == collision */
        if collision := f.checkForKeyCollision(key, POST_BODY_KEY_CHARSET); collision == true {
            i += 1 /* Fix the index */
            continue
        }

        if i == magic_number {
            parameter := string(POST_BODY_KEY_CHARSET[util.RandInt(0, len(POST_BODY_KEY_CHARSET))])
            parm_map[util.B64E([]byte(parameter))] = string(post_pool)
            continue
        }

        parm_map[key] = pool
    }

    /* Perform HTTP TX */
    resp, tx_err := func(
            client *NetChannelClient,
            method string,
            URI string,
            m map[string]string) (response *http.Response, err error) {
        form := url.Values{}
        for k, v := range m {
            form.Set(k, v)
        }
        form_encoded := form.Encode()

        req, err := http.NewRequest(method /* POST */, URI, strings.NewReader(form_encoded))
        if err != nil {
            return nil, err
        }

        /*
         * "application/x-www-form-urlencoded"
         *
         *  Most common ever Content-Type
         */
        req.Header.Set("Content-Type", HTTP_CONTENT_TYPE)
        //req.Header.Set("Connection", "close")

        /*
         * "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
         *  (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"
         *
         * Most common ever UA
         */
        req.Header.Set("User-Agent", HTTP_USER_AGENT)

        /* Parse the domain/IP */
        uri, err := url.Parse(URI)
        if err != nil {
            return nil, err
        }
        req.Header.Set("Host", uri.Hostname()) // FIXME -- check that the URI is correct for Host!!!

        http_client := &http.Client{}
        resp, tx_status := http_client.Do(req)
        if tx_status != nil {
            return nil, tx_status
        }

        return resp, nil
    } (f, HTTP_VERB /* POST */, f.InputURI, parm_map)
    if tx_err != nil && tx_err != io.EOF {
        return tx_err
    }

    if resp.Status != "200 OK" {
        return util.RetErrStr("HTTP 200 OK not returned")
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return err
    }
    encoded, err := util.B64D(string(body))
    if err != nil {
        return err
    }

    var response_pool = bytes.Buffer{}
    response_pool.Write(encoded)

    var xor_key = make([]byte, crc64.Size)
    var xord_marshalled = make([]byte, len(encoded) - crc64.Size - md5.Size)
    var client_id = make([]byte, md5.Size)

    response_pool.Read(xor_key)
    response_pool.Read(xord_marshalled)
    marshalled := func (xor_key []byte, encoded []byte) []byte {
        output := make([]byte, len(encoded))
        copy(output, encoded)
        counter := 0
        for k := range output {
            if counter == len(xor_key) {
                counter = 0
            }

            output[k] ^= xor_key[counter]
            counter += 1
        }
        return output
    } (xor_key, xord_marshalled)
    response_pool.Read(client_id)

    serverPubKey, ok := curve.Unmarshal(marshalled)
    if !ok {
        return util.RetErrStr("Failed to unmarshal server-side public key")
    }

    /* Generate the secret finally */
    secret, err := curve.GenerateSharedSecret(clientPrivateKey, serverPubKey)
    if err != nil || len(secret) == 0 {
        return err
    }

    if (f.Flags & FLAG_DEBUG) > 1 {
        util.DebugOut("Client-side secret:")
        util.DebugOutHex(secret)
    }

    /*
     * Test the circuit
     */
    if err := f.testCircuit(); err != nil {
        return err
    }

    return nil
}

func (f *NetChannelClient) checkForKeyCollision(key string, char_set string) (out bool) {
    /* FIXME -- this should be consolidated code */
    out = false
    var key_vector = make([]string, len(char_set))
    for i := len(char_set) - 1; i >= 0; i -= 1 {
        key_vector[i] = util.B64E([]byte(string(char_set[i])))
    }

    for i := range key_vector {
        if bytes.Equal([]byte(key), []byte(key_vector[i])) {
            out = true
            break
        }
    }

    return
}

func (f *NetChannelClient) testCircuit() error {


    return nil
}

func (f *NetChannelClient) Write(p []byte) (written int, err error) {
    if len(p) == 0 {
        return 0, util.RetErrStr("No input data")
    }



    return 0, nil
}

func (f *NetChannelClient) encryptDataClient(data []byte, enc_key []byte) (key string, value string) {


}

func (f *NetChannelClient) genTxPool(pubKeyMarshalled []byte) ([]byte, error) {
    /***********************************************************************************************
     * Tranmis the public key ECDH key to server. The transmission buffer contains:                *
     *  b64([8 bytes XOR key][XOR-SHIFT encrypted marshalled public ECDH key][md5sum of first 2])  *
     ***********************************************************************************************/
    var pool = bytes.Buffer{}
    xor_key := make([]byte, crc64.Size)
    rand.Read(xor_key)
    pool.Write(xor_key)
    marshal_encrypted := make([]byte, len(pubKeyMarshalled))
    copy(marshal_encrypted, pubKeyMarshalled)
    counter := 0 /* FIXME -- controller.go also has a similar function */
    for k := range marshal_encrypted {
        if counter == len(xor_key) {
            counter = 0
        }
        marshal_encrypted[k] ^= xor_key[counter]
        counter += 1
    }
    pool.Write(marshal_encrypted)
    pool_sum := md5.Sum(pool.Bytes())
    pool.Write(pool_sum[:])

    b64_buf := util.B64E(pool.Bytes())
    return []byte(b64_buf), nil
}