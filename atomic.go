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
    "io"
    "strings"
    "bytes"
    "sync"
    "strconv"
    "time"
    "net/url"
    "net/http"
    "crypto/elliptic"
    "hash/crc64"
    "crypto/md5"
    "crypto/rand"
    "io/ioutil"
    "encoding/hex"
    "encoding/gob"

    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
    "github.com/AlexRuzin/cryptog"
)

/************************************************************
 * websock Client objects and methods                       *
 ************************************************************/
type FlagVal int
const (
    FLAG_DO_NOT_USE                 FlagVal = 1 << iota /* Flip up to 32 bits -- placeholder*/
    FLAG_DEBUG
    FLAG_ENCRYPT
    FLAG_COMPRESS
    FLAG_DIRECTION_TO_SERVER
    FLAG_DIRECTION_TO_CLIENT
    FLAG_TERMINATE_CONNECTION
    FLAG_TEST_CONNECTION
    FLAG_CHECK_STREAM_DATA
)

type internalCommands struct {
    flags FlagVal
    command string
    comment string
}
var iCommands = []internalCommands{
    {flags: FLAG_TEST_CONNECTION,
     command: TEST_CONNECTION_DATA,
     comment: "Tests the connection after key negotiation"},

    {flags: FLAG_CHECK_STREAM_DATA,
     command: CHECK_STREAM_DATA,
     comment: "Checks the server for any inbound data"},

    {flags: FLAG_TERMINATE_CONNECTION,
     command: TERMINATE_CONNECTION_DATA,
     comment: "Terminates the connection between the controller and atom"},
}

type NetChannelClient struct {
    /* Server connection parameters */
    inputURI            string
    port                int16
    path                string
    host                string
    controllerURL       *url.URL

    /* Identifiers for the client */
    clientId            []byte
    clientIdString      string

    /* ECDH secret */
    secret              []byte

    /* States and configuration */
    flags               FlagVal
    connected           bool

    /* Data coming in from the server */
    responseData        *bytes.Buffer
    responseSync        sync.Mutex

    /* Request elements */
    requestSync         sync.Mutex
    transport           *http.Transport
    request             *http.Request
    cancelled           bool
}

type TransferUnit struct {
    GlobalIP        string
    LocalIP         string
    TimeStamp       string
    ClientID        string
    Data            []byte
    DecryptedSum    string
    Direction       FlagVal
}

func (f *NetChannelClient) Len() int {
    if f.connected == false {
        return 0
    }

    f.responseSync.Lock()
    defer f.responseSync.Unlock()

    return f.responseData.Len()
}

/*
 * NOTE: this function is not implemented
 */
var (
    WAIT_TIMEOUT_REACHED = util.RetErrStr("timeout reached")
    WAIT_DATA_RECEIVED = util.RetErrStr("data received")
    WAIT_CLOSED = util.RetErrStr("socket closed")
)
func (f *NetChannelClient) Wait(timeoutMilliseconds time.Duration) (responseLen int, err error) {
    if f.connected == false {
        return 0, util.RetErrStr("client not connected")
    }

    responseLen = 0
    err = WAIT_TIMEOUT_REACHED

    for i := timeoutMilliseconds / 100; i != 0; i -= 1 {
        if f.connected == false {
            err = WAIT_CLOSED
            responseLen = -1
            break
        }

        if f.Len() > 0 {
            responseLen = f.Len()
            err = WAIT_DATA_RECEIVED
            break
        }

        util.Sleep(100 * time.Millisecond)
    }

    return
}

func (f *NetChannelClient) readInternal(p []byte) (int, error) {
    if f.connected == false {
        return 0, util.RetErrStr("client not connected")
    }

    if f.Len() == 0 {
        return 0, io.EOF
    }

    read, err := f.readStream(p, 0)
    if err != io.EOF {
        return 0, err
    }

    return read, io.EOF
}

func (f *NetChannelClient) writeInternal(p []byte) (int, error) {
    if f.connected == false {
        return 0, util.RetErrStr("client not connected")
    }

    if f.transport != nil {
        f.cancelled = true
        f.transport.CancelRequest(f.request)
    }

    _, wrote, err := f.writeStream(p, 0)
    if err != nil {
        return 0, err
    }

    return wrote, io.EOF
}

func (f *NetChannelClient) Read(p []byte) (read int, err error) {
    read, err = f.readInternal(p)
    if err != io.EOF {
        return 0, err
    }

    return
}

func (f *NetChannelClient) Write(p []byte) (written int, err error) {
    written, err = f.writeInternal(p)
    if err != io.EOF {
        return 0, err
    }

    return
}

func BuildChannel(gate_uri string, flags FlagVal) (*NetChannelClient, error) {
    if (flags & FLAG_DO_NOT_USE) == 1 {
        return nil, util.RetErrStr("Invalid flag: FLAG_DO_NOT_USE")
    }

    if (flags & FLAG_ENCRYPT) == 0 {
        return nil, util.RetErrStr("FLAG_ENCRYPT is a mandatory switch for the `flags` parameter")
    }

    main_url, err := url.Parse(gate_uri)
    if err != nil {
        return nil, err
    }
    if main_url.Scheme != "http" {
        return nil, util.RetErrStr("HTTP scheme must not use TLS")
    }

    port, _ := strconv.Atoi(main_url.Port())
    var io_channel = &NetChannelClient{
        controllerURL: main_url,
        inputURI: gate_uri,
        port: int16(port),
        flags: flags,
        connected: false,
        path: main_url.Path,
        host: main_url.Host,
        secret: nil,
        responseData: &bytes.Buffer{},
        transport: nil,
        request: nil,
        cancelled: false,
    }

    if (io_channel.flags & FLAG_DEBUG) > 1 {
        util.DebugOut("NetChannelClient structure initialized")
    }

    return io_channel, nil
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
    body, tx_err := sendTransmission(HTTP_VERB /* POST */, f.inputURI, parm_map, f)
    if tx_err != nil && tx_err != io.EOF {
        return tx_err
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

    f.clientId = client_id
    f.clientIdString = hex.EncodeToString(f.clientId)

    serverPubKey, ok := curve.Unmarshal(marshalled)
    if !ok {
        return util.RetErrStr("Failed to unmarshal server-side public key")
    }

    /* Generate the secret finally */
    secret, err := curve.GenerateSharedSecret(clientPrivateKey, serverPubKey)
    if err != nil || len(secret) == 0 {
        return err
    }
    f.secret = secret

    if (f.flags & FLAG_DEBUG) > 1 {
        util.DebugOut("Client-side secret:")
        util.DebugOutHex(secret)
    }

    /*
     * Test the circuit
     */
    if err := f.testCircuit(); err != nil {
        f.Close()
        return err
    }

    /*
     * Periodically check to see if the server has any data to be sent to the
     *  socket.
     */
    go func (client *NetChannelClient) {
        for {
            read, _, err := client.writeStream(nil, FLAG_CHECK_STREAM_DATA)
            if err != nil {
                if err == io.EOF {
                    /* Connection is closed due to a Write() request */
                    util.Sleep(10 * time.Millisecond)
                    continue
                }
                client.Close()
                return
            }

            if (client.flags & FLAG_DEBUG) > 1 && read == 0 {
                datetime := func() string {
                    return time.Now().String()
                }()
                util.DebugOut("[" + datetime + "] FLAG_CHECK_STREAM_DATA: Keep-alive -- no data")
            }
        }
    } (f)

    return nil
}

func (f *NetChannelClient) Close() {
    f.connected = false
    f.writeStream(nil, FLAG_TERMINATE_CONNECTION)
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
    if _, _, err := f.writeStream(nil, FLAG_TEST_CONNECTION); err != nil {
        return err
    }

    if f.responseData.Len() == 0 {
        return util.RetErrStr("testCircuit() failed on the server side")
    }

    var response_data = make([]byte, f.responseData.Len())
    read, err := f.readStream(response_data, FLAG_TEST_CONNECTION)
    if err != io.EOF || read != len(TEST_CONNECTION_DATA) {
        return util.RetErrStr("testCircuit() invalid response from server side")
    }

    if !util.IsAsciiPrintable(string(response_data)) ||
        strings.Compare(string(response_data), TEST_CONNECTION_DATA) != 0 {
        return util.RetErrStr("testCircuit() data corruption from server side")
    }

    f.connected = true
    return nil
}

func (f *NetChannelClient) writeStream(p []byte, flags FlagVal) (read int, written int, err error) {
    if !((flags & FLAG_TEST_CONNECTION) > 0) && f.connected == false {
        return 0,0, util.RetErrStr("Client not connected")
    }

    f.requestSync.Lock()
    defer f.requestSync.Unlock()

    /* Internal commands are based on the FlagVal bit flag */
    if len(p) == 0 && flags != 0 {
        p = func (flags FlagVal) []byte {
            for k := range iCommands {
                if (iCommands[k].flags & flags) > 0 {
                    return []byte(iCommands[k].command)
                }
            }
            return nil
        } (flags)
    }

    if len(p) == 0 {
        return 0, 0, util.RetErrStr("No input data")
    }

    f.flags |= FLAG_DIRECTION_TO_SERVER
    encrypted, err := encryptData(p, f.secret, FLAG_DIRECTION_TO_SERVER, f.clientIdString)
    if err != nil {
        return 0, 0, err
    }
    var parm_map = make(map[string]string)

    /* key = b64(ClientIdString) value = b64(JSON(<data>)) */
    value := util.B64E(encrypted)
    key := util.B64E([]byte(f.clientIdString))
    parm_map[key] = value

    body, err := sendTransmission(HTTP_VERB, f.inputURI, parm_map, f)
    if err != nil {
        return 0,0, err
    }

    if len(body) != 0 {
        /* Decode the body (TransferUnit) and store in NetChannelClient.ResponseData */
        client_id, response_data, err := decryptData(string(body), f.secret)
        if err != nil {
            return len(body), len(p), err
        }
        if strings.Compare(client_id, f.clientIdString) != 0 {
            return len(body), len(p), util.RetErrStr("Invalid server response")
        }

        f.responseSync.Lock()
        defer f.responseSync.Unlock()

        f.responseData.Write(response_data)
    }

    return len(body), len(p), nil
}

func (f *NetChannelClient) readStream(p []byte, flags FlagVal) (read int, err error) {
    if !((flags & FLAG_TEST_CONNECTION) > 0) &&f.connected == false {
        return 0, util.RetErrStr("Client not connected")
    }

    read = f.responseData.Len()
    if read == 0 {
        return 0, io.EOF
    }

    f.responseSync.Lock()
    defer f.responseSync.Unlock()

    f.responseData.Read(p)
    f.responseData.Reset() /* FIXME */

    return read, io.EOF
}

func encryptData(data []byte, secret []byte, flags FlagVal, client_id string) (encrypted []byte, err error) {
    if len(data) == 0 {
        return nil, util.RetErrStr("Invalid parameters for encryptData")
    }
    err = util.RetErrStr("encryptData: Unknown error")

    /* Transmission object */
    tx := &TransferUnit{
        ClientID: client_id,
        TimeStamp: func () string {
            return time.Now().String()
        } (),
        Data: make([]byte, len(data)),
        DecryptedSum: func (p []byte) string {
            data_sum := md5.Sum(data)
            return hex.EncodeToString(data_sum[:])
        } (data),
        Direction: flags,

    }
    copy(tx.Data, data)

    tx_stream, err := func(tx TransferUnit) ([]byte, error) {
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

    output, err := cryptog.RC4_Encrypt(tx_stream, cryptog.RC4_PrepareKey(secret))
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
    xor_key := make([]byte, crc64.Size)
    rand.Read(xor_key)
    pool.Write(xor_key)
    marshal_encrypted := make([]byte, len(pubKeyMarshalled))
    copy(marshal_encrypted, pubKeyMarshalled)
    counter := 0
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

func encodeKeyValue (high int) string {
    return func (h int) string {
        return util.B64E([]byte(util.RandomString(util.RandInt(1, high))))
    } (high)
}

func sendTransmission(verb string, URI string, m map[string]string, client *NetChannelClient) (response []byte, err error) {
    form := url.Values{}
    for k, v := range m {
        form.Set(k, v)
    }
    form_encoded := form.Encode()

    req, err := http.NewRequest(verb /* POST */, URI, strings.NewReader(form_encoded))
    if err != nil {
        return nil, err
    }

    /*
     * "application/x-www-form-urlencoded"
     *
     *  Most common ever Content-Type
     */
    req.Header.Set("Content-Type", HTTP_CONTENT_TYPE)
    req.Header.Set("Connection", "close")

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
    req.Header.Set("Host", uri.Hostname())

    resp_io := make(chan *http.Response)
    tr := &http.Transport{}
    http_client := &http.Client{Transport: tr}
    client.request = req
    client.transport = tr
    go func (r *http.Request) {
        resp, tx_status := http_client.Do(r)
        if tx_status != nil {
            close(resp_io)
            return
        }
        resp_io <- resp
    } (req)

    resp, ok := <- resp_io
    if !ok {
        if client.cancelled == true {
            /* Forced write request */
            client.transport = nil
            client.request = nil
            client.cancelled = false
            return nil, io.EOF
        }
        return nil, util.RetErrStr("Failure in client request")
    }
    defer close(resp_io)

    if resp.Status != "200 OK" {
        return nil, util.RetErrStr("HTTP 200 OK not returned")
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    return body, nil
}