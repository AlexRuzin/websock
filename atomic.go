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
    "crypto"
    "io/ioutil"

    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
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
    GlobalIP            string
    LocalIP             string
    TimeStamp           string
    ClientID            string
    Data                []byte
    DecryptedSum        string
    Direction           FlagVal
    Flags               FlagVal
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
    WAIT_TIMEOUT_REACHED    = util.RetErrStr("timeout reached")
    WAIT_DATA_RECEIVED      = util.RetErrStr("data received")
    WAIT_CLOSED             = util.RetErrStr("socket closed")
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

func BuildChannel(gateURI string, flags FlagVal) (*NetChannelClient, error) {
    if (flags & FLAG_DO_NOT_USE) == 1 {
        return nil, util.RetErrStr("Invalid flag: FLAG_DO_NOT_USE")
    }

    if (flags & FLAG_ENCRYPT) == 0 {
        return nil, util.RetErrStr("FLAG_ENCRYPT is a mandatory switch for the `flags` parameter")
    }

    if testCharSetPKE(POST_BODY_KEY_CHARSET) == false {
        return nil, util.RetErrStr("PANIC: POST_BODY_KEY_CHARSET contains non-unique elements")
    }

    mainURL, err := url.Parse(gateURI)
    if err != nil {
        return nil, err
    }
    if mainURL.Scheme != "http" {
        return nil, util.RetErrStr("HTTP scheme must not use TLS")
    }

    port, _ := strconv.Atoi(mainURL.Port())
    var ioChannel = &NetChannelClient{
        controllerURL:      mainURL,
        inputURI:           gateURI,
        port:               int16(port),
        flags:              flags,
        connected:          false,
        path:               mainURL.Path,
        host:               mainURL.Host,
        secret:             nil,
        responseData:       &bytes.Buffer{},
        transport:          nil,
        request:            nil,
        cancelled:          false,
    }

    if (ioChannel.flags & FLAG_DEBUG) > 1 {
        util.DebugOut("NetChannelClient structure initialized")
    }

    return ioChannel, nil
}

func (f *NetChannelClient) InitializeCircuit() error {
    /*
     * Generate keypair, construct HTTP POST request parameter map
     */
    var ( /* Output reserved for keypair/post request generate method */
        curve                   ecdh.ECDH
        request                 map[string]string
        initStatus              error = nil
        clientPrivateKey        crypto.PrivateKey
    )
    curve, request, clientPrivateKey, initStatus = f.generateCurvePostRequest()
    if initStatus != nil {
        return initStatus
    }

    /* Perform HTTP TX, receive the public key from the server */
    body, txErr := sendTransmission(HTTP_VERB /* POST */, f.inputURI, request, f)
    if txErr != nil && txErr != io.EOF {
        return txErr
    }

    /*
     * Decode the public key returned by the server and create a secret key
     */
    var genStatus               error = nil
    f.secret, genStatus = f.decodeServerPubkeyGenSecret(body, clientPrivateKey, curve)
    if genStatus != nil {
        return genStatus
    }

    if (f.flags & FLAG_DEBUG) > 1 {
        util.DebugOut("Client-side secret:")
        util.DebugOutHex(f.secret)
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
     *  socket. This is the primary i/o subsystem
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

    /* No compression */
    _, wrote, err := f.writeStream(p, 0)
    if err != nil {
        return 0, err
    }

    return wrote, io.EOF
}

func (f *NetChannelClient) testCircuit() error {
    if _, _, err := f.writeStream(nil, FLAG_TEST_CONNECTION); err != nil {
        return err
    }

    if f.responseData.Len() == 0 {
        return util.RetErrStr("testCircuit() failed on the server side")
    }

    var responseData = make([]byte, f.responseData.Len())
    read, err := f.readStream(responseData, FLAG_TEST_CONNECTION)
    if err != io.EOF || read != len(TEST_CONNECTION_DATA) {
        return util.RetErrStr("testCircuit() invalid response from server side")
    }

    if !util.IsAsciiPrintable(string(responseData)) ||
        strings.Compare(string(responseData), TEST_CONNECTION_DATA) != 0 {
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

    /* Check for high-entropy compression inflation and generate a compression stream */
    var (
        compressionFlag FlagVal = 0
        txData          []byte = p
        deflateStatus   error = nil
    )
    if (f.flags & FLAG_COMPRESS) > 0 && len(p) > util.GetCompressedSize(p) &&
        !((flags & FLAG_TEST_CONNECTION) > 0) /* Compression is not required for testing the circuit */ {
        compressionFlag |= FLAG_COMPRESS

        txData, deflateStatus = util.CompressStream(txData)
        if err != nil {
            panic(deflateStatus)
        }
    }

    f.flags |= FLAG_DIRECTION_TO_SERVER
    encrypted, err := encryptData(txData, f.secret, FLAG_DIRECTION_TO_SERVER, compressionFlag, f.clientIdString)
    if err != nil {
        return 0, 0, err
    }
    var parmMap = make(map[string]string)

    /* key = b64(ClientIdString) value = b64(JSON(<data>)) */
    value := util.B64E(encrypted)

    /* Add a random length between 16-32 bytes at the end of the clientIDString */
    clientString := func (clientID string) []byte {
        var randValue = util.RandomString(util.RandInt(CLIENTID_POST_MIN, CLIENTID_POST_MAX))
        return []byte(clientID + randValue)
    } (f.clientIdString)
    key := util.B64E(clientString)
    parmMap[key] = value

    body, err := sendTransmission(HTTP_VERB, f.inputURI, parmMap, f)
    if err != nil {
        return 0,0, err
    }

    if len(body) != 0 {
        /* Decode the body (TransferUnit) and store in NetChannelClient.ResponseData */
        clientId, responseData, _, err := decryptData(string(body), f.secret)
        if err != nil {
            return len(body), len(p), err
        }

        /* Check that the clientID does not exceed 32 bytes */
        /* FIXME / ADDME -- finish this component
        if len(f.clientIdString) > 32 {
            f.clientIdString = f.clientIdString[:len(f.clientIdString) - 32]
        }
        */

        if strings.Compare(clientId, f.clientIdString) != 0 {
            return len(body), len(p), util.RetErrStr("Invalid server response")
        }

        f.responseSync.Lock()
        defer f.responseSync.Unlock()

        var rawData = responseData

        if (f.flags & FLAG_COMPRESS) > 0 && !((flags & FLAG_TEST_CONNECTION) > 0) {
            var (
                streamStatus        error = nil
                decompressed        []byte
            )

            decompressed, streamStatus = util.DecompressStream(responseData)
            if streamStatus != nil {
                return 0, 0, err
            }

           rawData = decompressed
        }

        /* Write either the compressed or decompressed stream */
        f.responseData.Write(rawData)
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

func sendTransmission(verb string, URI string, m map[string]string, client *NetChannelClient) (response []byte, err error) {
    form := url.Values{}
    for k, v := range m {
        form.Set(k, v)
    }
    formEncoded := form.Encode()

    req, err := http.NewRequest(verb /* POST */, URI, strings.NewReader(formEncoded))
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

    respIo := make(chan *http.Response)
    tr := &http.Transport{}
    httpClient := &http.Client{Transport: tr}
    client.request = req
    client.transport = tr
    go func (r *http.Request) {
        resp, tx_status := httpClient.Do(r)
        if tx_status != nil {
            close(respIo)
            return
        }
        respIo <- resp
    } (req)

    resp, ok := <- respIo
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
    defer close(respIo)

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