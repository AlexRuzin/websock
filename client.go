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
    "sync"
    "time"
    "bytes"
    "strings"
    "crypto"
    "strconv"
    "net/url"
    "net/http"
    "io/ioutil"

    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
)

/************************************************************
 * websock Client objects and methods                       *
 ************************************************************/
type FlagVal int
const (
    FLAG_DO_NOT_USE     FlagVal = 1 << iota /* Flip up to 32 bits -- placeholder*/
    FLAG_DEBUG
    FLAG_ENCRYPT
    FLAG_COMPRESS
    FLAG_DIRECTION_TO_SERVER
    FLAG_DIRECTION_TO_CLIENT
    FLAG_TERMINATE_CONNECTION
    FLAG_TEST_CONNECTION
    FLAG_CHECK_STREAM_DATA
) /* asdfasdf */

type internalCommands struct {
    flags   FlagVal
    command string
    comment string
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
    cancelledSync       sync.Mutex

    /* Main config */
    config              *ProtocolConfig
}

type transferUnit struct {
    GlobalIP            string
    LocalIP             string
    TimeStamp           string
    ClientID            string
    Data                []byte
    DecryptedSum        string
    Direction           FlagVal
    Flags               FlagVal
}

func (f *NetChannelClient) Read(p []byte) (read int, err error) {
    read, err = f.readInternal(p)

    if f.connected == false {
        return 0, util.RetErrStr("Read(): client has closed the connection")
    }

    if err != io.EOF {
        return 0, err
    }

    return
}

func (f *NetChannelClient) Write(p []byte) (written int, err error) {
    written, err = f.writeInternal(p)

    if f.connected == false {
        return 0, util.RetErrStr("Write(): client has closed the connection")
    }

    if err != io.EOF {
        return 0, err
    }

    return
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
        return 0, util.RetErrStr("Wait(): client not connected")
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

func BuildChannel(gateURI string, flags FlagVal) (*NetChannelClient, error) {
    if (flags & FLAG_DO_NOT_USE) == 1 {
        return nil, util.RetErrStr("Invalid flag: FLAG_DO_NOT_USE")
    }

    if (flags & FLAG_ENCRYPT) == 0 {
        return nil, util.RetErrStr("FLAG_ENCRYPT is a mandatory switch for the `flags` parameter")
    }

    /*
     * Parse the primary configuration and set it as a reference to masterConfig
     */
    var (
        tmpConfig           *ProtocolConfig
        configParseStatus   error
    )
    tmpConfig, configParseStatus = parseConfig()
    if configParseStatus != nil {
        return nil, configParseStatus
    }

    if testCharSetPKE(tmpConfig.PostBodyKeyCharset) == false {
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

        config:             tmpConfig,
    }

    if (ioChannel.flags & FLAG_DEBUG) > 1 {
        util.DebugOut("NetChannelClient structure initialized")
    }

    return ioChannel, nil
}

func (f *NetChannelClient) InitializeCircuit() error {
    /* Transmit and receive public keys, generate secret */
    if pkeStatus := f.initializePKE(); pkeStatus != nil {
        return pkeStatus
    }

    f.connected = true

    /*
     * Test the circuit
     */
    if err := f.testCircuit(); err != nil {
        f.Close()
        return err
    }

    /*
     * Keep sending POSTs until some data is written to the controller write interface
     */
    checkWriteThread(f)

    return nil
}

func checkWriteThread(client *NetChannelClient) {
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

            if (client.flags & FLAG_DEBUG) > 0 && read == 0 {
                datetime := func() string {
                    return time.Now().String()
                }()
                util.DebugOut("[" + datetime + "] FLAG_CHECK_STREAM_DATA: Keep-alive -- no data")
            }
        }
    } (client)
}

func (f *NetChannelClient) initializePKE() (error) {
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
    var body []byte
    body, initStatus = f.sendTransmission(f.config.HTTPVerb/* POST */, f.inputURI, request)
    if initStatus != nil && initStatus != io.EOF {
        return initStatus
    }
    if len(body) == 0 {
        return util.RetErrStr("server has returned a null length public key")
    }

    /*
     * Decode the public key returned by the server and create a secret key
     */
    f.secret, initStatus = f.decodeServerPubkeyGenSecret(body, clientPrivateKey, curve)
    if initStatus != nil {
        return initStatus
    }

    if (f.flags & FLAG_DEBUG) > 0 {
        util.DebugOut("Client-side secret:")
        util.DebugOutHex(f.secret)
    }

    return nil
}

func (f *NetChannelClient) Close() {
    f.connected = false
    f.writeStream(nil, FLAG_TERMINATE_CONNECTION)
}

func (f *NetChannelClient) readInternal(p []byte) (int, error) {
    if f.connected == false {
        return 0, util.RetErrStr("readInternal(): client not connected")
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
        return 0, util.RetErrStr("writeInternal(): client not connected")
    }

    if f.transport != nil {
        f.cancelled = true
        f.transport.CancelRequest(f.request)
        f.cancelledSync.Lock()
    }
    f.cancelledSync.Unlock()

    /* No compression */
    _, wrote, err := f.writeStream(p, 0)
    if err != io.EOF {
        return 0, err
    }

    return wrote, io.EOF
}

func (f *NetChannelClient) testCircuit() error {
    if _, _, err := f.writeStream(nil, FLAG_TEST_CONNECTION); err != io.EOF {
        return err
    }

    if f.responseData.Len() == 0 {
        return util.RetErrStr("testCircuit() failed on the server side")
    }

    var responseData = make([]byte, f.responseData.Len())
    read, err := f.readStream(responseData, FLAG_TEST_CONNECTION)
    if err != io.EOF || read != len(f.config.TestStream) {
        return util.RetErrStr("testCircuit() invalid response from server side")
    }

    if !util.IsAsciiPrintable(string(responseData)) ||
        strings.Compare(string(responseData), f.config.TestStream) != 0 {
        return util.RetErrStr("testCircuit() data corruption from server side")
    }

    return nil
}

func (f *NetChannelClient) writeStream(rawData []byte, flags FlagVal) (read int, written int, err error) {
    if (flags & FLAG_TERMINATE_CONNECTION) > 0 {
        return 0, 0, util.RetErrStr("writeStream(): Client has forced the connection to close")
    }

    if !((flags & FLAG_TEST_CONNECTION) > 0) && f.connected == false {
        return 0,0, util.RetErrStr("writeStream(): client not connected")
    }

    f.requestSync.Lock()
    defer f.requestSync.Unlock()

    /* Generate parameters */
    var parmMap = make(map[string]string)
    if parmMap, err = f.generatePOSTrequest(rawData, flags); err != nil {
        util.RetErrStr(err.Error())
    }

    /* Transmit */
    var body []byte
    body, err = f.sendTransmission(f.config.HTTPVerb, f.inputURI, parmMap)
    if err != nil {
        return 0,0, err
    }

    if (flags & FLAG_CHECK_STREAM_DATA) > 0 && len(body) == 0 {
        return 0, 0, io.EOF
    }

    read = len(body)

    written = 0
    if len(body) != 0 {
        /* Decode the body (TransferUnit) and store in NetChannelClient.ResponseData */
        if written, err = f.processHTTPresponse(body, flags); err != nil {
            util.RetErrStr(err.Error())
        }
    }

    err = io.EOF
    return
}

func (f *NetChannelClient) processHTTPresponse(body []byte, flags FlagVal) (written int, err error) {
    /* Decode the body (TransferUnit) and store in NetChannelClient.ResponseData */
    clientId, responseData, _, err := decryptData(string(body), f.secret)
    if err != nil {
        return 0, err
    }
    if strings.Compare(clientId, f.clientIdString) != 0 {
        return 0, util.RetErrStr("Invalid server response")
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
            return 0, err
        }

        rawData = decompressed
    }

    /* Write either the compressed or decompressed stream */
    if written, err = f.responseData.Write(rawData); err != io.EOF {
        return written, err
    }

    return written, nil
}

func returnCommandString(flag FlagVal, config ProtocolConfig) ([]byte, error) {
    var iCommands = []internalCommands{
        {flags: FLAG_TEST_CONNECTION,
            command: config.TestStream},

        {flags: FLAG_CHECK_STREAM_DATA,
            command: config.CheckStream},

        {flags: FLAG_TERMINATE_CONNECTION,
            command: config.TermConnect},
    }

    /* Internal commands are based on the FlagVal bit flag */
    var output = func (flags FlagVal) []byte {
        for k := range iCommands {
            if (iCommands[k].flags & flags) > 0 {
                return []byte(iCommands[k].command)
            }
        }
        return nil
    } (flag)

    if output == nil {
        return nil, util.RetErrStr("flag does not suppose a command string")
    }

    return output, nil
}

func (f *NetChannelClient) generatePOSTrequest(rawData []byte, flags FlagVal) (map[string]string, error) {
    if len(rawData) == 0 && flags != 0 {
        var (
            err error
            tmp []byte
        )
        if tmp, err = returnCommandString(flags, *f.config); err == nil {
            rawData = tmp
        }
    }

    if len(rawData) == 0 {
        return nil, util.RetErrStr("No input data")
    }

    var (
        encrypted           []byte
        processStatus       error
    )
    if encrypted, processStatus = f.compressEncryptData(rawData, flags); processStatus != nil {
        return nil, processStatus
    }

    var parmMap = make(map[string]string)

    /* key = b64(ClientIdString) value = b64(JSON(<data>)) */
    value := util.B64E(encrypted)
    key := util.B64E([]byte(f.clientIdString))
    parmMap[key] = value

    return parmMap, nil
}

func (f *NetChannelClient) compressEncryptData(rawData []byte, flags FlagVal) (encrypted []byte, err error) {
    err = nil

    /* Check for high-entropy compression inflation and generate a compression stream */
    var (
        compressionFlag     FlagVal = 0
        txData              []byte = rawData
        deflateStatus       error = nil
    )
    if (f.flags & FLAG_COMPRESS) > 0 && len(rawData) > util.GetCompressedSize(rawData) &&
        !((flags & FLAG_TEST_CONNECTION) > 0) /* Compression is not required for testing the circuit */ {
        compressionFlag |= FLAG_COMPRESS

        txData, deflateStatus = util.CompressStream(txData)
        if deflateStatus != nil {
            return nil, deflateStatus
        }
    }

    f.flags |= FLAG_DIRECTION_TO_SERVER
    encrypted, err = encryptData(txData, f.secret, FLAG_DIRECTION_TO_SERVER, compressionFlag, f.clientIdString)
    if err != nil {
        return nil, err
    }

    return
}

func (f *NetChannelClient) readStream(p []byte, flags FlagVal) (read int, err error) {
    if !((flags & FLAG_TEST_CONNECTION) > 0) &&f.connected == false {
        return 0, util.RetErrStr("readStream: client not connected")
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

func (f* NetChannelClient) sendTransmission(verb string, URI string, params map[string]string) ([]byte, error) {

    f.cancelledSync.Lock()
    defer f.cancelledSync.Unlock()

    var (
        req             *http.Request
        reqError        error
    )
    if req, reqError = f.generateHTTPheaders(URI, verb, params); reqError != nil {
        return nil, reqError
    }

    /* Wait until there is some data to be written, then cancel the HTTP request to get
     *  data from the server, and create a new request to transmit the new data
     */
    var (
        resp            *http.Response
        respError       error
    )
    if resp, respError = f.cancelHTTPandWrite(req); respError != nil {
        return nil, respError
    }
    if resp == nil {
        return nil, util.RetErrStr("sendTransmission() reports that the response buffer is nil")
    }

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

func (f *NetChannelClient) cancelHTTPandWrite(req *http.Request) (*http.Response, error) {
    var respIo              = make(chan *http.Response)

    tr                      := &http.Transport{}
    httpClient              := &http.Client{Transport: tr}
    f.request               = req
    f.transport             = tr

    go func (r *http.Request) {
        var (
            response        *http.Response
            rxStatus        error = nil
        )
        if response, rxStatus = httpClient.Do(r); rxStatus != nil {
            close(respIo)
            return
        }
        respIo <- response
    } (req)

    resp, ok := <- respIo
    if !ok {
        if f.cancelled == true {
            /* Forced write request */
            f.transport    = nil
            f.request      = nil
            f.cancelled    = false
            return nil, nil
        }
        return nil, util.RetErrStr("Failure in client request")
    }
    defer close(respIo)

    return resp, nil
}

func (f *NetChannelClient) generateHTTPheaders(URI string, verb string,
    formMap map[string]string) (*http.Request, error) {

    form := url.Values{}
    for k, v := range formMap {
        form.Set(k, v)
    }
    formEncoded := form.Encode()

    var (
        req         *http.Request
        reqStatus   error
    )
    if req, reqStatus = http.NewRequest(verb /* POST */, URI, strings.NewReader(formEncoded)); reqStatus != nil {
        return nil, reqStatus
    }

    /*
     * "application/x-www-form-urlencoded"
     *
     *  Most common ever Content-Type
     */
    req.Header.Set("Content-Type", f.config.ContentType)
    req.Header.Set("Connection", "close")

    /*
     * "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
     *  (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"
     *
     * Most common ever UA
     */
    req.Header.Set("User-Agent", f.config.UserAgent)

    /* Set the domain/IP */
    var (
        parsedURI   *url.URL
        parseError  error
    )
    if parsedURI, parseError = url.Parse(URI); parseError != nil {
        return nil, parseError
    }
    req.Header.Set("Host", parsedURI.Hostname())

    return req, nil
}

/* EOF */