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
    "net"
    "net/url"
    "net/http"
    "io/ioutil"

    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"

    "github.com/tatsushid/go-fastping"
)

type NetChannelClient struct {
    /* Server connection parameters */
    inputURI            string
    port                int16
    path                string
    host                string
    controllerURL       *url.URL

    /* Circuit tests */
    testCircuit         bool
    pingServer          bool

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
    transport           *http.Transport
    request             *http.Request
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

    return written, io.EOF
}

func (f *NetChannelClient) Len() int {
    if f.connected == false {
        return 0
    }

    f.responseSync.Lock()
    defer f.responseSync.Unlock()

    return f.responseData.Len()
}

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
    if (flags & FLAG_DO_NOT_USE) == 1  {
        return nil, util.RetErrStr("Invalid flag: FLAG_DO_NOT_USE")
    }

    if !((flags & FLAG_ENCRYPT) > 1) {
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
        config:             tmpConfig,
        testCircuit:        false,
        pingServer:         false,
    }

    if (flags & FLAG_TEST_CIRCUIT) > 0 {
        ioChannel.testCircuit = true
    }

    if (flags & FLAG_PING_SERVER) > 0 {
        ioChannel.pingServer = true
    }

    if (ioChannel.flags & FLAG_DEBUG) > 1 {
        util.DebugOut("NetChannelClient structure initialized")
    }

    return ioChannel, nil
}

func (f *NetChannelClient) InitializeCircuit() error {
    /*
     * Determine if we can pull anything from the target URI
     */
    if f.pingServer == true {
        if checkServerStatus := checkServerAliveStatus(f.controllerURL.String()); checkServerStatus != ERROR_SERVER_UP {
            return checkServerStatus
        }
    }

    /* Transmit and receive public keys, generate secret */
    if pkeStatus := f.initializePKE(); pkeStatus != nil {
        return pkeStatus
    }

    f.connected = true

    /*
     * Test the circuit
     */
    if f.testCircuit == true {
        if circuitStatus := f.testCircuitRoutine(); circuitStatus != nil {
            f.Close()
            return circuitStatus
        }
    }

    /*
     * Keep sending POSTs until some data is written to the controller write interface
     */
    checkWriteThread(f)
    util.SleepSeconds(5)

    return nil
}

func checkServerAliveStatus(URI string) error {
    var (
        parsedURI       *url.URL
        parseStatus     error
        remoteAddr      *net.IPAddr
        reachable       bool = false
    )
    parsedURI, parseStatus = url.Parse(URI)
    if parseStatus != nil {
        return ERROR_INVALID_URI
    }

    if parsedURI.Hostname() != "" {
        remoteAddr, parseStatus = net.ResolveIPAddr("ip4:icmp", parsedURI.Hostname())
        if parseStatus != nil {
            return ERROR_INVALID_URI
        }
    } else {
        q := net.ParseIP(parsedURI.Host)
        remoteAddr = &net.IPAddr{
            IP:         q,
            Zone:       "",
        }
    }

    /* Test ping */
    const numPings = 5
    if serverStatus := func (addr net.IPAddr) error {
        var ping = fastping.NewPinger()
        ping.AddIPAddr(&addr)
        ping.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
            reachable = true
        }

        for i := 0; i != numPings; i += 1 {
            if err := ping.Run(); err != nil {
                reachable = false
            }
        }

        if reachable == false {
            return ERROR_SERVER_DOWN
        }

        return ERROR_SERVER_UP
    } (*remoteAddr); serverStatus != ERROR_SERVER_UP {
        return serverStatus
    }

    var (
        response        *http.Response
        responseStatus  error
    )
    if response, responseStatus = http.Get(URI); responseStatus != nil || response == nil {
        return ERROR_SERVER_DOWN
    }

    return ERROR_SERVER_UP
}

func checkWriteThread(client *NetChannelClient) {
    /*
     * Periodically check to see if the server has any data to be sent to the
     *  socket. This is the primary i/o subsystem
     */
    go func (client *NetChannelClient) {
        for {
            read, written, err := client.writeStream(nil, FLAG_CHECK_STREAM_DATA)
            if err == io.EOF && (read + written) == 0 {
                /* Connection is closed due to a Write() request */
                if (client.flags & FLAG_DEBUG) > 0 && read == 0 {
                    datetime := func() string {
                        return time.Now().String()
                    }()
                    util.DebugOut("[" + datetime + "] FLAG_CHECK_STREAM_DATA: Keep-alive -- no data")
                }
                util.Sleep(10 * time.Millisecond)
                continue
            }

            /* Some other error -- i.e. the server terminates the socket */
            client.Close()
            return
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
        curveStatus             error = nil
        clientPrivateKey        crypto.PrivateKey
    )
    curve, request, clientPrivateKey, curveStatus = f.generateCurvePostRequest()
    if curveStatus != nil {
        return curveStatus
    }

    /* Perform HTTP TX, receive the public key from the server */
    body, initStatus := f.sendTransmission(f.config.HTTPVerb/* POST */, f.inputURI, request)
    if initStatus != nil {
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
    f.writeStream(nil, FLAG_TERMINATE_CONNECTION)
    f.connected = false
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
        f.cancelledSync.Lock()
        f.transport.CancelRequest(f.request)
    }
    f.cancelledSync.Lock()

    _, wrote, err := f.writeStream(p, 0)
    if err != io.EOF {
        return 0, err
    }

    return wrote, io.EOF
}

func (f *NetChannelClient) testCircuitRoutine() error {
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

    if rawData == nil && (flags & FLAG_CHECK_STREAM_DATA) > 0 {
        rawData, _ = returnCommandString(FLAG_CHECK_STREAM_DATA, *f.config)
    }

    /* Generate parameters */
    var (
        parmMap             = make(map[string]string)
        genPostStatus       error
    )
    if parmMap, genPostStatus = f.generatePOSTrequest(rawData, flags); genPostStatus != nil {
        return 0, 0, genPostStatus
    }

    /* Transmit */
    var body []byte
    body, sendStatus := f.sendTransmission(f.config.HTTPVerb, f.inputURI, parmMap)
    if sendStatus == nil && body == nil {
        /* This is the case in which Write() abruptly forces an HTTP channel to close */
        return 0,0, io.EOF
    }
    read = len(body)
    written = len(rawData)

    if read != 0 {
        /* Decode the body (TransferUnit) and store in NetChannelClient.ResponseData */
        if written, err = f.processHTTPresponse(body, flags); err != nil {
            return 0, 0, err
        }

        return read, written, io.EOF
    }

    return 0, written, io.EOF
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
    if written, err = f.responseData.Write(rawData); err != nil {
        return written, err
    }

    return written, nil
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
    var (
        req             *http.Request
        resp            *http.Response
        reqError        error
    )
    if req, reqError = f.generateHTTPheaders(URI, verb, params); reqError != nil {
        return nil, reqError
    }

    /*
     * This method invokes a thread which waits for a Write() call, and terminates the read request
     *  coming from the client to server. Consequently, the only type of request which ought to be
     *  terminated is a FLAG_CHECK_STREAM_DATA request, which, upon termination, does not contain
     *  data. If it does contain data, then a Write() was not called
     */
    resp, stopStatus := f.waitForWriteTxCancel(req)
    if resp == nil && stopStatus == nil{
        /*
         * Graceful termination of the FLAG_CHECK_STREAM_DATA request. There is no response, as a
         *  consequence of the abrupt termination of the stream. There is no data to be returned
         */
        return nil, nil
    }

    /*
     * The FLAG_CHECK_STREAM_DATA request was terminated, but not by force due to Write(), but because
     *  the server supplemented data on the stream. Check for a normal response
     */
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

func (f *NetChannelClient) waitForWriteTxCancel(httpRequestInput *http.Request) (*http.Response, error) {
    var (
        tr                  = &http.Transport{}
        httpClient          = &http.Client{Transport: tr}
        respIo              = make(chan *http.Response)
    )
    f.request               = httpRequestInput
    f.transport             = tr

    wasItCancelled          := false
    go func (httpRequest *http.Request) {
        util.Sleep(10 * time.Millisecond)
        var (
            response        *http.Response
            rxStatus        error = nil
        )
        if response, rxStatus = httpClient.Do(httpRequest); rxStatus != nil {
            /* If cancelled, the channel will close and the HTTP request will be cleaned up */
            wasItCancelled = true
            close(respIo)
            return
        }
        /*
         * In the instance of a regular transmit, this object should be passed, and this method
         *  should ultimately server no purpose.
         */
        respIo <- response
    } (f.request)

    resp, ok := <- respIo
    if !ok {
        /* Forced write request -- the request is cancelled, so permit another transmit */
        f.transport    = nil
        f.request      = nil
        f.cancelledSync.Unlock()
        return nil, nil
    }
    defer close(respIo)

    /* PKE doesn't require this */
    defer func(d bool) {
        if d == true {
            f.cancelledSync.Unlock()
        }
    } (wasItCancelled)

    /*
     * The timeout for FLAG_CHECK_STREAM_DATA was not reached, and the server has transmitted data
     *  in the meantime, meaning a response body should exist.
     */
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