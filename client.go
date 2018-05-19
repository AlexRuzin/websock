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
    "sync"
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

    /* Data coming in from the server via queue subsystem */
    responseData        *clientRx

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

/*
 * Read only one element in the read queue, which is populated automatically
 *  once a response is given by the server to the client.
 *
 * A Read request may be issued by the client by using the internal function
 *  readStream().
 */
func (f *NetChannelClient) Read(p []byte) (read int, err error) {
    if f.connected == false {
        return 0, util.RetErrStr("readInternal(): client not connected")
    }

    if f.Len() == 0 {
        return 0, io.EOF
    }

    /*
     * Read from the response queue
     */
    queueData, err := f.dequeue()
    if err != nil {
        return 0, err
    }
    copy(p, queueData)

    return len(queueData), io.EOF
}

/*
 * Create's a Write() stream by generating a POST request to the server, in
 *  parallel to the inbound stream
 */
func (f *NetChannelClient) Write(p []byte) (written int, err error) {
    if f.connected == false {
        return 0, util.RetErrStr("writeInternal(): client not connected")
    }

    wrote, err := f.transmitHttpRequest(p, 0)
    if err != io.EOF {
        return 0, err
    }

    return wrote, io.EOF
}

func (f *NetChannelClient) Len() int {
    if f.connected == false {
        return 0
    } else if f.responseData == nil {
        return 0
    }

    return f.queueLen()
}

func (f *NetChannelClient) Wait(timeoutMilliseconds time.Duration) (responseLen int, err error) {
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
        responseData:       nil,
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
    util.Sleep(100 * time.Millisecond)

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
            var (
                rawData             []byte
                parmMap             = make(map[string]string)
                httpRequest         *http.Request
                response            *http.Response
                tr                  = &http.Transport{}
                httpClient          = &http.Client{Transport: tr}
                body                []byte
                err                 error
            )
            rawData, _ = returnCommandString(FLAG_CHECK_STREAM_DATA, *client.config)
            if parmMap, err = client.generatePOSTrequest(rawData, FLAG_CHECK_STREAM_DATA);
                err != nil {
                break
            }

            /* Generate headers from parameter map */
            if httpRequest, err = client.generateHTTPheaders(client.inputURI, client.config.HTTPVerb, parmMap); err != nil {
                break
            }

            /* Write to stream */
            if response, err = httpClient.Do(httpRequest); err != nil || response.Status != "200 OK" {
                break
            }

            body, err = ioutil.ReadAll(response.Body)
            if len(body) > 0 {
                /* Write to response queue */
                client.enqueue(body)
            }

            response.Body.Close()
        }

        client.Close()
        return
    } (client)
}

func (f *NetChannelClient) initializePKE() (error) {
    /*
     * Generate keypair, construct HTTP POST request parameter map
     */
    var ( /* Output reserved for keypair/post request generate method */
        curve                   ecdh.ECDH
        paramaterMap            map[string]string
        curveStatus             error = nil
        clientPrivateKey        crypto.PrivateKey
        response                *http.Response
        tr                      = &http.Transport{}
        httpClient              = &http.Client{Transport: tr}
    )
    curve, paramaterMap, clientPrivateKey, curveStatus = f.generateCurvePostRequest()
    if curveStatus != nil {
        return curveStatus
    }

    /* Perform HTTP TX, receive the public key from the server */
    request, reqStatus := f.generateHTTPheaders(f.inputURI, f.config.HTTPVerb, paramaterMap)
    if reqStatus != nil {
        return reqStatus
    }

    response, reqStatus = httpClient.Do(request)
    if reqStatus != nil {
        return reqStatus
    }

    /*
     * Read from stream
     */
    if response.Status != "200 OK" {
        return util.RetErrStr("200 OK not returned by server during PKE initialization")
    }
    defer response.Body.Close()

    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return err
    }
    if len(body) == 0 {
        return util.RetErrStr("server has returned a null length public key")
    }

    /*
     * Decode the public key returned by the server and create a secret key
     */
    if f.secret, err = f.decodeServerPubkeyGenSecret(body, clientPrivateKey, curve); err != nil {
        return err
    }

    if (f.flags & FLAG_DEBUG) > 0 {
        util.DebugOut("Client-side secret:")
        util.DebugOutHex(f.secret)
    }

    return nil
}

func (f *NetChannelClient) Close() {
    f.transmitHttpRequest(nil, FLAG_TERMINATE_CONNECTION)
    f.connected = false
}

func (f *NetChannelClient) testCircuitRoutine() error {
    if _, err := f.transmitHttpRequest(nil, FLAG_TEST_CONNECTION); err != io.EOF {
        return err
    }

    if f.queueLen() == 0 {
        return util.RetErrStr("testCircuit() failed on the server side")
    }

    read, err := f.dequeue()
    if err != io.EOF || len(read) != len(f.config.TestStream) {
        return util.RetErrStr("testCircuit() invalid response from server side")
    }

    if !util.IsAsciiPrintable(string(read)) ||
        strings.Compare(string(read), f.config.TestStream) != 0 {
        return util.RetErrStr("testCircuit() data corruption from server side")
    }

    return nil
}

func (f *NetChannelClient) transmitHttpRequest(rawData []byte, flags FlagVal) (written int, err error) {
    if !((flags & FLAG_TEST_CONNECTION) > 0) && f.connected == false {
        return 0, util.RetErrStr("writeStream(): client not connected")
    }

    if (flags & FLAG_TERMINATE_CONNECTION) > 0 {
        rawData, _ = returnCommandString(FLAG_TERMINATE_CONNECTION, *f.config)
    }
    if rawData == nil && (flags & FLAG_CHECK_STREAM_DATA) > 0 {
        rawData, _ = returnCommandString(FLAG_CHECK_STREAM_DATA, *f.config)
    }

    /*
     * Generates a request. This may be a FLAG_CHECK_STREAM_DATA request, or a generic
     *  write request to the transmit stream.
     *
     * The returnCommandString() method, when invoked (above), generates an ASCII string
     *  that can be configured in shared.go.
     */
    var (
        parmMap             = make(map[string]string)
        genPostStatus       error
    )
    if parmMap, genPostStatus = f.generatePOSTrequest(rawData, flags); genPostStatus != nil {
        return 0, genPostStatus
    }

    /* Generate headers from parameter map */
    var httpRequest *http.Request
    if httpRequest, err = f.generateHTTPheaders(f.inputURI, f.config.HTTPVerb, parmMap); err != nil {
        return 0, err
    }

    /*
     * Transmit request and receive response, if any
     */
    var (
        tr              = &http.Transport{}
        httpClient      = &http.Client{Transport: tr}
        httpResponse    *http.Response
    )
    if httpResponse, err = httpClient.Do(httpRequest); err != nil {
        /*
         * Unknown error in request, Logic is to attempt comms until server sends the terminate
         *  signal FLAG_TERMINATE_CONNECTION
         */
        return 0, err
    }

    /*
     * Check for nominal HTTP response first1
     */
    if httpResponse.Status != "200 OK" {
        return 0, util.RetErrStr("HTTP 200 OK not returned")
    }
    defer httpResponse.Body.Close()

    /*
     * There should NOT be a response inbound in this stream, only 200 OK. Response are returned
     *  when a FLAG_CHECK_STREAM_DATA request is transmitted via readStream()
     */
    if err = func (resp *http.Response) error {
        body, error := ioutil.ReadAll(resp.Body)
        if error != io.EOF {
            return util.RetErrStr("Unexpected response from mangled response buffer during write")
        }

        if len(body) > 0 {
            return util.RetErrStr("Server returned response during write I/O request")
        }

        return io.EOF
    } (httpResponse); err != nil {
        return len(rawData), err
    }

    return len(rawData), io.EOF
}

func (f *NetChannelClient) decryptAndWriteResponse(body []byte, flags FlagVal) (err error) {
    /* Decode the body (TransferUnit) and store in NetChannelClient.ResponseData */
    clientId, rawData, _, err := decryptData(string(body), f.secret)
    if err != nil {
        return err
    }
    if strings.Compare(clientId, f.clientIdString) != 0 {
        return util.RetErrStr("Invalid server response")
    }

    if (f.flags & FLAG_COMPRESS) > 0 && !((flags & FLAG_TEST_CONNECTION) > 0) {
        var (
            streamStatus        error = nil
            decompressed        []byte
        )

        decompressed, streamStatus = util.DecompressStream(rawData)
        if streamStatus != nil && len(decompressed) == 0 {
            return err
        }

        rawData = decompressed
    }

    /* Write either the compressed or decompressed stream queue */
    f.enqueue(rawData)
    return nil
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
        deflateStatus       error = nil
        txData              = rawData
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

/*
 * Response queue mechanism for the client
 *  FIXME -- merge this with the server.go implementation
 */
type clientRx struct {
    data            *bytes.Buffer

    next            *clientRx
    last            *clientRx
}
var clientRespSync  sync.Mutex

func (f *NetChannelClient) enqueue(p []byte) {
    clientRespSync.Lock()
    defer clientRespSync.Unlock()

    if f.responseData == nil {
        f.responseData = &clientRx{
            data:   bytes.NewBuffer(p),
            next:   nil,
            last:   nil,
        }

        return
    }

    f.responseData.last = &clientRx{
        data:   bytes.NewBuffer(p),
        next:   f.responseData,
        last:   nil,
    }

    f.responseData = f.responseData.last
}

func (f *NetChannelClient) dequeue() ([]byte, error) {
    clientRespSync.Lock()
    defer clientRespSync.Unlock()

    if f.responseData == nil {
        return nil, nil
    }

    if f.responseData.next == nil {
        out := f.responseData.data.Bytes()
        f.responseData = nil
        return out, nil
    }

    endElement := f.responseData
    for ;endElement.next != nil; endElement = endElement.next {}
    var out = endElement.data.Bytes()
    t := endElement.last
    t.next = nil

    return out, nil

}

func (f *NetChannelClient) queueLen() int {
    clientRespSync.Lock()
    defer clientRespSync.Unlock()

    if f.responseData == nil {
        return 0
    }

    q := f.responseData
    total := 0
    for q != nil {
        total += q.data.Len()
        q = q.next
    }

    return total
}

/* EOF */