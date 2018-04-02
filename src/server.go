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

/* Commit test */

package src

import (
    "fmt"
    "sync"
    "bytes"
    "strings"
    "io"
    "time"
    "net/http"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/md5"
    "encoding/hex"

    "github.com/AlexRuzin/util"
    "github.com/wsddn/go-ecdh"
)

/************************************************************
 * websock Server objects and methods                       *
 ************************************************************/
type NetChannelService struct {
    /* Handler for new clients */
    IncomingHandler         func(client *NetInstance, server *NetChannelService) error

    /* Flags may be modified at any time */
    Flags                   FlagVal

    /* Non-exported members */
    port                    int16
    pathGate                string
    clientMap               map[string]*NetInstance
    clientSync              sync.Mutex

    config                  *ProtocolConfig
}

/*
 * Global object representing the service instance
 */
var channelService          *NetChannelService

/*
 * Channel for inbound clients
 */
var clientIO                = make(chan *NetInstance)

type NetInstance struct {
    /* Unique identifier that represents the client connection */
    ClientIdString          string

    /* Non-exported members */
    service                 *NetChannelService
    secret                  []byte
    clientId                []byte
    clientTX                *bytes.Buffer   /* Data waiting to be transmitted */
    clientRX                rxBuffer        /* Data that is waiting to be read, using a custom FIFO queue */
    iOSync                  sync.Mutex

    connected               bool

    /* URI Path */
    RequestURI              string
}

func CreateServer(pathGate string, port int16, flags FlagVal, handler func(client *NetInstance,
    server *NetChannelService) error) (*NetChannelService, error) {

    /* The FLAG_ENCRYPT switch must always be set to true */
    if (flags & FLAG_ENCRYPT) == 0 {
        return nil, util.RetErrStr("FLAG_ENCRYPT must be set")
    }

    var (
        tmpConfig   *ProtocolConfig
        err         error
    )
    tmpConfig, err = parseConfig()
    if err != nil {
        return nil, err
    }

    if testCharSetPKE(tmpConfig.PostBodyKeyCharset) == false {
        return nil, util.RetErrStr("PANIC: POST_BODY_KEY_CHARSET contains non-unique elements")
    }

    var server = &NetChannelService{
        IncomingHandler:    handler,
        port:               port,
        Flags:              flags,
        pathGate:           pathGate,

        /* Map consists of key: ClientId (string) and value: *NetInstance object */
        clientMap:          make(map[string]*NetInstance),

        /* Set the main config */
        config:             tmpConfig,
    }
    channelService = server

    /* Start the inbound/outbound listener threads */
    util.Sleep(100 * time.Millisecond)
    server.startListeners()

    return server, nil
}

func (f *NetChannelService) closeClient(client *NetInstance) {
    f.clientSync.Lock()
    delete(f.clientMap, client.ClientIdString)
    f.clientSync.Unlock()
}

func (f *NetChannelService) CloseService() {
    if clientIO != nil {
        close(clientIO)
    }
}

func (f *NetInstance) Close(client *NetInstance) {
    f.service.closeClient(client)
}

/*
 * Retrieves length of the buffer at index 0
 */
func (f *NetInstance) Len() int {
    return f.clientRX.len()
}

func (f *NetInstance) Wait(timeoutMilliseconds time.Duration) (responseLen int, err error) {
    if f.connected == false {
        return 0, util.RetErrStr("client not connected")
    }

    responseLen = 0
    err = WAIT_TIMEOUT_REACHED

    for i := timeoutMilliseconds / 100; i != 0; i -= 1 {
        if f.connected == false {
            responseLen = -1
            err = WAIT_CLOSED
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

func (f *NetInstance) Read(p []byte) (read int, err error) {
    read, err = f.readInternal(p)
    if err != io.EOF {
        return 0, err
    }

    return
}

func (f *NetInstance) Write(p []byte) (wrote int, err error) {
    wrote, err = f.writeInternal(p)
    if err != io.EOF {
        return 0, err
    }

    return
}

func (f *NetChannelService) startListeners() {
    go func (svc *NetChannelService) {
        var wg sync.WaitGroup
        wg.Add(1)

        for {
            client, ok := <- clientIO
            if !ok {
                break /* Close the processor */
            }

            svc.clientSync.Lock()

            svc.clientMap[client.ClientIdString] = client
            if err := svc.IncomingHandler(client, svc); err != nil {
                svc.closeClient(client)
            }

            svc.clientSync.Unlock()
            client.connected = true
        }
    } (f)

    go func(svc *NetChannelService) {
        /* FIXME -- find a way of closing this thread once CloseService() is invoked */
        http.HandleFunc(svc.pathGate, handleClientRequest)

        svc.sendDebug("Handling request for path :" + svc.pathGate)
        if err := http.ListenAndServe(":" + util.IntToString(int(f.port)),nil); err != nil {
            util.ThrowN("panic: Failure in loading httpd.")
        }
    } (f)
}

/* Create circuit -OR- process gate requests */
func handleClientRequest(writer http.ResponseWriter, reader *http.Request) {
    if clientIO == nil {
        util.RetErrStr("Cannot handle request without initializing processor")
    }
    defer reader.Body.Close()

    /* Contains the marshalled Public Key after the initial decoding */
    var (
        marshalledPublicClientKey       *string
        keyStatus                       error
    )
    if marshalledPublicClientKey, keyStatus = decodePublicKeyParameters(reader); keyStatus != nil {
        util.RetErrStr(keyStatus.Error())
    }

    if marshalledPublicClientKey == nil {
        /*
         * Parameter for key negotiation does not exist. This implies that either someone is not using
         *  the server in the designed fashion, or that there is another command request coming from
         *  and existing client. Here we verify if the client exists.
         *
         * If it's a command, then there should be only one parameter, which is:
         *  b64(ClientIdString) = <command>
         */
         parseExistingClient(reader, &writer)

         return /* The appropriate ClientData has been stored, so no more need for this method */
    }

    /*
     * Create a new client
     */
    if err := handleNewClient(*marshalledPublicClientKey, reader, &writer); err != nil {
        util.DebugOut(err.Error())
    }

    return
}

func handleNewClient(marshalledKey string, reader *http.Request, writer *http.ResponseWriter) error {
    /* Parse client-side public ECDH key*/
    marshalled, err := getClientPublicKey(marshalledKey)
    if err != nil || marshalled == nil {
        sendBadErrorCode(*writer, err)
        util.DebugOut(err.Error())
        return err
    }

    ecurve := ecdh.NewEllipticECDH(elliptic.P384())
    clientPublicKey, ok := ecurve.Unmarshal(marshalled)
    if !ok {
        sendBadErrorCode(*writer, util.RetErrStr("unmarshalling failed"))
        return util.RetErrStr("Failed to unmarshal the ecurve Public Key")
    }

    /*
     * Since the client public key is nominal return generate
     *  our own keypair
     */
    serverPrivateKey, serverPublicKey, err := ecurve.GenerateKey(rand.Reader)
    if err != nil {
        sendBadErrorCode(*writer, err)
        return err
    }

    /* Transmit the server public key */
    var serverPubKeyMarshalled = ecurve.Marshal(serverPublicKey)
    if serverPubKeyMarshalled == nil {
        sendBadErrorCode(*writer, util.RetErrStr("Failed to marshal server-side pub key"))
        return err
    }
    clientId := md5.Sum(marshalled)
    if err := sendPubKey(*writer, serverPubKeyMarshalled, clientId[:]); err != nil {
        sendBadErrorCode(*writer, err)
        return err
    }

    /* Generate the secret */
    secret, err := ecurve.GenerateSharedSecret(serverPrivateKey, clientPublicKey)
    if len(secret) == 0 {
        sendBadErrorCode(*writer, util.RetErrStr("Failed to generate a shared secret key"))
        return err
    }

    if (channelService.Flags & FLAG_DEBUG) > 1 {
        util.DebugOut("Server-side secret:")
        util.DebugOutHex(secret)
    }

    var instance = &NetInstance{
        service:            channelService,
        secret:             secret,
        clientId:           clientId[:],
        ClientIdString:     hex.EncodeToString(clientId[:]),
        clientRX:           rxBuffer{},
        clientTX:           &bytes.Buffer{},
        connected:          false,
        RequestURI:         reader.RequestURI,
    }

    /* Send the signal to startListeners() */
    clientIO <- instance

    return nil
}

func parseExistingClient(reader *http.Request, writer *http.ResponseWriter) {
    /*
     * Parameter for key negotiation does not exist. This implies that either someone is not using
     *  the server in the designed fashion, or that there is another command request coming from
     *  and existing client. Here we verify if the client exists.
     *
     * If it's a command, then there should be only one parameter, which is:
     *  b64(ClientIdString) = <command>
     */
    key := reader.Form
    if key == nil {
        return
    }

    for k := range key {
        var err error = nil
        var decodedKey []byte
        if decodedKey, err = util.B64D(k); err != nil {
            continue
        }
        client := channelService.clientMap[string(decodedKey)]
        if client != nil {
            /*
             * An active connection exists.
             *
             * Base64 decode the signal and return the RC4 encrypted buffer to
             *  be processed
             *
             * Write data to NetInstance.ClientData
             */
            value := key[k]
            var (
                clientId       string
                data           []byte = nil
                txUnit         *transferUnit = nil
            )
            if clientId, data, txUnit, err = decryptData(value[0], client.secret);
                err != nil || strings.Compare(clientId, client.ClientIdString) != 0 {
                channelService.closeClient(client)
                return
            }

            if (channelService.Flags & FLAG_COMPRESS) > 0 && (txUnit.Flags & FLAG_COMPRESS) > 0 {
                var streamStatus error = nil
                data, streamStatus = util.DecompressStream(data)
                if streamStatus != nil {
                    channelService.closeClient(client)
                    return
                }
            }

            if err := client.parseClientData(data, *writer); err != nil {
                channelService.closeClient(client)
                return
            }

            return /* The appropriate ClientData has been stored, so no more need for this method */
        }
    }
}

func decodePublicKeyParameters(reader *http.Request) (clientKey *string, err error) {
    /* Get remote client public key base64 marshalled string */
    clientKey = nil
    if err := reader.ParseForm(); err != nil {
        util.DebugOut(err.Error())
        return clientKey, err
    }

    for key := range reader.Form {
        for i := len(channelService.config.PostBodyKeyCharset); i != 0; i -= 1 {
            var tmpKey = string(channelService.config.PostBodyKeyCharset[i - 1])

            decodedKey, err := util.B64D(key)
            if err != nil {
                return nil, err
            }

            if strings.Compare(tmpKey, string(decodedKey)) == 0 {
                clientKey = &reader.Form[key][0]
                break
            }
        }
        if clientKey != nil {
            break
        }
    }
    return clientKey, nil
}

func (f *NetInstance) cmdWaitAndTransmitData(writer http.ResponseWriter) error {
    if f.connected == false {
        return util.RetErrStr("client not connected")
    }

    var timeout = f.service.config.C2ResponseTimeout
    for ; timeout != 0; timeout -= 1 {
        if f.clientTX.Len() != 0 {
            break
        }
        util.Sleep(1 * time.Second)
    }

    f.iOSync.Lock()
    defer f.iOSync.Unlock() /* We break out of the loop so defer is OK */

    if timeout == 0 || f.clientTX.Len() == 0 {
        /* Time out -- no data to be sent */
        writer.WriteHeader(http.StatusOK)
        return nil
    }

    defer f.clientTX.Reset()

    var (
        outputStream = f.clientTX.Bytes()
        otherFlags FlagVal = 0
    )

    if (f.service.Flags & FLAG_COMPRESS) > 0 && len(outputStream) > util.GetCompressedSize(outputStream) {
        otherFlags |= FLAG_COMPRESS
        var streamStatus error = nil
        outputStream, streamStatus = util.CompressStream(outputStream)
        if streamStatus != nil {
            panic(streamStatus)
        }
    }

    encrypted, _ := encryptData(outputStream, f.secret, FLAG_DIRECTION_TO_CLIENT, otherFlags, f.ClientIdString)
    return sendResponse(writer, encrypted)
}

func (f *NetInstance) parseClientData(rawData []byte, writer http.ResponseWriter) error {
    /*
     * Check for internal commands first
     */
    if util.IsAsciiPrintable(string(rawData)) {
        var command = string(rawData)

        switch command {
        case f.service.config.CheckStream: // FLAG_CHECK_STREAM_DATA
            return f.cmdWaitAndTransmitData(writer)

        case f.service.config.TestStream: // FLAG_TEST_CONNECTION
            encrypted, _ := encryptData(rawData, f.secret, FLAG_DIRECTION_TO_CLIENT, 0, f.ClientIdString)
            return sendResponse(writer, encrypted)

        case f.service.config.TermConnect: // FLAG_TERMINATE_CONNECTION
            /* FIXME */
            panic("terminating connection")
        }
    }

    /* Append data to read buffer */
    if f.connected == false {
        return util.RetErrStr("client not connected")
    }

    f.iOSync.Lock()
    defer f.iOSync.Unlock()

    var requestData []byte = rawData

    /* Decompression, if required, has already taken place in handleClientRequest() by parsing the TransmissionUnit flags */
    f.clientRX.enqueue(requestData)

    /* If there is any data to return, then send it over */
    var otherFlags FlagVal = 0
    if f.clientTX.Len() > 0 {
        defer f.clientTX.Reset()

        var outputStream []byte = f.clientTX.Bytes()

        if (f.service.Flags & FLAG_COMPRESS) > 0 && len(outputStream) > util.GetCompressedSize(outputStream) {
            otherFlags |= FLAG_COMPRESS

            var streamStatus error = nil
            outputStream, streamStatus = util.CompressStream(outputStream)
            if streamStatus != nil {
                panic(streamStatus)
            }
        }

        encrypted, _ := encryptData(outputStream, f.secret, FLAG_DIRECTION_TO_CLIENT, otherFlags, f.ClientIdString)
        return sendResponse(writer, encrypted)
    }
    writer.WriteHeader(http.StatusOK)

    return nil
}

func (f *NetInstance) readInternal(p []byte) (int, error) {
    if f.connected == false {
        return 0, util.RetErrStr("client not connected")
    }

    if f.clientRX.len() == 0 {
        return 0, io.EOF
    }

    f.iOSync.Lock()
    defer f.iOSync.Unlock()

    rawData := f.clientRX.dequeue()
    copy(p, rawData)

    return len(rawData), io.EOF
}

func (f *NetInstance) writeInternal(p []byte) (int, error) {
    if f.connected == false {
        return 0, util.RetErrStr("client not connected")
    }

    f.iOSync.Lock()
    defer f.iOSync.Unlock()

    f.clientTX.Write(p)

    return len(p), io.EOF
}

/* HTTP 500 - Internal Server Error */
func sendBadErrorCode(writer http.ResponseWriter, err error) {
    writer.WriteHeader(http.StatusInternalServerError)
    writer.Write([]byte("500 - " + err.Error()))
    return
}

func sendResponse(writer http.ResponseWriter, data []byte) error {
    if len(data) == 0 {
        return util.RetErrStr("sendResponse: Invalid parameter")
    }

    var b64Encoded = util.B64E(data)

    writer.Header().Set("Content-Type", channelService.config.ContentType)
    writer.Header().Set("Connection", "close")
    writer.WriteHeader(http.StatusOK)

    fmt.Fprintln(writer, b64Encoded)

    return nil
}

/* EOF */