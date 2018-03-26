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
    "flag"
    "testing"
    "errors"
    "strconv"
    "time"
    "io"
    "encoding/json"
    "io/ioutil"

    "github.com/AlexRuzin/util"
)

/*
 * Configuration file name. Overriding the config filename is possible using the "-config" flag
 *  i.e.
 */
const JSON_FILENAME                 string = "config.json"

const DEFAULT_RX_WAIT_DURATION      time.Duration = 5000 /* milliseconds */

/*
 * For example, the config.json file uses the following key/value structure:
 *
 * {
 *   // true -> server/listener mode, false -> client/connect mode
 *   "Server": true,
 *
 *   // Debug is piped to stdout
 *   "Verbosity": true,
 *
 *   // Encryption/compression settings
 *   "Encryption": true,
 *   "Compression": true,
 *
 *   // Connectivity settings for both client and server
 *   "Port": 80,
 *   "Path": "/websock.php",
 *   "Domain": "127.0.0.1",
 *
 *   // If set to true the client will transmit data
 *   "ClientTX": true,
 *
 *   // Data is transmitted between these intervals (milliseconds)
 *   //  i.e every 2 seconds transmit.
 *   "ClientTXTimeMin": 2000,
 *   "ClientTXTimeMax": 2000,
 *
 *   // Transmit data in length between the below intervals (bytes)
 *   //  All data is sent are ASCII capitals between 0x41 - 0x5a
 *   "ClientTXDataMin": 16,
 *   "ClientTXDataMax": 64,
 *
 *   // If this is true, each character will be 'A' 0x41, otherwise
 *   //  they will be ASCII capitals
 *   "ClientTXDataStatic": true,
 *
 *   // If set to true, the server will transmit data to the client.
 *   //  All other settings below follow the above client convention
 *   "ServerTX": true,
 *
 *   "ServerTXTimeMin": 2000,
 *   "ServerTXTimeMax": 2000,
 *
 *   "ServerTXDataMin": 16,
 *   "ServerTXDataMax": 64,
 *
 *   "ServerTXDataStatic": true,
 *
 *   // Do not change this setting
 *   "ModuleName": "websock"
 * }
 */
const moduleName =                              "websock" /* Do not change this setting */
type ConfigInput struct {
    /* Default test mode */
    Server                          bool        `json:"Server"`

    Verbosity                       bool        `json:"Verbosity"`

    Encryption                      bool        `json:"Encryption"`
    Compression                     bool        `json:"Compression"`

    Port                            uint16      `json:"Port"`
    Path                            string      `json:"Path"`
    Domain                          string      `json:"Domain"`

    /* Transmission from client configuration */
    ClientTX                        bool        `json:"ClientTX"`
    ClientTXTimeMin                 uint64      `json:"ClientTXTimeMin"`
    ClientTXTimeMax                 uint64      `json:"ClientTXTimeMax"`
    ClientTXDataMin                 uint        `json:"ClientTXDataMin"`
    ClientTXDataMax                 uint        `json:"ClientTXDataMax"`
    ClientTXDataStatic              bool        `json:"ClientTXDataStatic"`

    /* Transmission from server configuration */
    ServerTX                        bool        `json:"ServerTX"`
    ServerTXTimeMin                 uint64      `json:"ServerTXTimeMin"`
    ServerTXTimeMax                 uint64      `json:"ServerTXTimeMax"`
    ServerTXDataMin                 uint        `json:"ServerTXDataMin"`
    ServerTXDataMax                 uint        `json:"ServerTXDataMax"`
    ServerTXDataStatic              bool        `json:"ServerTXDataStatic"`

    /* This value must be static "websock" */
    ModuleName                      string      `json:"ModuleName"`
}

var (
    mainConfig                      ConfigInput
    mainServer                      *NetChannelService
    mainClient                      *NetChannelClient
    configFilename                  *string = flag.String("config", JSON_FILENAME,
                                        "Usage -config [filename]")
)
func TestMainChannel(t *testing.T) {
    /* Parse config */
    var configStatus error
    if mainConfig, configStatus = setupJSONconfig(*configFilename); configStatus != nil {
        util.RetErrStr(configStatus.Error())
    }

    /* Debug output if verbosity switch is true */
    if mainConfig.Verbosity == true {
        printDebugOutput()
    }

    var err error
    switch mainConfig.Server {
    case false: /* Client mode */
        if mainClient, err = startClientMode(mainConfig); err != nil {
            util.RetErrStr(err.Error())
        }
        break
    case true: /* Server mode */
        if mainServer, err = startServerMode(mainConfig); err != nil {
            util.RetErrStr(err.Error())
        }
        mainServer.startListeners()
    }

    /* Wait forever */
    util.WaitForever()
}

func startServerMode(config ConfigInput) (*NetChannelService, error) {
    D("Server is running on localhost, port: " + util.IntToString(int(config.Port)) +
        ", on HTTP URI path: " + config.Path)

    var createStatus error
    mainServer, createStatus = CreateServer(config.Path, int16(config.Port),
        /* The below inlines will determine which flags to use based on use input */
        func(useDebug bool) FlagVal {
            if useDebug == true {
                return FLAG_DEBUG
            }

            return 0
        }(config.Verbosity) |
            func(useEncryption bool) FlagVal {
                if useEncryption == true {
                    return FLAG_ENCRYPT
                }

                return 0
            }(config.Encryption) |
            func(useCompression bool) FlagVal {
                if useCompression == true {
                    return FLAG_COMPRESS
                }

                return 0
            }(config.Compression),
        incomingClientHandler)
    if createStatus != nil {
        util.RetErrStr(createStatus.Error())
    }

    return mainServer, nil
}

func startClientMode(config ConfigInput) (*NetChannelClient, error) {
    var gateURI string = "http://" + config.Domain + ":" +
        util.IntToString(int(config.Port)) + config.Path
    D("Client target URI is: " + gateURI)

    var buildStatus error
    mainClient, buildStatus = BuildChannel(gateURI /* Primary URI (scheme + domain + port + path) */ ,

        /* The below inlines will determine which flags to use based on use input */
        func(useDebug bool) FlagVal {
            if useDebug == true {
                return FLAG_DEBUG
            }

            return 0
        }(config.Verbosity) |
            func(useEncryption bool) FlagVal {
                if useEncryption == true {
                    return FLAG_ENCRYPT
                }

                return 0
            }(config.Encryption) |
            func(useCompression bool) FlagVal {
                if useCompression == true {
                    return FLAG_COMPRESS
                }

                return 0
            }(config.Compression),
    )
    if buildStatus != nil {
        util.RetErrStr(buildStatus.Error())
    }
    if err := mainClient.InitializeCircuit(); err != nil {
        util.RetErrStr(err.Error())
    }
    clientTX(config)

    return mainClient, nil
}

func printDebugOutput() {
    /* It is absolutely required to use encryption, therefore check for this prior to anything futher */
    if mainConfig.Encryption == false {
        panic(errors.New("must use the 'encrypt' flag to 'true'"))
    }

    if mainConfig.Verbosity == true {
        func(config ConfigInput) {
            switch config.Server {
            case false: /* Client mode */
                D("We are running in TYPE_CLIENT mode. Default target server is: " + "http://" +
                    config.Domain + ":" + util.IntToString(int(config.Port)) +
                    config.Path)
                break
            case true: /* Server mode */
                D("We are running in TYPE_SERVER mode. Default listening port is: " +
                    util.IntToString(int(config.Port)))
                D("Default listen path is set to: " + config.Path)
            }

            D("Using encryption [forced]: " + strconv.FormatBool(config.Encryption))
            D("Using compression [optional]: " + strconv.FormatBool(config.Compression))
        }(mainConfig)
    }
    D("Configuration file " + *configFilename + " is nominal, proceeding...")
}

func setupJSONconfig(file string) (ConfigInput, error) {
    /* Parse the user input and create a configInput instance */
    var (
        rawFile             []byte
        readStatus          error
    )
    if rawFile, readStatus = ioutil.ReadFile(file); readStatus != nil {
        util.RetErrStr(readStatus.Error())
    }

    /*
     * Build the configInput structure
     */
    parseStatus := json.Unmarshal(rawFile, &mainConfig)
    if parseStatus != nil {
        util.RetErrStr(parseStatus.Error())
    }
    if mainConfig.ModuleName != moduleName {
        util.RetErrStr("invalid configuration file: " + *configFilename)
    }

    /*
     * Check configuration sanity
     */
    if mainConfig.ServerTXTimeMax < mainConfig.ServerTXTimeMin ||
        mainConfig.ServerTXDataMax < mainConfig.ServerTXDataMin ||
        mainConfig.ClientTXDataMax < mainConfig.ClientTXDataMin ||
        mainConfig.ClientTXTimeMax < mainConfig.ClientTXTimeMin {

        util.RetErrStr("invalid configuration file, data/timeout ranges are not configured properly")
    }

    return mainConfig, nil
}

func incomingClientHandler(client *NetInstance, server *NetChannelService) error {
    D("Initial connect from client " + client.ClientIdString)

    server.clientMap[client.ClientIdString] = client
    serverTX(mainConfig)

    return nil
}

func clientTX(config ConfigInput) {
    /*
     * Transmit data
     */
    func () {
        if config.ClientTX == true {
            go func(config ConfigInput) {
                if mainClient.connected == false {
                    util.RetErrStr("Failed to connect to server")
                }

                var transmitStatus error = nil
                for {
                    if config.ClientTXTimeMin == config.ClientTXTimeMax {
                        util.Sleep(time.Duration(config.ClientTXTimeMin) * time.Millisecond)
                    } else {
                        /* Transmit within a random time range */
                        util.Sleep(time.Duration(util.RandInt(int(config.ClientTXTimeMin),
                            int(config.ClientTXTimeMax))) * time.Millisecond)
                    }

                    transmitStatus = transmitRawData(config.ClientTXDataMin, config.ClientTXDataMax,
                        config.ClientTXDataStatic, handlerClientTx)
                    if transmitStatus != nil {
                        panic(transmitStatus)
                    }
                }
            }(config)
        }
    } ()

    /* Receive data */
    go func (config ConfigInput) {
        for {
            if len, rxStatus := mainClient.Wait(DEFAULT_RX_WAIT_DURATION); rxStatus == WAIT_DATA_RECEIVED {
                rawData := make([]byte, len)
                mainClient.Read(rawData)
                D("inbound data from server (" + util.IntToString(len) + " bytes): " + string(rawData))
            }
        }
    } (config)
}

func serverTX(config ConfigInput) {
    /* Transmit data periodically */
    if config.ServerTX == true {
        go func (config ConfigInput) {
            var transmitStatus error
            for {
                if config.ServerTXTimeMin == config.ServerTXTimeMax {
                    util.Sleep(time.Duration(config.ServerTXTimeMin) * time.Millisecond)
                } else {
                    /* Transmit within a random time range */
                    util.Sleep(time.Duration(util.RandInt(int(config.ServerTXTimeMin),
                        int(config.ServerTXTimeMax))) * time.Millisecond)
                }
                transmitStatus = transmitRawData(config.ServerTXDataMin, config.ServerTXDataMax,
                    config.ServerTXDataStatic, handlerServerTx)
                if transmitStatus != nil {
                    util.RetErrStr(transmitStatus.Error())

                }
            }
        } (config)
    }
}

func transmitRawData(minLen uint, maxLen uint, staticData bool, handler func(p []byte) error) error {
    var (
        rawLength           int
        rawData             []byte
    )
    if minLen == maxLen {
        rawLength = int(minLen)
    } else {
        rawLength = util.RandInt(int(minLen), int(maxLen))
    }

    if staticData == true {
        rawData = make([]byte, 1)
        rawData[0] = 'A'
        for c := 0; c != rawLength; c += 1 {
            rawData = append(rawData, 'A')
        }
    } else {
        rawData = []byte(util.RandomString(rawLength))
    }

    /* Invoke the transmit method */
    var txStatus = handler(rawData)
    if txStatus != io.EOF {
        return txStatus
    }

    return nil
}

func handlerClientTx(p []byte) error {
    txLen, err := mainClient.Write(p)
    if err != io.EOF {
        return err
    }

    if txLen != len(p) {
        return util.RetErrStr("handlerClientTx() reports unexpected EOF in write stream")
    }

    return nil
}

func handlerServerTx(p []byte) error {
    /* Write to all clients */
    for _, v := range mainServer.clientMap {
        //D("transmitting data to client: " + v.ClientIdString)
        txLen, err := v.Write(p)
        if err != io.EOF {
            return err
        }
        D("sent [" + util.IntToString(len(p)) + " bytes]: " + string(p))

        if txLen != len(p) {
            return util.RetErrStr("handlerServerTx() reports unexpected EOF in write stream")
        }
    }

    return nil
}

func D(debug string) {
    if mainConfig.Verbosity == true {
        util.DebugOut("[+] " + debug)
    }
}

func T(debug string) {
    util.ThrowN("[!] " + debug)
}
