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
    "github.com/AlexRuzin/util"
    "testing"
    "flag"
    "math"
    "errors"
    "strconv"
)

/* Configuration */
const CONTROLLER_DOMAIN             string = "127.0.0.1"
const CONTROLLER_PATH_GATE          string = "/gate.php"
const CONTROLLER_PORT               int16  = 2222

type serverType uint8
const (
    TYPE_SERVER                     serverType = iota
    TYPE_CLIENT                     /* Type is a client */
)
type configInput struct {
    controllerAddress               string
    controllerPort                  int16

    controllerGatePath              string

    /* False -- start client, true -- start server */
    runningMode                     serverType

    /* Configuration for the server */
    useEncryption                   bool
    useCompression                  bool

    /* Generic verbosity -- generic debug output */
    verbosity                       bool
}

var (
    genericConfig   *configInput = nil
    mainServer      *NetChannelService = nil
)
func TestMainChannel(t *testing.T) {
    /* Parse the user input and create a configInput instance */
    config, _ := func () (*configInput, error) {
        out := &configInput{
            controllerAddress:      CONTROLLER_DOMAIN,
            controllerPort:         CONTROLLER_PORT,
            controllerGatePath:     CONTROLLER_PATH_GATE,

            useEncryption:          true,
            useCompression:         true,

            runningMode:            TYPE_CLIENT,

            verbosity:              false,
        }

        tmp := flag.Int("server-mode", int(TYPE_CLIENT),
            "Start the test in server mode [")
        out.runningMode = serverType(*tmp)
        if out.runningMode == TYPE_CLIENT {
            /* Client-mode */
            &out.controllerAddress = flag.String("server-address", out.controllerAddress,
                "Target server address")
        }

        &out.controllerGatePath = flag.String("gate-path", out.controllerGatePath,
            "Default path for the gate, i.e. /path/gate.php")

        tmpPort := flag.Int("port", int(out.controllerPort),
            "Default service port [1-65536]")
        out.controllerPort = int16(*tmpPort)
        if float64(out.controllerPort) >= math.Exp2(float64(16)) {
            /* Cannot exceed 2^16 */
            panic(flag.ErrHelp)
        }

        &out.verbosity = flag.Bool("v", false, "Generic debug verbosity")
        D("Generic debug verbosity enabled")

        &out.useEncryption = flag.Bool("encrypt", true, "use standard encryption [forced]")
        &out.useCompression = flag.Bool("compress", true, "use standard compression [optional]")

        return out, nil
    } ()
    genericConfig = config

    /* It is absolutely required to use encryption, therefore check for this prior to anything futher */
    if config.useEncryption == false {
        panic(errors.New("must use the 'encrypt' flag to 'true'"))
    }

    if config.verbosity == true {
        func(config *configInput) {
            switch config.runningMode {
            case TYPE_CLIENT:
                D("We are running in TYPE_CLIENT mode. Default target server is: " + "http://" +
                    config.controllerAddress + ":" + util.IntToString(int(config.controllerPort)) +
                        config.controllerGatePath)
                break
            case TYPE_SERVER:
                D("We are running in TYPE_SERVER mode. Default listening port is: " +
                    util.IntToString(int(config.controllerPort)))
                D("Default listen path is set to: " + config.controllerGatePath)
            }

            D("Using encryption [forced]: " + strconv.FormatBool(config.useEncryption))
            D("Using compression [optional]: " + strconv.FormatBool(config.useCompression))
        }(config)
    }

    switch config.runningMode {
    case TYPE_CLIENT:
        var gateURI string = "http://" + config.controllerAddress + ":" +
            util.IntToString(int(config.controllerPort)) + config.controllerGatePath
        D("Client target URI is: " + gateURI)

        client, err := BuildChannel(gateURI /* Primary URI (scheme + domain + port + path) */ ,

            /* The below inlines will determine which flags to use based on use input */
            func(useDebug bool) FlagVal {
                if useDebug == true {
                    return FLAG_DEBUG
                }

                return 0
            }(config.verbosity)|
                func(useEncryption bool) FlagVal {
                    if useEncryption == true {
                        return FLAG_ENCRYPT
                    }

                    return 0
                }(config.useEncryption)|
                func(useCompression bool) FlagVal {
                    if useCompression == true {
                        return FLAG_COMPRESS
                    }

                    return 0
                }(config.useCompression),
        )
        if err != nil {
            panic(err)
        }
        if err := client.InitializeCircuit(); err != nil {
            panic(err)
        }

        break
    case TYPE_SERVER:
        D("Server is running on localhost, port: " + util.IntToString(int(config.controllerPort)) +
            ", on HTTP URI path: " + config.controllerGatePath)

        server, err := CreateServer(config.controllerGatePath, config.controllerPort,
            /* The below inlines will determine which flags to use based on use input */
            func(useDebug bool) FlagVal {
                if useDebug == true {
                    return FLAG_DEBUG
                }

                return 0
            }(config.verbosity)|
                func(useEncryption bool) FlagVal {
                    if useEncryption == true {
                        return FLAG_ENCRYPT
                    }

                    return 0
                }(config.useEncryption)|
                func(useCompression bool) FlagVal {
                    if useCompression == true {
                        return FLAG_COMPRESS
                    }

                    return 0
                }(config.useCompression),
            incomingClientHandler)
        if err != nil {
            panic(err)
        }
        mainServer = server
    }

    /* Wait forever */
    util.WaitForever()
}

func incomingClientHandler(client *NetInstance, server *NetChannelService) error {
    util.SleepSeconds(14)
    client.Write([]byte("some random data"))

    util.SleepSeconds(25)
    if client.Len() != 0 {
        data := make([]byte, client.Len())
        client.Read(data)
        util.DebugOut(string(data))
    }
    return nil
}

func D(debug string) {
    if genericConfig.verbosity == true {
        util.DebugOut("[+] " + debug + "\r\n")
    }
}

func T(debug string) {
    util.ThrowN("[!] " + debug)
}
