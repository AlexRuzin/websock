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
    "os"
    "strings"
)

/* Test configuration */
const RUN_CLIENT_TEST                bool = true
const RUN_SERVER_TEST                bool = true

/* Configuration */
//const CONTROLLER_DOMAIN              string = "192.168.0.50:8080"
const CONTROLLER_DOMAIN              string = "127.0.0.1"
const CONTROLLER_PATH_GATE           string = "/gate.php"
const CONTROLLER_PORT                int16 = 80

const STANDALONE                     bool = false

func TestMainChannel(t *testing.T) {
    if STANDALONE == true {
        if len(os.Args) == 0 {
            panic("Invalid arguments")
        }

        var mode = os.Args[1:]
        if strings.Compare("server", mode[0]) == 0{
            D("Building the server processor")
            D("Starting websock service on [TCP] port: " + util.IntToString(int(CONTROLLER_PORT)))

            service, err := CreateServer(CONTROLLER_PATH_GATE, /* /gate.php */
                CONTROLLER_PORT, /* 80 */
                FLAG_DEBUG,
                incomingClientHandler)
            if err != nil || service == nil {
                D(err.Error())
                T("Cannot start websock service")
            }
        }

        if strings.Compare("client", mode[0]) == 0 {
            D("Building the client transporter")

            gate_uri := "http://" + CONTROLLER_DOMAIN + CONTROLLER_PATH_GATE
            client, err := BuildChannel(gate_uri, FLAG_DEBUG)
            if err != nil || client == nil {
                D(err.Error())
                T("Cannot build net channel")
            }

            if err := client.InitializeCircuit(); err != nil {
                D(err.Error())
                T("Service is not responding")
            }
        }

        return
    }

    var service *NetChannelService = nil
    if RUN_SERVER_TEST == true {
        D("Building the server processor")
        D("Starting websock service on [TCP] port: " + util.IntToString(int(CONTROLLER_PORT)))

        var err error
        service, err = CreateServer(CONTROLLER_PATH_GATE, /* /gate.php */
                                     CONTROLLER_PORT, /* 80 */
                                     FLAG_DEBUG,
                                     incomingClientHandler)
        if err != nil || service == nil {
            D(err.Error())
            T("Cannot start websock service")
        }
    }

    if RUN_CLIENT_TEST == true {
        D("Building the client transporter")

        gate_uri := "http://" + CONTROLLER_DOMAIN + CONTROLLER_PATH_GATE
        client, err := BuildChannel(gate_uri, FLAG_DEBUG)
        if err != nil || client == nil {
            D(err.Error())
            T("Cannot build net channel")
        }

        if err := client.InitializeCircuit(); err != nil {
            D(err.Error())
            T("Service is not responding")
        }

        go func (client *NetChannelClient) {
            util.SleepSeconds(20)
            util.DebugOut("Sending forced write request...")
            client.Write([]byte("test data"))
        } (client)

        util.WaitForever()
    }

    if RUN_SERVER_TEST == true {
        util.WaitForever()
    }
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
    util.DebugOut("[+] " + debug)
}

func T(debug string) {
    util.ThrowN("[!] " + debug)
}
