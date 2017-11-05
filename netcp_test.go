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
    "github.com/AlexRuzin/util"
    "testing"
)

/* Test configuration */
const RUN_CLIENT_TEST                bool = false

/* Configuration */
const CONTROLLER_DOMAIN              string = "127.0.0.1"
const CONTROLLER_PATH                string = "/gate.php"
const CONTROLLER_PORT                int16 = 80

func TestMainChannel(t *testing.T) {
    /*
     * Create the channel listener
     */
    D("Building the server processor")
    D("Starting netcp service on [TCP] port: " + string(CONTROLLER_PORT))
    service, err := CreateNetCPServer(   CONTROLLER_PATH, /* /gate.php */
                                         CONTROLLER_PORT, /* 80 */
                                         0)
    if err != nil || service == nil {
        D(err.Error())
        T("Cannot start netcp service")
    }

    if RUN_CLIENT_TEST == true {
        /*
         * Generate the client connection
         */
        D("Building the client transporter")

        var URI= "http://" + CONTROLLER_DOMAIN + CONTROLLER_PATH
        D("Connecting to: " + URI + " on port: " + string(CONTROLLER_PORT))
        client, err := BuildNetCPChannel(URI, CONTROLLER_PORT, 0)
        if err != nil || client == nil {
            D(err.Error())
            T("Cannot build net channel")
        }
    }
}

func D(debug string) {
    util.DebugOut("[+] " + debug)
}

func T(debug string) {
    util.ThrowN("[!] " + debug)
}