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
    "fmt"
    "net/http"
    "github.com/AlexRuzin/util"
)

/*
 * Writer objects
 */
type Writer struct {
    s int
}

/************************************************************
 * netcp Server objects and methods                         *
 ************************************************************/

type NetChannelService struct {
    Port int16
    Flags int
    PathGate string
}

/* Create circuit -OR- process gate requests */
func requestHandlerGate(writer http.ResponseWriter, reader *http.Request) {
    fmt.Fprintf(writer, "Testing Testing %s", reader.URL.Path[:])
}

func CreateNetCPServer(path_gate string, port int16, flags int) (*NetChannelService, error) {
    var io_server = &NetChannelService{
        Port: port,
        Flags: flags,
        PathGate: path_gate,
    }

    go func(svc *NetChannelService) {
        http.HandleFunc(io_server.PathGate, requestHandlerGate)
        if err := http.ListenAndServe(":" + util.IntToString(int(io_server.Port)), nil); err != nil {
            util.ThrowN("panic: Faiilure in loading httpd")
        }
    } (io_server)

    return io_server, nil
}


/************************************************************
 * netcp Client objects and methods                         *
 ************************************************************/

type NetChannelClient struct {
    GateURI string
    Port int16
    Flags int
    Connected bool
}

func BuildNetCPChannel(gate_uri string, port int16, flags int) (*NetChannelClient, error) {
    var io_channel = &NetChannelClient{
        GateURI: gate_uri,
        Port: port,
        Flags: 0,
        Connected: false,
    }

    return io_channel, nil
}
