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
)

/************************************************************
 * websock Client objects and methods                       *
 ************************************************************/
type FlagVal int
const (
    FLAG_DO_NOT_USE     FlagVal = 1 << iota /* Flip up to 32 bits -- placeholder*/
    FLAG_DO_NOT_USE2
    FLAG_DEBUG
    FLAG_PING_SERVER
    FLAG_TEST_CIRCUIT
    FLAG_ENCRYPT
    FLAG_COMPRESS
    FLAG_DIRECTION_TO_SERVER
    FLAG_DIRECTION_TO_CLIENT
    FLAG_TERMINATE_CONNECTION
    FLAG_TEST_CONNECTION
    FLAG_CHECK_STREAM_DATA
)

type internalCommands struct {
    flags                   FlagVal
    command                 string
    comment                 string
}

/*
 * NOTE: this function is not implemented
 */
var (
    WAIT_TIMEOUT_REACHED    = util.RetErrStr("timeout reached")
    WAIT_DATA_RECEIVED      = util.RetErrStr("data received")
    WAIT_CLOSED             = util.RetErrStr("socket closed")
)

/*
 * Shared error enumerator
 */
var (
    ERROR_NONE              error = nil
    ERROR_SERVER_DOWN       = util.RetErrStr("server is down")
    ERROR_SERVER_UP         = util.RetErrStr("server is up")
    ERROR_INVALID_URI       = util.RetErrStr("invalid URI -- DNS resolve issue?")
    ERROR_TERMINATE         = util.RetErrStr("client requested a terminate command")
)

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

func (f *NetChannelService) sendDebug(s string) {
    if (f.Flags & FLAG_DEBUG) > 0 {
        util.DebugOut("[+] " + s)
    }
}

/* EOF */