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

/*
 * Any of these characters in the charset may be a the key
 *  for the client's public key exchange. Increasing the length of the
 *  character set will require the IDS to write a signature for each
 *  possible variation. Therefore, this characterset should be custom
 *  for each implementation, to make the negotiation (PKE) communication
 *  more varied. The performance cost on this is trivial. Note: each
 *  character in this array should be unique.
 */
const POST_BODY_KEY_CHARSET         = "aielndqor"

/*
 * For each data request sent by the client, the server must wait
 *  wait n seconds before it sends back a 200 OK (i.e. no data to
 *  be transmitted). Otherwise, if during this time data is sent,
 *  then the loop is broken and the data buffer is transmitted.
 *
 * The below value is how many iterations/checks are required before
 *  sending a 200 OK. The value is in seconds
 */
const CONTROLLER_RESPONSE_TIMEOUT   = 10

/*
 * The length of the POST parameter values. If -1, the sizes
 *  will approximate the length of the transmit pool
 */
const POST_BODY_VALUE_LEN           = -1

/*
 * The length of the parameter name
 */
const POST_BODY_KEY_LEN             = 8

/*
 * The number of garbage parameters. Our useful information
 *  will be in there somewhere. Minimum should be 3 due to
 *  the constraints of code logic
 */
const POST_BODY_JUNK_MAX_PARAMETERS = 8

/*
 * User-Agent for the HTTP client
 */
const HTTP_USER_AGENT               = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"

/*
 * The standard Content-Type for the client
 */
const HTTP_CONTENT_TYPE             = "application/x-www-form-urlencoded"

/*
 * GET or POST verb when constructing circuit with HTTPd
 */
const HTTP_VERB                     = "POST"

/*
 * Constants beyond this point -- do not change these values
 */
const (
    CHECK_STREAM_DATA               = "check stream data"
    TEST_CONNECTION_DATA            = "test connection data"
    TERMINATE_CONNECTION_DATA       = "terminate connection"
)

/* EOF */
