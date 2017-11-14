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

/*
 * This is the POST parameter name of our main ECDH public key
 *  coming in from the client side
 */
const POST_PARAM_NAME = "q"

/*
 * The length of the POST parameter values. If -1, the sizes
 *  will approximate the length of the transmit pool
 */
const POST_BODY_VALUE_LEN = -1

/*
 * The length of the parameter name (key(
 */
const POST_BODY_KEY_LEN = 8

/*
 * The number of garbage parameters. Our useful information
 *  will be in there somewhere. Minimum should be 3 due to
 *  the constraints of code logic
 */
const POST_BODY_JUNK_MAX_PARAMETERS = 8
