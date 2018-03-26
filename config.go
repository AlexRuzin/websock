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
    "encoding/json"
    "encoding/base32"
)

/*
 * The object representing the internal config
 */
var masterConfig *ProtocolConfig

/*
*
* The default configuration file is base32 encrypted, and stored in a buffer here.
*  To modify the config, decode the config, edit it, and encode it again
*
* {
*   "MagicPortal":"127.0.0.1,127.0.0.1,google.com,127.0.0.2",
*
*   "post_body_key_charset": "aielndqor",
*
*   "c2_response_timeout": 10,
*
*   "post_body_value_length": -1,
*
*   "post_body_key_length": 1,
*
*   "post_body_junk_length": 16,
*   "post_body_junk_length_offset": 8,
*
*   "UAgen": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
*
*   "CType": "text/plain",
*
*   "HTVerb": "POST",
*   "randomize_http_verb": true,
*
*   "cmd_check_stream": "Knocking on Heaven's door",
*   "cmd_test_connection": "I'm trying to test the connecting",
*   "cmd_terminate_connection": "Peace the fuck out".
* }
*/

type ProtocolConfig struct {
    /* Default location of the json file */
    configLocation      string

    /*
     * Gateways are encoded like:
     *  "domain,ip,domain,ip", etc....
     *  The default is "127.0.0.1,127.0.0.1,google.com,127.0.0.2"
     *  IMPORTANT_NOTE: this is not used, i.e. the gateway addresses
     *  are provided by the calling program, and not within the
     *  library itself.
     */
    defaultGateways     string      `json:"MagicPortal"`

    /*
     * The keyset used as the "actual" parameter containing sensitive data. This is
     *  required fot the application to verify that the connection is indeed a
     *  websock request. The original is: "aielndqor"
     */
    PostBodyKeyCharset  string      `json:"post_body_key_charset"`

    /*
     * Default timeout before the server closes the connection if no request has
     *  been received. In seconds
     */
    C2ResponseTimeout   uint16      `json:"c2_response_timeout"`

    /*
     *
     */
    PostBodyValueLength int         `json:"post_body_value_length"`
    PostBodyKeyLength   int         `json:"post_body_key_length"`

    /*
     * The length of the POST request parameter names
     */
    PostBodyJunkLen     uint16      `json:"post_body_junk_length"`
    PostBodyJunkLenOff  uint16      `json:"post_body_junk_length_offset"`

    /*
     * The default User-Agent HTTP header value. The most common User-Agent
     *  was used by default. The user-agent is Base32 encoded
     *  the original being: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
    *   (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"
     */
    UserAgent           string      `json:"UAgen"`

    /*
     * The default content type. The user-agent is Base32 encoded, the
     *  original is "text/plain".
     */
    ContentType         string      `json:"CType"`

    /*
     * The default HTTP request (should be POST). The randomize value
     *  is experimental and not used, NOR SHOULD BE SET TO TRUE
     */
    HTTPVerb            string      `json:"HTVerb"`
    RandomizeHTTPVerb   bool        `json:"randomize_http_verb"`

    /*
     * The default commands are listed below. The first is used by the
     *  method testCircuit() to verify the PKE subsystem. base32 encoded
     */
    TestStream          string      `json:"CMD1"`

    /*
     * This command asks the server for any data to be read. B32 encoded
     */
    CheckStream         string      `json:"CMD2"`

    /*
     * Client/Server terminate the connection. B32 encoded string
     */
    TermConnect         string      `json:"CMD3"`
}

/*
 * This method modifies the masterConfig global variable, instantiating the
 *  protocolConfig structure
 */
func ParseConfig() (error) {
    rawJSON, err := base32.StdEncoding.DecodeString(MAIN_CONFIG_B32_ENCODED)
    if err != nil {
        return err
    }

    if err = json.Unmarshal(rawJSON, masterConfig); err != nil {
        return err
    }

    return nil
}

/*
 * Base32 encoded json file
 */
const MAIN_CONFIG_B32_ENCODED = "18g208jdc5kpjrugdxt78rbc48x24dhmegtpark8cwuq4whjexhkjrtp6hu36tb2d1kkawkj69vp6eb3cdw72w3tehv66rvde4v3cxkpcgupewkb6hj78t9p61rk6c32d1n24b0a18g208kgdxtq8qv2dxj7jqvbcnwnyrv8c5t76tbm48x208k36npq0rbp6djp6u3je1wqett25g52080a40g24rtjbxt6awvgdxq76tazehmputbfenu24eh064r2r2h040520812e1qq6x2zc9qp8yazetgprxb5bxp6avk7ehm24eh05mrjr2h040520812e1qq6x2zc9qp8yazddjqjqvccnq6ex3848x20c9c18g202h040h70vvkehfp4vv4f5fpmxbeddfprtbecxu6g8hu40rkcb0a40g24w3fedu5yrkfchwnyukndtnnyv35dtkq8u2zdxk6cwv5egh3m81r5g5202h040h5agb7cnq24eh048wpwwbhdnup4rv4d1kpmyb475jkcc3769kpwxhtchu6mdktf1v6pd1h6wukge1hd0v30w9k61jq8c31f1pq0xv4d1pkerv76xkp8u3d6mu6ed1jewtpet38d9q6ax3268wp8vbh71h78vhpcdv6mxv3ehr38c3d6hr6mckd75q3cckj70tp6t1ndtr62e1j6xhpwu3ge1v78e9m64rq0tvqddk68vkad9wp8u386nt74ckqcdu6gdkjehn7erttcwv30ttn6tt64dk36nu3cuk2ehq3crvpd9vp6x3g48p0m81018g208j3ahwq0t9278g24tb8d9rpey1hctjk2w1p69up4t925g52080a40g24j2matjq4rh278g24m2fada24b0a40g24wk1dtj6yvb9f9jnyu3mehr5yxk5e9h24eh0eht7at9c18g202h040h66vb4bxhpgtb3ddfq6x3jcngpuqvpd5j6avt278g24rv4e1r3gwbpdnhpwx3h71rqccv4f1rkcxvmc8tpau3de1wqctt25g520812cdpp8qvmcntq8qv3dxq6wtb3ehmpyvh278g24tbrd9r38xvpcthp8vka61t7crv46nn70xvr64r68dbmd8r7gcvacrupuw3qehu30tb8e5n30y1k75hp8vkge9u3jc366nrq2rbqd0r66x37e1vq4xkm48p0m81049hput2zehjq4vb9dtgq8tazcdqpwvk5cdu6jvve48x208k3chr70e3hetpp6vkm6tuqark5ccuqadk1e5v36t3re4v7ex326djpgvbgf5v6e8he19yg"

/* EOF */