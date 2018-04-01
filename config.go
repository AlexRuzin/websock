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
 *
 * The default configuration file is base32 encrypted, and stored in a buffer here.
 *  To modify the config, decode the config, edit it, and encode it again
 *
 * {
 *     "MagicPortal": "127.0.0.1,127.0.0.1,google.com,127.0.0.2",
 *
 *     "post_body_key_charset": "aielndqor",
 *
 *     "c2_response_timeout": 100,
 *
 *     "post_body_value_length": -1,
 *     "post_body_key_length": 1,
 *
 *     "post_body_junk_length": 16,
 *     "post_body_junk_length_offset": 8,
 *
 *     "UAgen": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
 *
 *     "CType": "text/plain",
 *
 *     "HTVerb": "POST",
 *     "randomize_http_verb": true,
 *
 *     "CMD1": "Knocking on Heaven's door",
 *     "CMD2": "I'm trying to test the connecting",
 *     "CMD3": "Peace the fuck out"
 * }
 */

type ProtocolConfig struct {
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

    /* Something to do with generating a false public key request parameters */
    PostBodyValueLength int         `json:"post_body_value_length"`
    PostBodyKeyLength   int         `json:"post_body_key_length"`

    /*
     * The length of the POST request parameter names, the values are 16, 8
     */
    PostBodyJunkLen     int         `json:"post_body_junk_length"`
    PostBodyJunkLenOff  int         `json:"post_body_junk_length_offset"`

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
func parseConfig() (*ProtocolConfig, error) {
    rawJSON, err := base32.StdEncoding.DecodeString(MAIN_CONFIG_B32_ENCODED)
    if err != nil {
        return nil, err
    }

    var masterConfig ProtocolConfig
    if err := json.Unmarshal(rawJSON, &masterConfig); err != nil {
        return nil, err
    }

    return &masterConfig, nil
}

/*
 * Base32 encoded json file
 */
const MAIN_CONFIG_B32_ENCODED = "PMFCAIBCOBXXG5C7MJXWI6K7NNSXSX3DNBQXE43FOQRDUIBCMFUWK3DOMRYW64RCFQFAUIBAEJRTEX3SMVZXA33OONSV65DJNVSW65LUEI5CAMJQFQFAUIBAEJYG643UL5RG6ZDZL53GC3DVMVPWYZLOM52GQIR2EAWTCLAKEAQCE4DPON2F6YTPMR4V623FPFPWYZLOM52GQIR2EA4CYCQKEAQCE4DPON2F6YTPMR4V62TVNZVV63DFNZTXI2BCHIQDCNRMBIQCAITQN5ZXIX3CN5SHSX3KOVXGWX3MMVXGO5DIL5XWMZTTMV2CEORAHAWAUCRAEARFKQLHMVXCEORAEJGW66TJNRWGCLZVFYYCAKCXNFXGI33XOMQE4VBAGEYC4MB3EBLWS3RWGQ5SA6BWGQUSAQLQOBWGKV3FMJFWS5BPGUZTOLRTGYQCQS2IKRGUYLBANRUWWZJAI5SWG23PFEQEG2DSN5WWKLZWGEXDALRTGE3DGLRRGAYCAU3BMZQXE2JPGUZTOLRTGYRCYCQKEAQCEQ2UPFYGKIR2EARGC4DQNRUWGYLUNFXW4L3YFV3XO5ZNMZXXE3JNOVZGYZLOMNXWIZLEEIWAUCRAEAREQVCWMVZGEIR2EARFAT2TKQRCYCRAEARHEYLOMRXW22L2MVPWQ5DUOBPXMZLSMIRDUIDUOJ2WKLAKBIQCAISDJVCDCIR2EAREW3TPMNVWS3THEBXW4ICIMVQXMZLOE5ZSAZDPN5ZCELAKEAQCEQ2NIQZCEORAEJ2GK43UNFXGOIDDN5XG4ZLDORUW63ROFYXCELAKEAQCEQ2NIQZSEORAEJ3WKYTTN5RWWIDDNRXXG2LOM4RAU7I="

/* EOF */