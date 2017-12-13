# websock
A socket-based covert data transfer protocol that uses encrypted data over HTTP, without TLS/SSL, and therefore without the need of any self-signed certificates. The client/server negotiate a key using ECDH, which is paired with a custom RC4 cipher implementation for data transfer.

Due to the nature of the ephemeral key negotiation, it is inferred that a static signature is not possible. This makes websock ideal for discrete and secure communication.

## Synopsis
The `websock` protocol provides an API that is similar to reading or writing to POSIX or WinSock sockets, except a compliant Reader/Writer interface is used.

HTTP is the overlaying protocol from which all data is sent. The client will send a request to the server to construct a circuit. The initial stage requires key negotiation -- in specific *Elliptic Curve Diffie-Hellman* [https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman] is uesd. The public keys shared over the wire are serialized, XOR'd with a random key, and base64 encoded. The public key exchanges are done using HTTP POST parameters, which are also randomized.

Once the secret key has been generated using the ECDH key exchange, all data will be transmitted using a custom RC4 implementation [https://github.com/AlexRuzin/cryptog], which makes use of an Initialization Vector (IV), and a hardcoded value that will maintain data integrity.


## Features
1. The NIST P384 curve is used to safely and covertly negotiate a key between the controller and atom (client). Any NIST-compliant curve may be used to strengthen the key exchange challenge.
2. An ephemeral Initialization Vector (IV) was implemented in the `cryptog.RC4_*` code, so even if the same data is sent, implementing a kind of *perfect forward secrecy*.
3. The HTTP implementation uses standard headers, including normal a common `User-Agent`, and `Content-Type`, which may be configured.
4. Key negotiation uses a covert set of key/value pairs in the HTTP POST parameter. The response, as well, is xor-encoded using an ephemeral key.
5. Simple use of the Reader/Writer interfaces to read/write to the stream. 

## Server API [`NetChannelService`]

The API consists of the initialization functions along with the methods used to read/write to the streams.

### Reference of the Server Side Objects

#### [Representation of the Server Object]

This object represents the `websock` server. This object is returned once the service has been initialized using `CreateServer()`. Please note that the value of `NetChannelService.IncomingHandler` may be modified at any time, but may cause undesired behaviour.

```go
type NetChannelService struct {
    /* Handler for new clients */
    IncomingHandler func(client *NetInstance, server *NetChannelService) error /* Handler for new clients */

    /* Flags may be modified at any time */
    Flags FlagVal /* Flags may be modified at any time */

    /* Non-exported members */
    [...]
}
```

#### [Representation of the Client on the Server] 

Each client is represented by this structure by the server's `NetChannelService` object.

```go
type NetInstance struct {
    ClientIdString string /* Unique identifier that represents the client connection */

    /* Non-exported members */
    [...]
}
```

### Initialization on the server side

Creating the `websock` server is simple. It requires a TCP listener port, usually port 80. A gate path is required as well. Any kind of gate path may be used (i.e. `/gate.php`, `/newclient.php`, `/`)

The initialization method will return a service object, `NetChannelService`, which will transparently contain a vector of all connected clients. A handler method is required that will handle all new client requests, `NetChannelService.IncomingHandler`. Each new client is represented by the below `NetInstance` object.

```go
package websock

var ServerInstance *NetChannelService = nil
var err error = nil
ServerInstance, err = websock.CreateServer("/gate.php", 
                                           80, 
                                           FLAG_BLOCKING,
                                           clientHandlerFunction)
if err != nil {
    panic(err.Error())
}
```

The `clientHandlerFunction` will handle all new requests. The `NetInstance` structure will be passed in this structure, which will allow the calling application to read or write to the instance. 

```go
func incomingClientHandler(client *NetInstance, server *NetChannelService) error {
    /* Write data from the server to the client */
    client.Write([]byte("some random data"))


    /* Check if any data is available from the client, if so, then read it */
    util.SleepSeconds(25)
    if client.Len() != 0 {
        data := make([]byte, client.Len())
        client.Read(data)
        util.DebugOut(string(data))
    }
    return nil
}
``` 

### Closing the service

Closing the service requires a simple call.

```go
ServerInstance.CloseService()
```

### Closing a client connection

To close a client connection requires an invocation of a method in the `NetChannelService` object.

```go
ServerInstance.CloseClient(client *NetInstance)
```

### Client I/O from the Server-side

Writing to the stream requires a simple call to the `NetInstance.Write()` method. This complies with the io.Writer interface.

```go
func (f *NetInstance) Write(p []byte) (wrote int, err error) {
    /* Once all data is written, the success error code will be io.EOF */
    return len(p), io.EOF
}
```

Reading from the client stream requires a check for data in the stream first, using `NetInstance.Len()`, followed by a call to `NetInstance.Read()`.

```go
func (f *NetInstance) Len() int {
    /* Return the length, if any */
}

func (f *NetInstance) Read(p []byte) (read int, err error) {
    /* Once all data is read, the io.EOF code is returned */
    return len(data), io.EOF
}
```

## Client API [`NetChannelClient`]

Having the client connect requires a call to initialize the client library by calling `websock.BuildChannel()`, where the target URI is passed, in the form of `http://domain.com:7676/handler.php`. Several flags may be passed as well, which will be elaborated on further below. Note that the client will *not* connect to the server at this point. The `websock.BuildChannel()` method returns a `NetChannelClient` structure, which will implement the Read/Write functions.

```go
client, err := BuildChannel(gate_uri, FLAG_DEBUG)
if err != nil || client == nil {
    D(err.Error())
    T("Cannot build net channel")
}
```

Next, the client must connect to the server by invoking the `NetChannelClient.InitializeCircuit()` method.

```go
if err := client.InitializeCircuit(); err != nil {
    D(err.Error())
    T("Service is not responding")
}
```

### Client I/O

Reading and writing to the client socket requires the use of the Read/Write functions, which implement the standard Reader/Writer interface. The prototypes of these functions, which are members of `NetChannelClient`, are described below:

```go
/* Returns the length of the read buffer, indicating data was sent from the server to the client */
func (f *NetChannelClient) Len() int
```

```go
/* Read into p until the buffer is depleted. An io.EOF error will be returned once the buffer is depleted */
func (f *NetChannelClient) Read(p []byte) (read int, err error)
```

```go
/* Write p into the buffer. Written returns the len(p), and io.EOF is returned if there was enough space in the buffer */
func (f *NetChannelClient) Write(p []byte) (written int, err error)
```

## Protocol Configuration

All configuration to the protocol is done by editing the `protocol_config.go` file, which will contain instructions on each configurable variable.

## Credits

All design and programming done by AlexRuzin for educational and research purposes. Please distribute with the attached MIT license. Contact, if you have any questions, or fixes, at stan [dot] ruzin [at] gmail [dot] com. 