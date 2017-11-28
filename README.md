# netcp
A socket-based covert data transfer protocol that uses HTTP without TLS. All data that is transmitted uses state-of-the-art cryptography to protect data transmitted through the stream.

The goal of this project is to create a socket that transmits data that cannot have a static signature placed against it, and further will use advanced cryptographic ciphers to maintain secrecy.

## Synopsis
On the highest level, this communication protocol uses a socket driven communication to send data to and from the client to server and back, much like POSIX or WinSocks. 

Under the radar, each write to the socket is transmitted using HTTP (without TLS/SSL), through a series of parameters that are encrypted using the RC4 cipher. The RC4 implementation itself [https://github.com/AlexRuzin/cryptog], uses an ephemeral IV to maintain a covert channel.

During the initialization stage, `netcp` makes use of Elliptic-curve Diffie-Hellman [https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman] to negotiate a secret key. This process itself uses xor/shift and base64 encoding, to prevent a regex against the serializer.

## Features
1. The NIST P384 curve is used to safely and covertly negotiate a key between the controller and atom (client)
2. An ephemeral Initialization Vector (IV) was implemented in the `cryptog.RC4_*` code, so even if the same data is sent, a completely different encoding will be shown.
3. The HTTP implementation uses standard headers, including normal a common `User-Agent`, and `Content-Type`.
4. Key negotiation uses a covert set of key/value pairs in the HTTP POST parameter. The response, as well, is xor-encoded using an ephemeral key.
5. Simple use of the Reader/Writer interfaces to read/write to the socket

## Controller API [`NetChannelService`]

The API consists of the initialization functions along with the methods used to read/write to the streams.

### Reference of the Server Side Objects

#### Representation of the Server Object

This object represents the `netcp` server. 

```go
type NetChannelService struct {
    Port int16                             // Listener port
    Flags int                              // Any flags (see flags section)
    PathGate string                        // Gateway URI
    ClientMap map[string]*NetInstance      // Mapping between client objects to client IDs
    ClientIO chan *NetInstance             // Channel that will receive new client connections
    ClientSync sync.Mutex                  // Synchronization object that is invoked during I/O operations
}
```

#### Representation of the Client on the Server 

Each client is represented by this structure by the server's `NetChannelService` object.

```go
type NetInstance struct {
    Secret []byte                          // The shared secret after ECDH negotiation
    ClientId []byte                        // Unique client ID
    ClientIdString string                  // Same as above, but in string format
    ClientData [][]byte                    // Contains an array of data waiting to be read/sent by/to the client
}
```

### Initialization on the server side

Creating the `netcp` server is simple. It requires a TCP listener port, usually port 80. A gate URI is required as well.

Lastly, flags must be set to indicate whether or not the I/O methods will be blocking or non-blocking.

The initialization method will return a service object, from which reading and writing will be possible. A handler method is required that will handle all new client requests. Each new client is represented by the `NetInstance` object.

```go
package netcp

var ServerInstance *NetChannelService = nil
var err error = nil
ServerInstance, err = netcp.CreateNetCpServer("/gate.php", 80, FLAG_BLOCKING)
if err != nil {
    panic(err.Error())
}
```

### Setting the `NetInstance` handler

This callback will handle events in which a new client has connected and established an encrypted connection with the controller.
```go
//TODO
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

### Write to the stream

Writing to the stream requires a simple call to the `NetInstance.WriteStream()` method.

```go
data_sent, err := ServerInstance.WriteStream(data []byte, client *NetInstance)
if err != nil || len(data) != data_sent {
    panic(errors.New("Failed to write to the stream"))
}
```