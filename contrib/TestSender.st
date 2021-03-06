PackageLoader fileInPackage: 'Sockets'.

Eval [
    | msg socket datagram addr |

    addr := Sockets.SocketAddress byName: '127.0.0.1'.
    socket := Sockets.DatagramSocket local: '127.0.0.1' port: 5000.
    datagram := Sockets.Datagram new.
    datagram port: 1313.
    datagram address: addr.

    "SLTM"
    msg := #(2 0 0 1 0 0 0 0 0 0 0
             15 193 232 197 7 0 17
             128 247 248 249 250 251
             252 253 254 ) asByteArray.

    datagram data: msg.
    socket nextPut: datagram.

    "TFP"
    msg := #(2 0 0 1 0 0 0 0 0 0 0 8
             192 232 197 7 0 20 62 2) asByteArray.
    datagram data: msg.
    socket nextPut: datagram.

    "ISUP"
    msg := #(2 0 0 1 0 0 0 0 0 0 0 11
             197 232 197 7 224 3 0 23 1 1 28) asByteArray.
    datagram data: msg.
    socket nextPut: datagram.

    "TRA"
    msg := #(2 0 0 1 0 0 0 0 0 0 0 6 192 232 197 7 0 23) asByteArray.
    datagram data: msg.
    socket nextPut: datagram.

    "SST"
    msg := #(2 0 0 1 0 0 0 0 0 0 0 24 195 233 197 7 224 9 0 3 5 9 2 66 1 4 67 31 0 1 5 3 7 233 5 0 ) asByteArray.
    datagram data: msg.
    socket nextPut: datagram.
]
