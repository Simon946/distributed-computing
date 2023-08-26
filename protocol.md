# Communication protocol for the distributed computing software. Version 2

## Master
The master connects via 1 TCP IPv4 connection to 1 Worker. The address and port are provided by the user. There can be multiple connections per Master. The master manages which connections can do which things.

## Worker
The worker waits on the master to make a connection.

## Protocol
Communication will be with HTTP. Requests and responses are formatted depending on the service. For instance base64 and json.




























