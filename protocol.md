# Communication protocol for the distributed computing software. Version 1

## Master
The master connects via 1 TCP IPv4 connection to 1 Worker. The address and port are provided by the user. There can be multiple connections per Master.

## Worker
The worker waits on the master to make a connection.

## Syntax
Requests and Responses are formatted in the following way:
 - Only ASCII characters
 - Starts with a 3 digit `Status code`
 - Optionally a text message
 - Each line ends with a carriage return and newline character.
 - The second and following lines are the `Additional info`
 - The length can never exceed 4096 bytes.

## Requests

| Status code   | Optional message      | Additional info	| Sent by | Description |
|---------------|-----------------------|-----------------|---------|-------------|
| 700		| Who are you?		| WorkerType: <string>  | Master  | First message that the Master sends after a connection is made. There can be multiple `WorkerType`s |
| 701		| Goodbye		| none			| Worker & Master | If sent by Master: abort current work, end connection and stop. If sent by Worker: close connection and do not reconnect |
| 800		| Go to work		| WorkerType: <string> and Task: <string> and Size: <int> | Master | Sends a job to the Worker. The `Task` is dependent on the `WorkerType`. For long or more complicated requests, the task can refer to the additional data, which can be any datatype. The `Size` is the size of the additional data. |

## Responses

| Status code   | Optional message      | Additional info	| Sent by | Description | 
|---------------|-----------------------|-----------------------|---------|--------------|
| 100 		| Continue		| MaxSize: <int> and Id: <string> | Worker | The worker is ready to receive additional data, such as input files. Can be used in sequence for large sizes. The `Id` specifies which data it expects |
| 101		| I'm a			| WorkerType: <string>  | Worker  	  | The worker identifies its type and capabilities. Note: A single TCP connection can be connected to multiple types. The `WorkerType` s are on separate lines | 
| 200		| OK			| none			| Worker & Master | The action is performed successfully. There is no return value |
| 201   | Done    | Size: <int> and Id: <string> | Worker | The action is performed successfully. The return value has a size of `Size` and can be identified by its `Id` |
| 400		| Invalid syntax	| none			| Worker & Master | This request is not recognized. Note: the request can be valid but unsupported |
| 401		| Unauthorized		| none			| Worker 	  | This action cannot be performed unless a login is provided |
| 404		| Not found		| none			| Worker 	  | The resource is currently unavailable. |
| 413 		| Payload too large     | MaxSize: <int>	| Worker & Master | The data such as input or output files is too large |
| 418		| I'm a teapot		| none			| Teapot  	  | https://en.wikipedia.org/wiki/Hyper_Text_Coffee_Pot_Control_Protocol
| 422		| Unprocessable Entity  | none			| Worker  	  | The additional data could not be processed. Send better data to try again, or a different command to abort |
| 500		| Internal server error | none			| Worker  	  | There has been some error. Same as 200 except the operation has been aborted. |
| 503		| Service Unavailable   | none			| Worker 	  | The worker temporarily lacks resources, for example be too busy, out of memory or out of storage |




## Example

Master `700 Who are you\r\n WorkerType: GCDcalculator\r\n WorkerType: fileStorage\r\n WorkerType: fileHashing\r\n`
The Master is looking for a Worker that can do GCD, fileStorage, or fileHashing.

Worker `101 I'm a\r\n WorkerType: fileStorage\r\n WorkerType: fileHashing\r\n`
The worker can do fileStorage and fileHashing. A different response could be: `400` if no `WorkerType`s match the implemented `WorkerType`s with the requested `WorkerType`s.

Master `800 Go to work\r\n WorkerType: fileStorage\r\n Task: CREATE "my file.txt"\r\n Size: 63126\r\n`
The Master wants to upload a file: my file.txt of 63126 bytes to the Worker. The syntax of `CREATE` is dependent on the `WorkerType` and unspecified here.

Worker `413 Payload too large\r\n MaxSize: 8192\r\n`
The Worker can only accept additional data in chunks of 8192 bytes.

Master `800 Go to work\r\n WorkerType: fileStorage\r\n Task: CREATE "my file.txt"\r\n Size: 8192\r\n`
The Master tries again by this time only sending the first 8192 bytes of the file.

Worker `100 Continue\r\n MaxSize: 8192\r\n Id: 0\r\n`
The Worker is ready to accept 8192 bytes. The `Id` is unused here but can be used by other `WorkerType`s to tell the Master which data is needed.

Master `...` 
The Master sends the first 8192 bytes of the file: "my file.txt".

Worker `100 Continue\r\n MaxSize: 8192\r\n Id: 0\r\n`
The Worker is ready to accept the next 8192 bytes.

Master `...` 
The Master sends the next 8192 bytes of the file: "my file.txt".

This continues until the entire file is transmitted.
...

Worker `200 OK\r\n`
When the last bytes are sent, the Worker tells the Master that the operation has been completed succesfully.

Master `701 Goodbye\r\n`
The Master closes the connection and the Worker stops listening for new connecting Masters. The Worker program quits.



































