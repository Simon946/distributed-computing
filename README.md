# distributed-computing
A simple C++ project to make multiple workers cooperate through a simple protocol.


The system works with one master and multiple workers. 

## Master
This is a http (maybe https in the future) server that the user can interact with using a browser. It has TCP connections with the workers to send commands. When a user interacts through the website, it selects one or multiple suitable workers and sends them commands.

## Workers
These can be different types. It gets a command from the Master, executes it and returns the result via the TCP connection.
Planned worker types:
 - Sudoku solver
 - File storage, hashing, encryption and cloud upload
 - Minecraft server
 - Searching
 - Prime factorization
 - greatest common divisor (GCD) finder

### Note
This is more of a personal project made from code snippets that I made from scratch. It may not be that useful but maybe you'll learn something interesting from it.
