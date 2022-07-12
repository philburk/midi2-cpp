# midi2-cpp

Benchmark to compare UDP vs TCP latency.

## Compile

    cd midiping
    clang++ -std=c++14 midiping.cpp -o midiping.app

OR

    g++ -std=c++14 midiping.cpp -o midiping.app

## Run Server

    ./midiping.app

Note the port number. Find the IP address somehow. Try looking in your network settings.

You can run multiple client tests against the server.

## Run CLient

On another machine, run midiping.app and pass it the IP address and port
of the server. For example:

    ./midiping.app 10.0.0.46:12657

When you pass an address:port it will run the client.

## Options

-h - print help

-t - on both server and client for TCP. It defaults to UDP.

-l - will run midiping.app by itself with the server and client in one process using LocalHost.

-n 50 - will do 50 pings.

-q - will tell the Client to send the Server a Quit message after one test.


