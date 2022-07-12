/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Measure ping time  for UDP or TCP packets across the network.
 *
 * See README.md for instructions.
 *
 * Created by Phil Burk on 7/7/22.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#else
#include <sys/sysinfo.h>
#endif

#define APP_VERSION  "0.1.1"
#define MSG_PING "ping"
#define MSG_ECHO "echo"
#define MSG_QUIT "quit"
#define ADDRESS_LOOPBACK "127.0.0.1"
#define MAX_MESSAGE_SIZE  8

// Set to 1 for verbose debugging. May affect timing.
#define RTDEBUG  0

/**
 * @return system time in nanoseconds, CLOCK_MONOTONIC
 */
#if defined(__APPLE__)
static int64_t getNanoTime() {
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    return (int64_t)(mach_absolute_time() * info.numer / info.denom);
}

#else
static const int64_t kNanosPerSecond = 1000 * 1000 * 1000;
static int64_t getNanoTime() {
    struct timespec res;
    int result = clock_gettime(CLOCK_MONOTONIC, &res);
    if (result < 0) {
        return result;
    }
    return (res.tv_sec * kNanosPerSecond) + res.tv_nsec;
}
#endif

/* ====================================================================== */
/* ====================================================================== */
/* ====================================================================== */
/**
 * Base class for sending discrete "packets" across the network.
 */
class NetworkSocketBase {
public:
    NetworkSocketBase() {}
    
    virtual ~NetworkSocketBase()  = default;
    
    virtual int createSocket() = 0;
    virtual int receiveMessage(void *data, size_t len) = 0;
    virtual int sendReply(const void *data, size_t len) = 0;
    virtual int sendToRemoteAddress(const void *data, size_t len) = 0;
    
    /**
     * Set a remote address for sending
     * @param remoteAddressPort  a string of the form {address}:{port}, for example  "127.0.0.1:12345"
     */
    int setRemoteAddress(const char *remoteAddressPort) {
        std::string text(remoteAddressPort);
        std::size_t colonAt = text.find_first_of(":");
        if (colonAt == std::string::npos) {
            std::cerr << "Missing ':' in " << text << std::endl;
            return -1;
        }
        std::string remoteAddress = text.substr(0, colonAt);
        std::string remotePort = text.substr(colonAt + 1);
        std::cout << "remote address = " << remoteAddress << ", port = " << remotePort << std::endl;

        struct addrinfo myInfo;
        memset(&myInfo,0,sizeof(myInfo));
        myInfo.ai_family=AF_INET;
        myInfo.ai_socktype=SOCK_DGRAM;
        myInfo.ai_protocol=0;
        myInfo.ai_flags=AI_ADDRCONFIG;
        
        int err = getaddrinfo(remoteAddress.c_str(),
                            remotePort.c_str(),
                            &myInfo,
                            &mRemoteAddressInfo);
        if (err!=0) {
            std::cerr << "Cannot resolve address, err = " << err << std::endl;
        }
        return err;
    }
    
    /**
     * Setup a socket and bind it to a local address.
     */
    int setupSocket(int port) {
        int err;
        
        err = createSocket();
        if (err) return err;
        
        struct sockaddr_in sin;
        memset((char *) &sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        sin.sin_addr.s_addr = INADDR_ANY;
        
        err = bind(mSocketFD, (struct sockaddr *) &sin, sizeof(sin));
        if (err == -1) {
            std::cerr << "setupListener(): bind() failed, errno = " << errno << ", " << strerror(errno) << std::endl;
            return -errno;
        }

        socklen_t len = sizeof(sin);
        if (getsockname(mSocketFD, (struct sockaddr *)&sin, &len) == -1) {
            std::cerr << "setupListener(): getsockname() failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        // std::cout << "socket address = " << inet_ntoa(sin.sin_addr) << std::endl;
        mLocalPort = ntohs(sin.sin_port);
            
        return 0;
    }
    
    int connectToRemoteAddress() {
        if (connect(mSocketFD,
                    mRemoteAddressInfo->ai_addr,
                    mRemoteAddressInfo->ai_addrlen) < 0) {
            std::cerr << "connect() failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        mConnected = true;
        return 0;
    }
    
    int getLocalPort() {
        return mLocalPort;
    }
    
    /**
     * Do whatever is necessary to act as a ping server.
     */
    virtual int setupServer() {
        return 0;
    }
    
    /**
     * @ return socket used for sending and receiving packets
     */
    virtual int getCommunicationSocket() const {
        return mSocketFD;
    }
    
protected:
    struct addrinfo* mRemoteAddressInfo = nullptr;
    
    struct sockaddr_storage mSourceAddress;
    socklen_t mSourceAddressLength = sizeof(mSourceAddress);
    
    int mSocketFD = -1; // for listening to incoming TCP connections, or sending UDP packets
#if 0
    // Requires C++14
    std::atomic<int> mLocalPort{0};
#else
    volatile int mLocalPort = 0;
#endif

    bool mConnected = false;
};

/* ====================================================================== */
/* ====================================================================== */
/* ====================================================================== */
/**
 * Send and receive messages over TCP.
 * TCP is a byte stream so we have to provide packet framing for messages.
 * A message consists of:
 *      uint8_t sync  = 0x5A
 *      uint8_t size
 *      char [...] payload
 *
 *   Note that this is not a MIDI standard. But it is similar to what a MIDI/TCP transport might do.
 */
class NetworkSocketTCP : public NetworkSocketBase {
public:
    
    ~NetworkSocketTCP() = default;
    
    int createSocket() override {
        std::cerr << "Create TCP socket." << std::endl;
        mSocketFD = socket(AF_INET, SOCK_STREAM, 0);
        if (mSocketFD==-1) {
            std::cerr << "Cannot create TCP socket, err = " << strerror(errno) << std::endl;
            return -errno;
        }
        int flag = 1;
        int result = setsockopt(mSocketFD,       /* socket affected */
                                IPPROTO_TCP,     /* set option at TCP level */
                                TCP_NODELAY,     /* name of option */
                                (char *) &flag,
                                sizeof(flag));
        if (result < 0)  {
            std::cerr << "Cannot create set TCP_NODELAY, err = " << strerror(errno) << std::endl;
            return -errno;
        }
        return 0;
    }
    
    int setupServer() override {
        const int backlog = 5;
        int err = listen(mSocketFD, backlog);
        if (err < 0) {
            std::cerr << "listen failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        
        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        mConnectionFD = accept(mSocketFD,
                               (struct sockaddr *) &sin,
                               &len);
        if (mConnectionFD < 0) {
            std::cerr << "accept failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        
        return err;
    }
        
    int receiveMessage(void *data, size_t len) override {
        uint8_t header[2];
        ssize_t bytesLeft = sizeof(header);
        uint8_t *input = &header[0];
        while (bytesLeft > 0) {
            ssize_t count = read(getCommunicationSocket(), input, bytesLeft);
            if (count < 0) {
                std::cerr << "TCP error receiveMessage(), count " << count << std::endl;
                return (int) count;
            } else if (count == 0) {
                std::cerr << "TCP client disconnected"<< std::endl;
                return 0;
            }
            // std::cerr << "TCP receiveMessage() header, count " << count << std::endl;
            bytesLeft -= count;
            input += count;;
        }
        
        if (header[0] != kSync) {
            std::cerr << "TCP framing error in receiveMessage(), expected " << std::to_string(kSync)
                    << ", got " << std::to_string(header[0]) << std::endl;
            return -2;
        }
        int messageSize = header[1];
        if (messageSize > len) {
                std::cerr << "TCP overflow in receiveMessage(), messageSize = " << messageSize
                        << " > " << len << std::endl;
                return -3;
        }
        // Read payload.
        bytesLeft = messageSize;
        input = (uint8_t *) data;
        while (bytesLeft > 0) {
            ssize_t count = read(getCommunicationSocket(), input, bytesLeft);
            if (count < 0) {
                std::cerr << "TCP error reading payload in receiveMessage() = " << count << std::endl;
                return (int) count;
            } else if (count == 0) {
                std::cerr << "TCP client disconnected"<< std::endl;
                return 0;
            }
            // std::cerr << "TCP receiveMessage() payload, count " << count << std::endl;
            bytesLeft -= count;
            input += count;;
        }
        return (int) messageSize;
    }

    /**
     * Send reply through the connection socket.
     */
    int sendReply(const void *data, size_t len) override {
        return sendToRemoteAddress(data, len);
    }

    int sendToRemoteAddress(const void *data, size_t len) override {
        uint8_t buffer[MAX_MESSAGE_SIZE + 2] = { kSync, (uint8_t)len };
        memcpy(&buffer[2], data, len);
        ssize_t count = write(getCommunicationSocket(), buffer, len + 2);
        if (count < 0) {
            std::cerr << "TCP write() failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        return (int) count;
    }
    
    int getCommunicationSocket() const override {
        return (mConnectionFD >= 0) ? mConnectionFD : mSocketFD;
    }
    
private:
    int mConnectionFD = -1;
    static constexpr uint8_t kSync = 0x5A;
};

/* ====================================================================== */
/* ====================================================================== */
/* ====================================================================== */
class NetworkSocketUDP : public NetworkSocketBase {
public:
    
    ~NetworkSocketUDP() = default;
    
    int createSocket() override {
        std::cerr << "Create UDP socket." << std::endl;
        mSocketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (mSocketFD==-1) {
            std::cerr << "Cannot create UDP socket, err = " << strerror(errno) << std::endl;
            return -errno;
        }
        return 0;
    }
    
//    void close() {
//        if (mSocketFD != -1) {
//            fclose(mSocketFD);
//        }
//        freeaddrinfo(mRemoteAddressInfo);
//    }
        
    int receiveMessage(void *data, size_t len) override {
        mSourceAddressLength = sizeof(mSourceAddress);
        ssize_t count = recvfrom(mSocketFD,
                                 data,
                                 len,
                                 0,
                                 (struct sockaddr*)&mSourceAddress,
                                 &mSourceAddressLength);
        if (count < 0) {
            std::cerr << "UDP error in recvfrom() = " << count << std::endl;
        }
        return (int) count;
    }

    /**
     * Send reply to whatever address the last message was received from.
     */
    int sendReply(const void *data, size_t len) override {
        ssize_t count = sendto(mSocketFD, data, len,
                0,
                (struct sockaddr *) &mSourceAddress,
                mSourceAddressLength);
        
        if (count < 0) {
            std::cerr << "sendReply() failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        return (int) count;
    }

    int sendToRemoteAddress(const void *data, size_t len) override {
        ssize_t count;
        if (mConnected) {
            count = sendto(mSocketFD, data, len, 0, NULL, 0);
        } else {
            count = sendto(mSocketFD, data, len, 0,
                             mRemoteAddressInfo->ai_addr,
                             mRemoteAddressInfo->ai_addrlen);
        }
        if (count == -1) {
            std::cerr << "sendToRemoteAddress() failed, errno = " << strerror(errno) << std::endl;
            return -errno;
        }
        
    #if RTDEBUG
        std::cout << "sent message length = " << count << std::endl;
    #endif
        return (int) count;
    }
    
};

struct TestParams {
    const char *remoteAddressPort = nullptr;
    int numPings = 100;
    bool localMode = false;
    bool useTCP = false;
    bool sendQuit = false;
    
    NetworkSocketBase * buildNetworkSocket() {
        if (useTCP) {
            return (NetworkSocketBase *) new NetworkSocketTCP ();
        } else {
            return (NetworkSocketBase *) new NetworkSocketUDP ();
        }
    }
};

/* ====================================================================== */
/* ====================================================================== */
/* ====================================================================== */
class NetworkBenchmarkServer
{
public:
    
    int getLocalPort() {
        return mNetWorkSocket->getLocalPort();
    }
    
    /**
     * @return negative error,  0 when client disconnects, or message size
     */
    int handleMessage() {
#if RTDEBUG
        std::cout << "handleMessage() called" << std::endl;
#endif
        char buffer[MAX_MESSAGE_SIZE + 1];
        int count = mNetWorkSocket->receiveMessage(buffer, sizeof(buffer) + 1);
#if RTDEBUG
        std::cout << "receiveMessage() returned " << count << std::endl;
#endif
        if (count > MAX_MESSAGE_SIZE) {
            std::cerr << "datagram too large" << std::endl;
            return -1;
        } else if (count > 0) {
            if (strcmp(buffer, MSG_PING) == 0) {
#if RTDEBUG
                std::cout << "got ping" << std::endl;
#endif
                // Send back a reply.
                const char response[] = MSG_ECHO;
                int err = mNetWorkSocket->sendReply(&response[0], sizeof(response));
                                     
                if (err == -1) {
                    std::cerr << "sendToRemoteAddress() failed, errno = " << strerror(errno) << std::endl;
                    return -1;
                }
#if RTDEBUG
                std::cout << "sent echo" << std::endl;
#endif
            } else if (strcmp(buffer, MSG_QUIT) == 0) {
                std::cout << "got MSG_QUIT" << std::endl;
                return -2;
            }
        }
        return (int) count;
    }
        
    /**
     * Run a server in a loop.
     */
    int run(struct TestParams *testParams) {
        mNetWorkSocket = testParams->buildNetworkSocket();
        
        std::cout << std::endl << "SERVER started" << std::endl;
        
        int err = mNetWorkSocket->setupSocket(0);
        if (err) {
            std::cout << "connect returned " << err << std::endl;
            return err;
        }
        
        while (err >= 0) {
            // Print port for the client.
            std::cout << "server.port = " << mNetWorkSocket->getLocalPort() << std::endl;
            
            err = mNetWorkSocket->setupServer();
            if (err) {
                std::cout << "setupServer() returned " << err << std::endl;
                return err;
            }
            
            std::cout << "Server ready for messages." << std::endl;
            while (true) {
                int count = handleMessage();
                if (count < 0 ) {
                    err = count;
                    break;
                } else if (count == 0) {
                    std::cout << std::endl << "Server waiting for new client." << std::endl;
                    break;
                }
            }
        }
        
    //    responder.close();
        
        std::cout << "Server finished." << std::endl;
        return 0;
    }
    
private:
    NetworkSocketBase *mNetWorkSocket;
};


class NetworkBenchmarkClient
{
public:
    
    /**
     * @return average duration of the round trip ping in milliseconds
     */
    double getAveragePingDuration() {
        return (mPingDurationCount == 0) ? -1.0 : mPingDurationSum / mPingDurationCount;
    }

    /**
     * @return maximum duration of the round trip ping in milliseconds
     */
    double getMaximumPingDuration() {
        return mPingDurationMax;
    }

    /**
     * @return minimum duration of the round trip ping in milliseconds
     */
    double getMinimumPingDuration() {
        return mPingDurationMin;
    }
    
    int sendPing() {
        mPingTime = getNanoTime();
        const char data[] = { MSG_PING };
        return mNetWorkSocket->sendToRemoteAddress(&data[0], sizeof(data));
    }
    
    int sendQuit() {
        std::cout << "send MSG_QUIT" << std::endl;
        const char data[] = { MSG_QUIT };
        return mNetWorkSocket->sendToRemoteAddress(&data[0], sizeof(data));
    }
    
    int handleMessage(bool discard) {
#if RTDEBUG
        std::cout << "handleMessage() called" << std::endl;
#endif
        char buffer[MAX_MESSAGE_SIZE + 1];
        int count = mNetWorkSocket->receiveMessage(buffer, sizeof(buffer) + 1);
#if RTDEBUG
        std::cout << "receiveMessage() returned " << count << std::endl;
#endif
        if (count > MAX_MESSAGE_SIZE) {
            std::cerr << "datagram too large" << std::endl;
        } else if (count > 0) {
            if (strcmp(buffer, MSG_ECHO) == 0) {
                // Gather timing statistics.
                int64_t now = getNanoTime();
                int64_t elapsed = now - mPingTime;
                double elapsedMsec = elapsed * 1.0e-6;
                if (discard) {
                    std::cout << "discard " << elapsedMsec << " msec" << std::endl;
                } else {
                    std::cout << "got echo after " << elapsedMsec << " msec" << std::endl;
                    mPingDurationSum += elapsedMsec;
                    mPingDurationCount++;
                    mPingDurationMin = std::min(mPingDurationMin, elapsedMsec);
                    mPingDurationMax = std::max(mPingDurationMax, elapsedMsec);
                }
            }
        }
        return (int) count;
    }
    
        
    /**
     * Send pings to other socket and wait for the echo.
     */
    int run(struct TestParams *testParams) {
        mNetWorkSocket = testParams->buildNetworkSocket();
        // Skip the first few pings. Which may be very long.
        const int kNumToDiscard = 4;
        
        std::cout << std::endl << "CLIENT started" << std::endl;
        
        int err = mNetWorkSocket->setupSocket(0);
        if (err) {
            std::cout << "connect returned " << err << std::endl;
            return err;
        }

        err = mNetWorkSocket->setRemoteAddress(testParams->remoteAddressPort);
        if (err) {
            std::cout << "setRemoteAddress returned " << err << std::endl;
            return err;
        }
        
        err = mNetWorkSocket->connectToRemoteAddress();
        if (err) {
            std::cout << "connectRemoteAddress returned " << err << std::endl;
            return err;
        }
        
        int loops = testParams->numPings + kNumToDiscard;
        for (int i = 0; i < loops; i++) {
            err = sendPing();
            if (err < 0) break;
                    
            err = handleMessage(i < kNumToDiscard);
            if (err < 0) break;
            
            // Send pings at random intervals.
            int sleepMillis = rand() % 10;
            usleep(sleepMillis * 1000);
        }
        
        std::cout << "Client finished." << std::endl;
        std::cout << "ping.average.msec = " << getAveragePingDuration() << std::endl;
        std::cout << "ping.min.msec = " << getMinimumPingDuration() << std::endl;
        std::cout << "ping.max.msec = " << getMaximumPingDuration() << std::endl;
        std::cout << "network.protocol = " << (testParams->useTCP ? "TCP" : "UDP") << std::endl;
        
        if (testParams->sendQuit) sendQuit();
        
    //    initiator.close();
        
        return 0;
    }

    void runLocalTest(struct TestParams *testParams) {
        NetworkBenchmarkServer serverBenchmark;
        // Run the SERVER in a background thread.
        std::thread serverThread(&NetworkBenchmarkServer::run, &serverBenchmark, testParams);
        
        // Wait for server to set its port.
        int timeout = 50;
        usleep(200 * 1000);
        while(serverBenchmark.getLocalPort() == 0 && --timeout > 0) {
            std::cout << "Client waiting for gServicePort" << std::endl;
            usleep(50 * 1000);
        }
        if (timeout == 0) {
            std::cout << "Client timed out waiting for the service." << std::endl;
        } else {
            // Build an address:port string from the service port.
            std::string remote(ADDRESS_LOOPBACK ":");
            remote += std::to_string(serverBenchmark.getLocalPort());
            // std::cout << "remoteAddressPort = " << remote << std::endl;
            testParams->remoteAddressPort = remote.c_str();
            testParams->sendQuit = true;
            run(testParams); // Run CLIENT in foreground.
        }
            
        serverThread.join();   // main thread waits for the server thread to to finish
    }

private:
    NetworkSocketBase *mNetWorkSocket;
    int64_t mPingTime = 0;
    double mPingDurationMin = 1.0e12;
    double mPingDurationMax = -1.0;
    double mPingDurationSum = 0.0;
    int mPingDurationCount = 0;
};

void usage() {
    std::cout << "midiping [-l] [-o] [-n numPings] {remoteAddressPort}" << std::endl;
    std::cout << "  -l local test of both server and client" << std::endl;
    std::cout << "  -t use TCP" << std::endl;
    std::cout << "  -n N number of pings" << std::endl;
    std::cout << "  -q send message telling server to Quit when done" << std::endl;
    std::cout << "  {remoteAddressPort} if specified then act as client" << std::endl;
    std::cout << "      eg. 127.0.0.1:12345" << std::endl;
}

int main(int argc, const char * argv[]) {
    std::cout << "MIDI Ping Benchmark v" << APP_VERSION << std::endl;
    TestParams testParams;
    
    for (int i = 1; i < argc; i++) {
        std::cout << "Arg: " << argv[i]  << std::endl;
        const char *arg = argv[i];
        if (arg[0] == '-') {
            switch (arg[1]) {
                case 'l':
                    testParams.localMode = true;
                    break;
                case 't':
                    testParams.useTCP = true;
                    break;
                case 'n':
                    i++;
                    testParams.numPings = atoi(argv[i]);
                    break;
                case 'q':
                    testParams.sendQuit = true;
                    break;
                case 'h':
                    usage();
                    break;
                default:
                    std::cout << "invalid arg " << arg << std::endl;
                    
            }
        } else {
            testParams.remoteAddressPort = arg;
        }
    }
        
    int err = 0;
    if (testParams.remoteAddressPort) { // CLIENT
        std::cout << "remoteAddressPort = " << testParams.remoteAddressPort << std::endl;
        if (testParams.localMode) {
            std::cerr << "Do not specify an {address}:{port} with local mode!" << std::endl;
            exit(1);
        }
        NetworkBenchmarkClient client;
        err = client.run(&testParams);
    } else if (testParams.localMode) {
        NetworkBenchmarkClient client;
        client.runLocalTest(&testParams);
    } else {
        NetworkBenchmarkServer server;
        err = server.run(&testParams);
    }
    
    return err ? 1 : 0;
}
