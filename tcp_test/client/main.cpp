#include "client_app.hpp"
#include "schannel_tls.hpp"
#include "../protocol/protocol.h"

#include <cstdio>
#include <csignal>

static ClientApp* g_app = nullptr;

static void signalHandler(int)
{
    if (g_app) g_app->shutdown();
}

int main(int argc, char** argv)
{
    SchannelTLS::initWinsock();

    std::string host = "127.0.0.1";
    uint16_t    port = PROTOCOL_PORT;

    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(std::stoi(argv[2]));

    printf("=== USBMonitor TLS Client (C++ / Schannel) ===\n");
    printf("Target: %s:%u\n", host.c_str(), port);

    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);

    ClientApp app(host, port);
    g_app = &app;
    app.run();

    SchannelTLS::cleanupWinsock();
    return 0;
}
