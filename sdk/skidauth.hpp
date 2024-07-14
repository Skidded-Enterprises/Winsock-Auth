#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

class SkidAuth {
private:
    const std::string SERVER_IP = "127.0.0.1";  // Change this to auth server's IP
    const int SERVER_PORT = 12345; // Port
    const std::string PUBLICTOKEN = "C759811D198B764F0571430419F106D6"; // replace with ur token (the public one)

    SOCKET sock; // The socket

    // Hashing
    std::string encryptDecrypt(const std::string& data);

    // Sending packets to auth server
    std::string sendRequest(const std::string& request);

public:
    SkidAuth();

    ~SkidAuth();

    // Authenticate user's credidentials by using HWID and Username
    bool authenticate(const std::string& username);

    // Register user using key and username
    bool registerUser(const std::string& username, const std::string& key);

    std::string getHWID();
};