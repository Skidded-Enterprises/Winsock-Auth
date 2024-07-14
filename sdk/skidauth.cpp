#include "skidauth.hpp"

const uint16_t XOR_KEY = 0x5AFE; // Keep this shi safe

SkidAuth::SkidAuth() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("Failed to initialize Winsock");
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP.c_str(), &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        throw std::runtime_error("Failed to connect to server");
    }
}

SkidAuth::~SkidAuth() {
    closesocket(sock);
    WSACleanup();
}

bool SkidAuth::authenticate(const std::string& username) {
    std::string hwid = getHWID();
    std::string request = "AUTH " + username + " " + hwid + " " + PUBLICTOKEN;
    std::string response = sendRequest(request);
    return response == "YES";
}

bool SkidAuth::registerUser(const std::string& username, const std::string& key) {
    std::string hwid = getHWID();
    std::string request = "REGISTER " + username + " " + key + " " + hwid + " " + PUBLICTOKEN;
    std::string response = sendRequest(request);
    return response == "YES";
}

std::string SkidAuth::encryptDecrypt(const std::string& data) {
    std::string result = data;
    for (char& c : result) {
        c ^= XOR_KEY;
    }
    return result;
}

std::string SkidAuth::sendRequest(const std::string& request) {
    std::string encrypted = encryptDecrypt(request);
    if (send(sock, encrypted.c_str(), encrypted.length(), 0) == SOCKET_ERROR) {
        throw std::runtime_error("Failed to send data");
    }

    char buffer[1024];
    int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
    if (bytesReceived == SOCKET_ERROR) {
        throw std::runtime_error("Failed to receive data");
    }

    std::string response(buffer, bytesReceived);
    return encryptDecrypt(response);
}

std::string SkidAuth::getHWID() {
    std::vector<std::string> hwInfos;

    char volumeName[MAX_PATH + 1] = { 0 };
    char fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;
    if (GetVolumeInformationA("C:\\", volumeName, ARRAYSIZE(volumeName), &serialNumber,
        &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName))) {
        hwInfos.push_back(std::to_string(serialNumber));
    }

    std::stringstream ss;
    for (const auto& info : hwInfos) {
        ss << info;
    }

    std::hash<std::string> hasher;
    size_t hash = hasher(ss.str());

    return std::to_string(hash);
}