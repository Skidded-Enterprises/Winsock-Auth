#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

const int PORT = 12345;
const char* SERVER_IP = "127.0.0.1"; // Change to auth server IP
const int BUFFER_SIZE = 1024;
const uint16_t XOR_KEY = 0x5AFE;

std::string adminToken;
std::string privateToken;

std::string encryptDecrypt(const std::string& data) {
    std::string result = data;
    for (char& c : result) {
        c ^= XOR_KEY;
    }
    return result;
}

bool loadCredentials() {
    std::ifstream file("admin_credentials.txt");
    if (file.is_open()) {
        std::getline(file, adminToken);
        std::getline(file, privateToken);
        file.close();
        return !adminToken.empty() && !privateToken.empty();
    }
    return false;
}

void saveCredentials() {
    std::ofstream file("admin_credentials.txt");
    file << adminToken << std::endl << privateToken;
    file.close();
}

std::string sendCommand(const std::string& command) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "Failed to initialize Winsock";
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return "Failed to create socket";
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return "Failed to connect to server";
    }

    std::string encryptedCommand = encryptDecrypt(command);
    send(sock, encryptedCommand.c_str(), encryptedCommand.length(), 0);

    char buffer[BUFFER_SIZE];
    int bytesReceived = recv(sock, buffer, BUFFER_SIZE, 0);
    
    closesocket(sock);
    WSACleanup();

    if (bytesReceived > 0) {
        std::string response(buffer, bytesReceived);
        return encryptDecrypt(response);
    }

    return "No response from server";
}

void printHelp() {
    std::cout << "Available commands (case sensitive eg. all caps):\n";
    std::cout << "1. BAN <username> - Ban a user\n";
    std::cout << "2. UNBAN <username> <hwid> - Unban a user\n";
    std::cout << "3. CREATE_KEY - Create a new key\n";
    std::cout << "4. DELETE_KEY <key> - Delete a specific key\n";
    std::cout << "5. HELP - Display this help message\n";
    std::cout << "6. EXIT - Exit the admin panel\n";
}

int main() {
    if (!loadCredentials()) {
        std::cout << "Enter your admin token: ";
        std::cin >> adminToken;
        std::cout << "Enter your private token: ";
        std::cin >> privateToken;
        saveCredentials();
    }

    std::cout << "Admin panel connected. Type 'help' for a list of commands.\n";

    std::string input;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin >> std::ws, input);

        if (input == "exit") {
            break;
        } else if (input == "help") {
            printHelp();
            continue;
        }

        std::string command = "ADMIN_COMMAND " + adminToken + " " + privateToken + " " + input;
        std::string response = sendCommand(command);
        std::cout << "Server response: " << response << std::endl;
    }

    std::cout << "Admin panel disconnected.\n";
    return 0;
}