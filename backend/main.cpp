#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <ctime>
#include <filesystem>
#include <random>
#include <chrono>
#include <sstream>
#pragma comment(lib, "Ws2_32.lib")

const int PORT = 12345;
const int BUFFER_SIZE = 1024;
const uint16_t XOR_KEY = 0x5AFE;
const int MAX_REQUESTS_PER_MINUTE = 200;

struct User {
    std::string username;
    std::string hwid;
};

struct Admin {
    std::string adminToken;
    std::string privateToken;
    std::unordered_map<std::string, User> users;
    std::vector<std::string> keys;
};

std::unordered_map<std::string, Admin> admins;
std::unordered_map<std::string, int> requestCount;
std::unordered_map<std::string, time_t> lastRequestTime;

std::string encryptDecrypt(const std::string& data) {
    std::string result = data;
    for (char& c : result) {
        c ^= XOR_KEY;
    }
    return result;
}

std::string generateToken() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);

    const char* hexChars = "0123456789ABCDEF";
    std::string token;
    for (int i = 0; i < 32; ++i) {
        token += hexChars[dis(gen)];
    }
    return token;
}

bool isRateLimited(const std::string& ip) {
    auto now = std::time(nullptr);
    if (requestCount.find(ip) == requestCount.end() || now - lastRequestTime[ip] >= 60) {
        requestCount[ip] = 1;
        lastRequestTime[ip] = now;
    } else {
        requestCount[ip]++;
    }
    return requestCount[ip] > MAX_REQUESTS_PER_MINUTE;
}

void createDefaultFiles() {
    if (!std::filesystem::exists("admins.txt")) {
        std::ofstream adminFile("admins.txt");
        adminFile.close();
    }
}

void createAdminFolder(const std::string& adminToken) {
    std::filesystem::create_directory(adminToken);
    std::ofstream userFile(adminToken + "/users.txt");
    userFile.close();
    std::ofstream keyFile(adminToken + "/keys.txt");
    keyFile.close();
}

void saveAdminData(const Admin& admin) {
    std::string folderPath = admin.adminToken + "/";
    std::filesystem::create_directory(folderPath);

    std::ofstream userFile(folderPath + "users.txt");
    for (const auto& user : admin.users) {
        userFile << user.second.username << "," << user.second.hwid << std::endl;
    }
    userFile.close();

    std::ofstream keyFile(folderPath + "keys.txt");
    for (const auto& key : admin.keys) {
        keyFile << key << std::endl;
    }
    keyFile.close();
}

void saveData() {
    std::ofstream adminFile("admins.txt");
    for (const auto& admin : admins) {
        adminFile << admin.second.adminToken << "," << admin.second.privateToken << std::endl;
        saveAdminData(admin.second);
    }
    adminFile.close();
}

void loadAdminData(Admin& admin) {
    std::string folderPath = admin.adminToken + "/";
    
    std::ifstream userFile(folderPath + "users.txt");
    std::string line;
    while (std::getline(userFile, line)) {
        size_t pos = line.find(',');
        std::string username = line.substr(0, pos);
        std::string hwid = line.substr(pos + 1);
        admin.users[username] = {username, hwid};
    }
    userFile.close();

    std::ifstream keyFile(folderPath + "keys.txt");
    while (std::getline(keyFile, line)) {
        admin.keys.push_back(line);
    }
    keyFile.close();
}

void loadData() {
    createDefaultFiles();

    std::ifstream adminFile("admins.txt");
    std::string line;
    while (std::getline(adminFile, line)) {
        size_t pos = line.find(',');
        std::string adminToken = line.substr(0, pos);
        std::string privateToken = line.substr(pos + 1);
        admins[adminToken] = {adminToken, privateToken};
        loadAdminData(admins[adminToken]);
    }
    adminFile.close();

    if (admins.empty()) {
        std::string adminToken = generateToken();
        std::string privateToken = generateToken();
        admins[adminToken] = {adminToken, privateToken};
        createAdminFolder(adminToken);
        saveData();
        std::cout << "Auto-generated admin token: " << adminToken << std::endl;
        std::cout << "Auto-generated private token: " << privateToken << std::endl;
    }
}



std::string handlePacket(const std::string& packet, const std::string& ip) {
    if (isRateLimited(ip)) {
        return encryptDecrypt("Rate limited");
    }

    std::string decrypted = encryptDecrypt(packet);
    std::istringstream iss(decrypted);
    std::string command;
    iss >> command;

    if (command == "AUTH") {
        std::string username, hwid, adminToken;
        iss >> username >> hwid >> adminToken;
        auto adminIt = admins.find(adminToken);
        if (adminIt == admins.end()) {
            return encryptDecrypt("Invalid admin token");
        }
        auto& admin = adminIt->second;
        auto it = admin.users.find(username);
        if (it != admin.users.end() && it->second.hwid == hwid) {
            return encryptDecrypt("YES");
        }
        return encryptDecrypt("NO");
    } else if (command == "REGISTER") {
        std::string username, key, hwid, adminToken;
        iss >> username >> key >> hwid >> adminToken;
        auto adminIt = admins.find(adminToken);
        if (adminIt == admins.end()) {
            return encryptDecrypt("Invalid admin token");
        }
        auto& admin = adminIt->second;
        std::cout << adminToken << "\n";
        auto it = std::find(admin.keys.begin(), admin.keys.end(), key);
        if (it != admin.keys.end()) {
            admin.keys.erase(it);
            admin.users[username] = {username, hwid};
            saveAdminData(admin);
            return encryptDecrypt("User registered");
        }
        return encryptDecrypt("Invalid key");
    } else if (command == "ADMIN_REGISTER") {
        std::string adminKey;
        iss >> adminKey;
        for (auto& admin : admins) {
            auto it = std::find(admin.second.keys.begin(), admin.second.keys.end(), adminKey);
            if (it != admin.second.keys.end()) {
                admin.second.keys.erase(it);
                std::string newAdminToken = generateToken();
                std::string privateToken = generateToken();
                admins[newAdminToken] = {newAdminToken, privateToken};
                std::filesystem::create_directory(newAdminToken);
                saveData();
                return encryptDecrypt(newAdminToken + " " + privateToken);
            }
        }
        return encryptDecrypt("Invalid admin key");
    } else if (command == "ADMIN_COMMAND") {
        std::string adminToken, privateToken, subCommand;
        iss >> adminToken >> privateToken >> subCommand;
        auto it = admins.find(adminToken);
        if (it == admins.end() || it->second.privateToken != privateToken) {
            return encryptDecrypt("Invalid admin credentials");
        }
        auto& admin = it->second;
        if (subCommand == "BAN") {
            std::string username;
            iss >> username;
            admin.users.erase(username);
            saveAdminData(admin);
            return encryptDecrypt("User banned");
        } else if (subCommand == "UNBAN") {
            std::string username, hwid;
            iss >> username >> hwid;
            admin.users[username] = {username, hwid};
            saveAdminData(admin);
            return encryptDecrypt("User unbanned");
        } else if (subCommand == "CREATE_KEY") {
            std::string newKey = generateToken();
            admin.keys.push_back(newKey);
            saveAdminData(admin);
            return encryptDecrypt("Key created: " + newKey);
        } else if (subCommand == "DELETE_KEY") {
            std::string keyToDelete;
            iss >> keyToDelete;
            auto keyIt = std::find(admin.keys.begin(), admin.keys.end(), keyToDelete);
            if (keyIt != admin.keys.end()) {
                admin.keys.erase(keyIt);
                saveAdminData(admin);
                return encryptDecrypt("Key deleted");
            }
            return encryptDecrypt("Key not found");
        }
        return encryptDecrypt("Invalid admin command");
    }
    return encryptDecrypt("Invalid command");
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    loadData();

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server started on port " << PORT << std::endl;

    while (true) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        char buffer[BUFFER_SIZE];
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytesReceived > 0) {
            std::string request(buffer, bytesReceived);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, INET_ADDRSTRLEN);
            std::string response = handlePacket(request, ipStr);
            send(clientSocket, response.c_str(), response.length(), 0);
        }

        closesocket(clientSocket);
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}