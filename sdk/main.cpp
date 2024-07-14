#include <iostream>
#include <string>
#include "skidauth.hpp"

int main () {
    SkidAuth auth = SkidAuth::SkidAuth();

    std::string option;
    std::cout << "Enter one: (a) login\n(b) register: ";
    std::cin >> option;
    std::cout << "\n";

    if (option == "a") {
        std::string username;
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "\n";
        std::cout << (auth.authenticate(username) ? "Success" : "Failed") << "\n";
        system("pause");
    } else {
        std::string username;
        std::cout << "Enter the username you wish to choose: ";
        std::cin >> username;
        std::cout << "\n";
        std::string key;
        std::cout << "Enter your key: ";
        std::cin >> key;
        std::cout << "\n";
        system("pause");

        std::cout << (auth.registerUser(username, key) ? "Success" : "Failed");
    }
}