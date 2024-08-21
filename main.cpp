#include <iostream>
#include <winsock2.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <algorithm>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

struct Connection {
    int index;
    std::string localAddress;
    std::string foreignAddress;
    std::string state;
    std::string protocol;

    bool operator==(const Connection& other) const {
        return localAddress == other.localAddress &&
               foreignAddress == other.foreignAddress &&
               state == other.state &&
               protocol == other.protocol;
    }
};

std::string ipToString(DWORD ip) {
    in_addr inAddr;
    inAddr.S_un.S_addr = ip;
    return std::string(inet_ntoa(inAddr)); // Возвращаем std::string
}
std::mutex connectionMutex;

void closeConnectionByIndex(int index, std::vector<Connection>& connections) {
    std::lock_guard<std::mutex> lock(connectionMutex);  // Блокируем мьютекс

    if (index > 0 && index <= connections.size()) {
        Connection conn = connections[index - 1];

        if (conn.protocol == "TCP") {
            MIB_TCPROW row;
            row.dwLocalAddr = inet_addr(conn.localAddress.substr(0, conn.localAddress.find(':')).c_str());
            row.dwLocalPort = htons(std::stoi(conn.localAddress.substr(conn.localAddress.find(':') + 1)));
            row.dwRemoteAddr = inet_addr(conn.foreignAddress.substr(0, conn.foreignAddress.find(':')).c_str());
            row.dwRemotePort = htons(std::stoi(conn.foreignAddress.substr(conn.foreignAddress.find(':') + 1)));
            row.dwState = MIB_TCP_STATE_DELETE_TCB;  // Устанавливаем состояние в DELETE_TCB для закрытия

            if (SetTcpEntry(&row) == NO_ERROR) {
                std::cout << "Connection with index " << index << " closed successfully." << std::endl;
            } else {
                std::cout << "Failed to close connection with index " << index << "." << std::endl;
            }
        } else {
            std::cout << "UDP connections cannot be closed programmatically." << std::endl;
        }
    } else {
        std::cout << "Invalid index." << std::endl;
    }
}

void handleUserInput(std::vector<Connection>& connections) {
    while (true) {
        std::string input;
        std::cout << "Enter command: ";
        std::getline(std::cin, input);

        if (input.rfind("close", 0) == 0) {
            int index = std::stoi(input.substr(6)); // Предполагаем, что формат команды "close N"
            closeConnectionByIndex(index, connections);
        } else {
            std::cout << "Unknown command." << std::endl;
        }
    }
}


std::string stateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT: return "SYN SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN RECEIVED";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN WAIT 1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN WAIT 2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE TCB";
        default: return "UNKNOWN";
    }
}

std::string protocolToString(const std::string& foreignAddress, const std::string& protocol) {
    size_t colonPos = foreignAddress.find(':');
    if (colonPos != std::string::npos) {
        int port = std::stoi(foreignAddress.substr(colonPos + 1));
        if (protocol == "TCP") {
            switch (port) {
                case 80: return "HTTP";
                case 443: return "HTTPS";
                default: return "TCP";
            }
        }
    }
    return protocol;
}

std::vector<Connection> getTcpConnections() {
    std::vector<Connection> connections;
    PMIB_TCPTABLE tcpTable;
    DWORD size = 0;

    GetTcpTable(NULL, &size, 0);
    tcpTable = (MIB_TCPTABLE*)malloc(size);

    if (GetTcpTable(tcpTable, &size, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW row = tcpTable->table[i];
            Connection conn;
            conn.index = i + 1;
            conn.localAddress = ipToString(row.dwLocalAddr) + ":" + std::to_string(ntohs((u_short)row.dwLocalPort));
            conn.foreignAddress = ipToString(row.dwRemoteAddr) + ":" + std::to_string(ntohs((u_short)row.dwRemotePort));
            conn.state = stateToString(row.dwState);
            conn.protocol = protocolToString(conn.foreignAddress, "TCP");
            connections.push_back(conn);
        }
    }
    free(tcpTable);
    return connections;
}

std::vector<Connection> getUdpConnections() {
    std::vector<Connection> connections;
    PMIB_UDPTABLE udpTable;
    DWORD size = 0;

    GetUdpTable(NULL, &size, TRUE);
    udpTable = (MIB_UDPTABLE*)malloc(size);

    if (GetUdpTable(udpTable, &size, TRUE) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDPROW row = udpTable->table[i];
            Connection conn;
            conn.index = i + 1;
            conn.localAddress = ipToString(row.dwLocalAddr) + ":" + std::to_string(ntohs((u_short)row.dwLocalPort));
            conn.foreignAddress = "0.0.0.0:0"; // Для UDP соединений удаленный адрес неизвестен
            conn.state = "N/A";
            conn.protocol = "UDP";
            connections.push_back(conn);
        }
    }
    free(udpTable);
    return connections;
}

std::vector<Connection> getNetworkConnections() {
    std::vector<Connection> connections;
    auto tcpConnections = getTcpConnections();
    auto udpConnections = getUdpConnections();

    connections.insert(connections.end(), tcpConnections.begin(), tcpConnections.end());
    connections.insert(connections.end(), udpConnections.begin(), udpConnections.end());

    return connections;
}

void displayConnections(const std::vector<Connection>& connections) {
    for (const auto& conn : connections) {
        std::cout << "Index: " << conn.index << std::endl;
        std::cout << "Protocol: " << conn.protocol << std::endl;
        std::cout << "Local Address: " << conn.localAddress << std::endl;
        std::cout << "Foreign Address: " << conn.foreignAddress << std::endl;
        std::cout << "State: " << conn.state << std::endl;
        std::cout << "------------------------" << std::endl;
    }
}

void clearConsole() {
    std::cout << std::string(100, '\n');
}

void monitorConnections() {
    std::vector<Connection> previousConnections;

    std::thread userInputThread(handleUserInput, std::ref(previousConnections));  // Поток для обработки команд

    while (true) {
        clearConsole();
        auto currentConnections = getNetworkConnections();

        {
            std::lock_guard<std::mutex> lock(connectionMutex);  // Блокируем мьютекс для безопасного доступа
            previousConnections = currentConnections;  // Обновляем текущие соединения для пользователя
        }

        std::cout << "Updated Connections:" << std::endl;
        displayConnections(currentConnections);

        std::cout << "-----------------------------------" << std::endl;

        std::this_thread::sleep_for(std::chrono::seconds(5)); // Обновление каждые 5 секунд
    }

    userInputThread.join();  // Ждем завершения потока ввода команд
}


int main() {
    monitorConnections();
    return 0;
}
