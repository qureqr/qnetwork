#include <iostream>
#include <winsock2.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <algorithm>

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
    return inet_ntoa(inAddr);
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
    return protocol; // Возвращаем "TCP" или "UDP"
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
    std::cout << std::string(100, '\n'); // Заполнение консоли пустыми строками
}

void monitorConnections() {
    std::vector<Connection> previousConnections;

    while (true) {
        clearConsole();
        auto currentConnections = getNetworkConnections();

        std::cout << "Updated Connections:" << std::endl;
        displayConnections(currentConnections);

        std::cout << "-----------------------------------" << std::endl;

        // Вывод информации о новых и удаленных подключениях в конце
        std::vector<Connection> removedConnections;
        std::vector<Connection> newConnections;

        // Поиск исчезнувших подключений
        for (const auto& prevConn : previousConnections) {
            if (std::find(currentConnections.begin(), currentConnections.end(), prevConn) == currentConnections.end()) {
                removedConnections.push_back(prevConn);
            }
        }

        // Поиск новых подключений
        for (const auto& currConn : currentConnections) {
            if (std::find(previousConnections.begin(), previousConnections.end(), currConn) == previousConnections.end()) {
                newConnections.push_back(currConn);
            }
        }

        // Вывод сообщений о пропавших соединениях
        for (const auto& removedConn : removedConnections) {
            std::cout << "Connection removed: " << removedConn.localAddress << " -> " << removedConn.foreignAddress << " (" << removedConn.protocol << ")" << std::endl;
        }

        // Вывод сообщений о новых соединениях
        for (const auto& newConn : newConnections) {
            std::cout << "New connection: " << newConn.localAddress << " -> " << newConn.foreignAddress << " (" << newConn.protocol << ")" << std::endl;
        }

        // Сохраняем текущие подключения для следующей итерации
        previousConnections = currentConnections;

        std::this_thread::sleep_for(std::chrono::seconds(5)); // Обновление каждые 5 секунд
    }
}

int main() {
    monitorConnections();
    return 0;
}
