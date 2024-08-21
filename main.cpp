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
    DWORD localAddr;
    DWORD remoteAddr;
    DWORD localPort;
    DWORD remotePort;
    DWORD state;
    std::string protocol;

    std::string getLocalAddress() const {
        in_addr inAddr;
        inAddr.S_un.S_addr = localAddr;
        return inet_ntoa(inAddr) + ":" + std::to_string(ntohs((u_short)localPort));
    }

    std::string getForeignAddress() const {
        in_addr inAddr;
        inAddr.S_un.S_addr = remoteAddr;
        return inet_ntoa(inAddr) + ":" + std::to_string(ntohs((u_short)remotePort));
    }

    std::string getStateString() const {
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

    bool operator==(const Connection& other) const {
        return localAddr == other.localAddr &&
               remoteAddr == other.remoteAddr &&
               localPort == other.localPort &&
               remotePort == other.remotePort &&
               protocol == other.protocol;
    }
};

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
            conn.localAddr = row.dwLocalAddr;
            conn.remoteAddr = row.dwRemoteAddr;
            conn.localPort = row.dwLocalPort;
            conn.remotePort = row.dwRemotePort;
            conn.state = row.dwState;
            conn.protocol = "TCP";
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
            conn.localAddr = row.dwLocalAddr;
            conn.localPort = row.dwLocalPort;
            conn.remoteAddr = 0;
            conn.remotePort = 0;
            conn.state = 0; // UDP не имеет состояний, как TCP
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
        std::cout << "Local Address: " << conn.getLocalAddress() << std::endl;
        if (conn.protocol == "TCP") {
            std::cout << "Foreign Address: " << conn.getForeignAddress() << std::endl;
            std::cout << "State: " << conn.getStateString() << std::endl;
        }
        std::cout << "------------------------" << std::endl;
    }
}

void clearConsole() {
    std::cout << std::string(100, '\n'); // Очистка консоли путем заполнения пустыми строками
}

void closeTcpConnection(const Connection& conn) {
    MIB_TCPROW row;
    row.dwLocalAddr = conn.localAddr;
    row.dwLocalPort = conn.localPort;
    row.dwRemoteAddr = conn.remoteAddr;
    row.dwRemotePort = conn.remotePort;
    row.dwState = MIB_TCP_STATE_DELETE_TCB;

    if (SetTcpEntry(&row) == NO_ERROR) {
        std::cout << "Connection closed: " << conn.getLocalAddress() << " -> " << conn.getForeignAddress() << std::endl;
    } else {
        std::cout << "Failed to close connection: " << conn.getLocalAddress() << " -> " << conn.getForeignAddress() << std::endl;
    }
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
            std::cout << "Connection removed: " << removedConn.getLocalAddress() << " -> " << removedConn.getForeignAddress() << " (" << removedConn.protocol << ")" << std::endl;
        }

        // Вывод сообщений о новых соединениях
        for (const auto& newConn : newConnections) {
            std::cout << "New connection: " << newConn.getLocalAddress() << " -> " << newConn.getForeignAddress() << " (" << newConn.protocol << ")" << std::endl;
        }

        // Сохраняем текущие подключения для следующей итерации
        previousConnections = currentConnections;

        std::this_thread::sleep_for(std::chrono::seconds(5)); // Обновление каждые 5 секунд

        // Проверка пользовательского ввода
        std::string command;
        std::getline(std::cin, command);
        if (command.find("close") == 0) {
            int index = std::stoi(command.substr(6)); // Извлечение индекса из команды
            auto it = std::find_if(currentConnections.begin(), currentConnections.end(),
                                   [index](const Connection& conn) { return conn.index == index; });
            if (it != currentConnections.end()) {
                if (it->protocol == "TCP") {
                    closeTcpConnection(*it);
                } else {
                    std::cout << "Cannot close UDP connection." << std::endl;
                }
            } else {
                std::cout << "Connection with index " << index << " not found." << std::endl;
            }
        }
    }
}

int main() {
    monitorConnections();
    return 0;
}
