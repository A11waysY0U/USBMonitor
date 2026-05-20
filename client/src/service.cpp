#include "service.h"

#include <fstream>
#include <chrono>
#include <iomanip>

std::string WStringToUTF8(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);

    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void LogToFile(const std::wstring &message)
{
    std::ofstream logFile("C:\\Windows\\Temp\\UsbMonitor.log", std::ios::app);
    if (logFile.is_open())
    {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        logFile << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S")
                << " - " << WStringToUTF8(message) << std::endl;

        logFile.flush();
    }
}

WinService *WinService::s_instance = nullptr;

WinService::WinService(const std::wstring &serviceName)
    : m_serviceName(serviceName), m_StatusHandle(NULL), m_ServiceStopEvent(INVALID_HANDLE_VALUE), m_DevNotify(NULL)
{
    ZeroMemory(&m_ServiceStatus, sizeof(m_ServiceStatus));
    s_instance = this;
}

WinService::~WinService()
{
    if (m_ServiceStopEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_ServiceStopEvent);
    }
}

HDEVNOTIFY WinService::RegisterUsbNotification()
{
    DEV_BROADCAST_DEVICEINTERFACE_W notificationFilter;
    ZeroMemory(&notificationFilter, sizeof(notificationFilter));
    notificationFilter.dbcc_size = sizeof(notificationFilter);
    notificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    notificationFilter.dbcc_classguid = GUID_DEVINTERFACE_DISK;
    return RegisterDeviceNotification(m_StatusHandle, &notificationFilter, DEVICE_NOTIFY_SERVICE_HANDLE);
}

VOID WinService::EnumerateDirectory(const std::wstring &path, int depth)
{
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((path + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0)
            continue;

        std::wstring indent(depth * 2, L' ');
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            LogToFile(indent + L"[DIR] " + fd.cFileName);
            EnumerateDirectory(path + L"\\" + fd.cFileName, depth + 1);
        }
        else
        {
            LogToFile(indent + L"[FILE] " + fd.cFileName);
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

DWORD WINAPI WinService::ServiceHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    if (s_instance == nullptr)
        return NO_ERROR;

    switch (dwControl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        s_instance->Stop();
        return NO_ERROR;

    case SERVICE_CONTROL_DEVICEEVENT:
        if (lpEventData != NULL)
        {
            PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lpEventData;
            if (pHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
            {
                PDEV_BROADCAST_DEVICEINTERFACE_W pDevInf = (PDEV_BROADCAST_DEVICEINTERFACE_W)pHdr;
                std::wstring devicePath = pDevInf->dbcc_name;

                if (dwEventType == DBT_DEVICEARRIVAL)
                {
                    LogToFile(L"[设备插入] " + devicePath);

                    // 等待 Windows 分配盘符（异步过程，需延时）
                    Sleep(3000);

                    DWORD drives = GetLogicalDrives();
                    for (wchar_t c = L'A'; c <= L'Z'; ++c)
                    {
                        if (drives & (1 << (c - L'A')))
                        {
                            std::wstring root = std::wstring(1, c) + L":\\";
                            if (GetDriveTypeW(root.c_str()) == DRIVE_REMOVABLE)
                            {
                                LogToFile(L"[可移动磁盘] 开始枚举: " + root);
                                EnumerateDirectory(root);
                            }
                        }
                    }
                }
                else if (dwEventType == DBT_DEVICEREMOVECOMPLETE)
                {
                    LogToFile(L"[设备拔出] " + devicePath);
                }
            }
        }
        break;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
    return NO_ERROR;
}

VOID WINAPI WinService::ServiceMain(DWORD argc, LPWSTR *argv)
{
    if (s_instance != nullptr)
        s_instance->Start();
}

VOID WinService::Start()
{
    m_StatusHandle = RegisterServiceCtrlHandlerEx(m_serviceName.c_str(), ServiceHandlerEx, NULL);
    if (!m_StatusHandle)
        return;

    m_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    m_ServiceStatus.dwControlsAccepted = dwAcceptControls;
    SetServiceStatus(m_StatusHandle, &m_ServiceStatus);

    m_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_ServiceStopEvent == NULL)
    {
        m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(m_StatusHandle, &m_ServiceStatus);
        return;
    }
    m_DevNotify = RegisterUsbNotification();

    LogToFile(L"服务已成功启动，开始监听 USB 事件...");

    m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(m_StatusHandle, &m_ServiceStatus);

    WaitForSingleObject(m_ServiceStopEvent, INFINITE);

    if (m_DevNotify)
    {
        UnregisterDeviceNotification(m_DevNotify);
        m_DevNotify = NULL;
    }

    m_ServiceStatus.dwControlsAccepted = 0;
    m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(m_StatusHandle, &m_ServiceStatus);
}

VOID WinService::Stop()
{
    m_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    m_ServiceStatus.dwWaitHint = 3000;
    SetServiceStatus(m_StatusHandle, &m_ServiceStatus);

    SetEvent(m_ServiceStopEvent);
}

BOOL WinService::Run()
{
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {(LPWSTR)m_serviceName.c_str(), (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}};
    return StartServiceCtrlDispatcher(ServiceTable) != FALSE;
}
