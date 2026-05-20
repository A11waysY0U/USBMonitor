#include <windows.h>
#include <dbt.h>
#include <usbiodef.h>
#include <string>

class WinService
{
private:
    static DWORD WINAPI ServiceHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);

    HDEVNOTIFY RegisterUsbNotification();

    static VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv);

    VOID Start();
    VOID Stop();

    static VOID EnumerateDirectory(const std::wstring& path, int depth = 0);

    std::wstring m_serviceName;

    SERVICE_STATUS m_ServiceStatus;
    SERVICE_STATUS_HANDLE m_StatusHandle;
    HANDLE m_ServiceStopEvent;
    HDEVNOTIFY m_DevNotify;

    static WinService *s_instance;

    DWORD m_dwCheckPoint = 1;

    DWORD dwAcceptControls = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

public:
    WinService(const std::wstring &serviceName);
    BOOL Run();
    ~WinService();
};
