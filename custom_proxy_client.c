/*
custom_net_fuzzer - a shared DLL to enable network fuzzing in winAFL
-------------------------------------------------------------

Written and maintained by Maksim Shudrak <mxmssh@gmail.com>

Copyright 2018 Salesforce Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "custom_winafl_server.h"

SOCKET ListenSocket = INVALID_SOCKET;
SOCKET AcceptSocket = INVALID_SOCKET;
SOCKET ConnectSocket = INVALID_SOCKET;
static UINT32 InitSuccess = FALSE;      // 判断连接状态是否完成
static UINT32 ConnectFailed = TRUE;     // 判断连接是否失败, 需要重启init
static struct sockaddr_in LocalAddr;
static struct sockaddr_in RemoteAddr;
static UINT32 ConnectClient = FALSE;	// 判断是否与客户端建立连接
static UINT32 ConnectServr = FALSE;		// 判断是否与服务端建立连接
CRITICAL_SECTION proxy_critical_section;
HANDLE client_handle = NULL;

#define DEFAULT_LOCAL_PORT 8898
#define DEFAULT_REMOTE_PORT 5900
#define DEFAULT_BUFLEN 71680

DWORD WINAPI handleClient(void*);
DWORD WINAPI handleServer(void*);

static int SocketClose()
{
    closesocket(AcceptSocket);
    closesocket(ListenSocket);
    closesocket(ListenSocket);
    return 1;
}

CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations) {
    int oResult = send(ConnectSocket, data, size, 0);
    if (oResult == SOCKET_ERROR) {
		printf("dll run: send to server failed: %d\n", WSAGetLastError());
        SocketClose();
        InterlockedExchange(&ConnectFailed, TRUE);
    }
    else
        printf("dll_run @ -> server: %d bytes\n", oResult);

    return 1;
}

static int stateCheck(char* buf, int len)
{
    return 0;
}

static int is_client_running() {
	int ret;
	EnterCriticalSection(&proxy_critical_section);
	ret = (client_handle && (WaitForSingleObject(client_handle, 0) == WAIT_TIMEOUT));
	LeaveCriticalSection(&proxy_critical_section);
	return ret;	// 返回1表示客户端进程还存活者
}

static void create_client_process() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	char cmd[] = "D:/Work/FuzzProject/vnc/vncviewer.exe  -config D:/Work/FuzzProject/vnc/local.vnc";
	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
	}
	client_handle = pi.hProcess;
	return;
}

static void destroy_client_process(int wait_exit) {
	char* kill_cmd;
	BOOL still_alive = TRUE;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	EnterCriticalSection(&proxy_critical_section);

	if (!client_handle) {
		goto leave;
	}

	if (WaitForSingleObject(client_handle, wait_exit) != WAIT_TIMEOUT) {
		goto done;
	}

	// nudge the child process only if dynamorio is used
	TerminateProcess(client_handle, 0);

	still_alive = WaitForSingleObject(client_handle, 2000) == WAIT_TIMEOUT;

	if (still_alive) {
		//wait until the child process exits
		FATAL("fuck, I can't kill the client, who can help me!!!\n");
	}

done:
	CloseHandle(client_handle);
	client_handle = NULL;
leave:
	LeaveCriticalSection(&proxy_critical_section);
}


DWORD WINAPI handleClient(void* a)
{
    char recvBuf[DEFAULT_BUFLEN] = { 0 };
    int iResult = 0;
    int oResult = 0;

	int count = 0;
    // 与客户端连接
    AcceptSocket = accept(ListenSocket, NULL, NULL);
    if (AcceptSocket == INVALID_SOCKET) {
		FATAL("accept client failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 0;
    }
	else
	{
        printf("Client connected \n");
		InterlockedExchange(&ConnectClient, TRUE);
	}

	while (ConnectServr == FALSE) {
		Sleep(100);
	}

    while (1)
    {
		// 开头先检查一个 ConnectFailed 全局变量，如果连接阶段服务端连接失败，则客户端也中断
		if (ConnectFailed == TRUE)
		{
			printf("passive close client connect\n");
			return 0;
		}

        iResult = recv(AcceptSocket, recvBuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0)
        {
            printf("client %d client -> @: %d bytes\n", count, iResult);
            if (stateCheck(recvBuf, iResult) > 0)
            {
                // 校验成功，连接已经完成
                //  设置全局变量 已连接
                InterlockedExchange(&InitSuccess, TRUE);
                return 1;
            }
            oResult = send(ConnectSocket, recvBuf, iResult, 0);
            if (oResult == SOCKET_ERROR) {
                printf("send to server failed: %d\n", WSAGetLastError());
                goto failed;
            }
            else
                printf("client %d  @ -> server: %d bytes\n", count, oResult);
        }
        else if (iResult == 0)
        {
            printf("Handle Client: Connection closed\n");
            goto failed;
        }
        else
        {
            printf("recv from client failed: %d\n", WSAGetLastError());
            goto failed;
        }
		count++;
    }

failed:
    SocketClose();
    // 设置连接失败全局变量
    InterlockedExchange(&ConnectFailed, TRUE);
    printf("active close client connect\n");
    return 1;
}

DWORD WINAPI handleServer(void* a)
{
    char recvBuf[DEFAULT_BUFLEN] = { 0 };
    int iResult = 0;
    int oResult = 0;
	int Result = 0;

	int count = 0;

    // 与服务端连接
    Result = connect(ConnectSocket, (SOCKADDR*)&RemoteAddr, sizeof(RemoteAddr));
    if (Result == SOCKET_ERROR) {
		FATAL("connect to server failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 0;
    }
	else
	{
        printf("Server connected \n");
		InterlockedExchange(&ConnectServr, TRUE);
	}

	while (ConnectClient == FALSE)
	{
		Sleep(100);
	}

    while (1)
    {
        // 开头先检查ConnectFailed变量状态，如果连接阶段，客户端那边连接失败，这边也要结束
        if (ConnectFailed == TRUE)
        {
            printf("passive close server connect\n");
            return 0;
        }

        iResult = recv(ConnectSocket, recvBuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0)
        {
            printf("server %d server -> @: %d bytes\n", count, iResult);
            if (InitSuccess == FALSE)
            {
                oResult = send(AcceptSocket, recvBuf, iResult, 0);
                if (oResult == SOCKET_ERROR) {
                    printf("send to client failed: %d\n", WSAGetLastError());
                    goto failed;
                }
                else
                    printf("server %d @ -> client: %d bytes\n", count, oResult);
            }
        }
        else if (iResult == 0)
        {
            printf("Handle Server: Connection closed\n");
            goto failed;
        }
        else
        {
            printf("recv from server failed: %d\n", WSAGetLastError());
            goto failed;
        }
    }
failed:
    SocketClose();
    InterlockedExchange(&ConnectFailed, TRUE);
    printf("active close Server Connect\n");
    return 0;
}

/* winAFL is a TCP server now (TODO: implement UDP server) */
CUSTOM_SERVER_API int APIENTRY dll_init() {

    if(ConnectFailed == FALSE)  // 不需要进行初始化
    {
        return 1;
    }

    int Result = 0;
    InterlockedExchange(&ConnectFailed, FALSE);
	ListenSocket = INVALID_SOCKET;
	AcceptSocket = INVALID_SOCKET;
	ConnectSocket = INVALID_SOCKET;
	ConnectClient = FALSE;
	ConnectServr = FALSE;
	InitSuccess = FALSE;

    // init listen socket
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET)
    {
		WSACleanup();
		FATAL("socket failed with error: %ld\n", WSAGetLastError());
    }

    // init connect socket
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET)
    {
		WSACleanup();
		FATAL("socket failed with error: %ld\n", WSAGetLastError());
    }

	// 监听端口
    if (bind(ListenSocket, (SOCKADDR*)&LocalAddr, sizeof(LocalAddr)) == SOCKET_ERROR) {
        WSACleanup();
		FATAL("bind failed with error: %ld\n", WSAGetLastError());
    }

    if (listen(ListenSocket, 1) == SOCKET_ERROR) {
        closesocket(ListenSocket);
        WSACleanup();
		FATAL("listen failed with error: %ld\n", WSAGetLastError());
    }

    // 这里插入检测启动客户端的操作
	if (!is_client_running()) {
		destroy_client_process(0);
		create_client_process();
	}


    HANDLE hThreadClient = CreateThread(NULL, 0, handleClient, NULL, 0, NULL);
    HANDLE hThreadServer = CreateThread(NULL, 0, handleServer, NULL, 0, NULL);
    CloseHandle(hThreadClient);
    CloseHandle(hThreadServer);

	while (InitSuccess == FALSE)
	{
		Sleep(100);
	}

    return 1;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		WORD sockVersion = MAKEWORD(2, 2);
		WSADATA wsaData;

		int Result = WSAStartup(sockVersion, &wsaData);
		if (Result != NO_ERROR)
		{
			FATAL("WSAStartup failed with error: %d\n", Result);
			return 0;
		}
		InitializeCriticalSection(&proxy_critical_section);

		LocalAddr.sin_family = AF_INET;
		InetPtonA(AF_INET, "127.0.0.1", &LocalAddr.sin_addr.s_addr);
		LocalAddr.sin_port = htons(DEFAULT_LOCAL_PORT);

		RemoteAddr.sin_family = AF_INET;
		InetPtonA(AF_INET, "127.0.0.1", &RemoteAddr.sin_addr.s_addr);
		RemoteAddr.sin_port = htons(DEFAULT_REMOTE_PORT);
	}

	if (fdwReason == DLL_PROCESS_DETACH)
	{
		WSACleanup();
		DeleteCriticalSection(&proxy_critical_section);
	}
	return TRUE;
}
