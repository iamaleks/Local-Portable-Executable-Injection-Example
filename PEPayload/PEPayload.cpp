#include <iostream>
#include <Windows.h>
#include <wininet.h>

int sendHTTPRequest() {

	LPCSTR userAgent = "agent";
	LPCSTR connectDomain = "google.com";
	LPCSTR httpRequestType = "GET";
	LPCSTR targetPath = "/test";

	HINTERNET internetHandle = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (internetHandle == NULL) {
		return -1;
	}

	DWORD_PTR dwService = (DWORD_PTR)NULL;

	HINTERNET httpHandle = InternetConnectA(internetHandle, connectDomain, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, dwService);
	if (httpHandle == NULL) {
		return -1;
	}

	HINTERNET httpRequestHandle = HttpOpenRequestA(httpHandle, httpRequestType, targetPath, NULL, NULL, NULL, 0, dwService);
	if (httpRequestHandle == NULL) {
		return -1;
	}

	BOOL result = HttpSendRequestA(httpRequestHandle, NULL, 0, NULL, 0);
	InternetCloseHandle(internetHandle);

	return 1;
}

void loopHTTPConnect() {

	while (true) {
		Sleep(2000);
		sendHTTPRequest();
		printf("Sent HTTP Request\n");
	}

}

int main() {

	printf("HTTP Payload Sending Starting\n");
	loopHTTPConnect();
}