#include <iostream>
#include "Injector.h"

std::string GetLastErrorAsString()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)& messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	LocalFree(messageBuffer);

	return message;
}

int main() {

	/*
		1. Get full path of PE file to inject.
	*/

#ifdef _DEBUG
	std::string exePath = "C:\\PEPayload.exe";
#else
	std::string exePath;
	std::cout << "Enter EXE to Inject into self: ";
	std::cin >> exePath;
#endif

	std::cout << "File selected for injection: " << exePath << "\n";

	/*
		2. Read target EXE from disk into local Heap space
	*/


	HANDLE hExePayloadFile = CreateFileA(&(exePath[0]), GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hExePayloadFile == INVALID_HANDLE_VALUE) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	DWORD exePayloadFileSize = GetFileSize(hExePayloadFile, NULL);
	if (exePayloadFileSize == INVALID_FILE_SIZE) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	PIMAGE_DOS_HEADER pExePayloadUnmapped = (PIMAGE_DOS_HEADER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, exePayloadFileSize);
	if (pExePayloadUnmapped == NULL) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	if (!ReadFile(hExePayloadFile, pExePayloadUnmapped, exePayloadFileSize, NULL, NULL)) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	CloseHandle(hExePayloadFile);

	/*
		3.	Map PE headers and sections into a newly allocated buffer
	*/

	PIMAGE_NT_HEADERS64 pExePayloadNTHeaders = (PIMAGE_NT_HEADERS64)(pExePayloadUnmapped->e_lfanew + (LPBYTE)pExePayloadUnmapped);
	PIMAGE_DOS_HEADER pExePayloadMapped = (PIMAGE_DOS_HEADER)VirtualAlloc(NULL, pExePayloadNTHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pExePayloadMapped == NULL) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	// Copy headers to mapped memory space

	DWORD totalHeaderSize = pExePayloadNTHeaders->OptionalHeader.SizeOfHeaders;
	memcpy_s(pExePayloadMapped, totalHeaderSize, pExePayloadUnmapped, totalHeaderSize);

	// Map PE sections into mapped memory space

	DWORD numberOfSections = pExePayloadNTHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pCurrentSection = (PIMAGE_SECTION_HEADER)(pExePayloadNTHeaders->FileHeader.SizeOfOptionalHeader + (LPBYTE)&(pExePayloadNTHeaders->OptionalHeader));
	
	for (DWORD i = 0; i < numberOfSections; i++, pCurrentSection++) {
		
		if (pCurrentSection->SizeOfRawData != 0) {
			LPBYTE pSourceSectionData = pCurrentSection->PointerToRawData + (LPBYTE)pExePayloadUnmapped;
			LPBYTE pDestinationSectionData = pCurrentSection->VirtualAddress + (LPBYTE)pExePayloadMapped;
			DWORD sectionSize = pCurrentSection->SizeOfRawData;

			memcpy_s(pDestinationSectionData, sectionSize, pSourceSectionData, sectionSize);
		}
	}

	// Replace our header pointer to mapped data and free the unmapped file in the heap

	pExePayloadNTHeaders = (PIMAGE_NT_HEADERS64)(pExePayloadMapped->e_lfanew + (LPBYTE)pExePayloadMapped);
	HeapFree(GetProcessHeap(), 0, pExePayloadUnmapped);


	/*
	4. Update the Base Relocation Table
*/


	PIMAGE_BASE_RELOCATION pCurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)(pExePayloadNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (LPBYTE)pExePayloadMapped);

	while (pCurrentBaseRelocation->VirtualAddress != NULL) {

		DWORD relocationEntryCount = (pCurrentBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		PIMAGE_RELOC pCurrentBaseRelocationEntry = (PIMAGE_RELOC)((LPBYTE)pCurrentBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < relocationEntryCount; i++, pCurrentBaseRelocationEntry++) {
			if (pCurrentBaseRelocationEntry->type == IMAGE_REL_BASED_DIR64) {

				ULONGLONG* pRelocationValue = (ULONGLONG*)((LPBYTE)pExePayloadMapped + (ULONGLONG)((pCurrentBaseRelocation->VirtualAddress + pCurrentBaseRelocationEntry->offset)));
				ULONGLONG updatedRelocationValue = (ULONGLONG)((*pRelocationValue - pExePayloadNTHeaders->OptionalHeader.ImageBase) + (LPBYTE)pExePayloadMapped);
				*pRelocationValue = updatedRelocationValue;
			}
		}

		// Increment current base relocation entry to the next one, we do this by adding its total size to the current offset
		pCurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pCurrentBaseRelocation + pCurrentBaseRelocation->SizeOfBlock);
	}


	/*
		5. Resolve and Update the IAT
	*/

	PIMAGE_IMPORT_DESCRIPTOR pMappedCurrentDLLImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pExePayloadNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (LPBYTE)pExePayloadMapped);

	while (pMappedCurrentDLLImportDescriptor->Name != NULL) {
		LPSTR currentDLLName = (LPSTR)(pMappedCurrentDLLImportDescriptor->Name + (LPBYTE)pExePayloadMapped);
		HMODULE hCurrentDLLModule = LoadLibraryA(currentDLLName);

		if (hCurrentDLLModule == NULL) {
			std::cout << GetLastErrorAsString();
			return -1;
		}

		PIMAGE_THUNK_DATA64 pImageThunkData = (PIMAGE_THUNK_DATA64)(pMappedCurrentDLLImportDescriptor->FirstThunk + (LPBYTE)pExePayloadMapped);

		while (pImageThunkData->u1.AddressOfData) {

			if (pImageThunkData->u1.Ordinal & 0x8000000000000000) {
				// Import is by ordinal

				FARPROC resolvedImportAddress = GetProcAddress(hCurrentDLLModule, MAKEINTRESOURCEA(pImageThunkData->u1.Ordinal));

				if (resolvedImportAddress == NULL) {
					std::cout << GetLastErrorAsString();
					return -1;
				}

				// Overwrite entry in IAT with the address of resolved function
				pImageThunkData->u1.AddressOfData = (ULONGLONG)resolvedImportAddress;

			}
			else {
				// Import is by name
				PIMAGE_IMPORT_BY_NAME pAddressOfImportData = (PIMAGE_IMPORT_BY_NAME)((pImageThunkData->u1.AddressOfData) + (LPBYTE)pExePayloadMapped);
				FARPROC resolvedImportAddress = GetProcAddress(hCurrentDLLModule, pAddressOfImportData->Name);

				if (resolvedImportAddress == NULL) {
					std::cout << GetLastErrorAsString();
					return -1;
				}

				// Overwrite entry in IAT with the address of resolved function
				pImageThunkData->u1.AddressOfData = (ULONGLONG)resolvedImportAddress;

			}

			pImageThunkData++;
		}

		pMappedCurrentDLLImportDescriptor++;
	}



	/*
		6. Invoke the EntryPoint of the payload as a new thread
	*/

	printf("Executing entrypoint of payload\n");

	LPTHREAD_START_ROUTINE pExePayloadEntryPoint = (LPTHREAD_START_ROUTINE) (pExePayloadNTHeaders->OptionalHeader.AddressOfEntryPoint + (LPBYTE)pExePayloadMapped);

	HANDLE hThread = CreateThread(NULL, 0, pExePayloadEntryPoint, NULL, NULL, NULL);
	if (hThread == NULL) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	WaitForSingleObject(hThread, INFINITE);

	return 0;
}