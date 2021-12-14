/**
* Copyright (C) 2020 Elisha Riedlinger
*
* This software is  provided 'as-is', without any express  or implied  warranty. In no event will the
* authors be held liable for any damages arising from the use of this software.
* Permission  is granted  to anyone  to use  this software  for  any  purpose,  including  commercial
* applications, and to alter it and redistribute it freely, subject to the following restrictions:
*
*   1. The origin of this software must not be misrepresented; you must not claim that you  wrote the
*      original  software. If you use this  software  in a product, an  acknowledgment in the product
*      documentation would be appreciated but is not required.
*   2. Altered source versions must  be plainly  marked as such, and  must not be  misrepresented  as
*      being the original software.
*   3. This notice may not be removed or altered from any source distribution.
*/

/* alanm: this code has been modified to specificly works as text mod for Gujian3.exe, for in-game text replacement. */
/* 12/12/2021 */

#include "dsound.h"
#include <dbghelp.h>

#pragma comment (lib, "dxguid.lib")
#pragma comment (lib, "dbghelp.lib")

std::ofstream Log::LOG("dsound.log");
AddressLookupTable<void> ProxyAddressLookupTable = AddressLookupTable<void>();

DirectSoundCreateProc m_pDirectSoundCreate;
DirectSoundEnumerateAProc m_pDirectSoundEnumerateA;
DirectSoundEnumerateWProc m_pDirectSoundEnumerateW;
DllCanUnloadNowProc m_pDllCanUnloadNow;
DllGetClassObjectProc m_pDllGetClassObject;
DirectSoundCaptureCreateProc m_pDirectSoundCaptureCreate;
DirectSoundCaptureEnumerateAProc m_pDirectSoundCaptureEnumerateA;
DirectSoundCaptureEnumerateWProc m_pDirectSoundCaptureEnumerateW;
GetDeviceIDProc m_pGetDeviceID;
DirectSoundFullDuplexCreateProc m_pDirectSoundFullDuplexCreate;
DirectSoundCreate8Proc m_pDirectSoundCreate8;
DirectSoundCaptureCreate8Proc m_pDirectSoundCaptureCreate8;

BYTE words[] = { 0x00, 0x00, 0xC1, 0xC0, 0x81, 0xC1, 0x40, 0x01, 0x01, 0xC3, 0xC0, 0x03, 0x80, 0x02, 0x41, 0xC2, 0x01, 0xC6, 0xC0, 0x06, 0x80, 0x07, 0x41, 0xC7, 0x00, 0x05, 0xC1, 0xC5, 0x81, 0xC4, 0x40, 0x04, 0x01, 0xCC, 0xC0, 0x0C, 0x80, 0x0D, 0x41, 0xCD, 0x00, 0x0F, 0xC1, 0xCF, 0x81, 0xCE, 0x40, 0x0E, 0x00, 0x0A, 0xC1, 0xCA, 0x81, 0xCB, 0x40, 0x0B, 0x01, 0xC9, 0xC0, 0x09, 0x80, 0x08, 0x41, 0xC8, 0x01, 0xD8, 0xC0, 0x18, 0x80, 0x19, 0x41, 0xD9, 0x00, 0x1B, 0xC1, 0xDB, 0x81, 0xDA, 0x40, 0x1A, 0x00, 0x1E, 0xC1, 0xDE, 0x81, 0xDF, 0x40, 0x1F, 0x01, 0xDD, 0xC0, 0x1D, 0x80, 0x1C, 0x41, 0xDC, 0x00, 0x14, 0xC1, 0xD4, 0x81, 0xD5, 0x40, 0x15, 0x01, 0xD7, 0xC0, 0x17, 0x80, 0x16, 0x41, 0xD6, 0x01, 0xD2, 0xC0, 0x12, 0x80, 0x13, 0x41, 0xD3, 0x00, 0x11, 0xC1, 0xD1, 0x81, 0xD0, 0x40, 0x10, 0x01, 0xF0, 0xC0, 0x30, 0x80, 0x31, 0x41, 0xF1, 0x00, 0x33, 0xC1, 0xF3, 0x81, 0xF2, 0x40, 0x32, 0x00, 0x36, 0xC1, 0xF6, 0x81, 0xF7, 0x40, 0x37, 0x01, 0xF5, 0xC0, 0x35, 0x80, 0x34, 0x41, 0xF4, 0x00, 0x3C, 0xC1, 0xFC, 0x81, 0xFD, 0x40, 0x3D, 0x01, 0xFF, 0xC0, 0x3F, 0x80, 0x3E, 0x41, 0xFE, 0x01, 0xFA, 0xC0, 0x3A, 0x80, 0x3B, 0x41, 0xFB, 0x00, 0x39, 0xC1, 0xF9, 0x81, 0xF8, 0x40, 0x38, 0x00, 0x28, 0xC1, 0xE8, 0x81, 0xE9, 0x40, 0x29, 0x01, 0xEB, 0xC0, 0x2B, 0x80, 0x2A, 0x41, 0xEA, 0x01, 0xEE, 0xC0, 0x2E, 0x80, 0x2F, 0x41, 0xEF, 0x00, 0x2D, 0xC1, 0xED, 0x81, 0xEC, 0x40, 0x2C, 0x01, 0xE4, 0xC0, 0x24, 0x80, 0x25, 0x41, 0xE5, 0x00, 0x27, 0xC1, 0xE7, 0x81, 0xE6, 0x40, 0x26, 0x00, 0x22, 0xC1, 0xE2, 0x81, 0xE3, 0x40, 0x23, 0x01, 0xE1, 0xC0, 0x21, 0x80, 0x20, 0x41, 0xE0, 0x01, 0xA0, 0xC0, 0x60, 0x80, 0x61, 0x41, 0xA1, 0x00, 0x63, 0xC1, 0xA3, 0x81, 0xA2, 0x40, 0x62, 0x00, 0x66, 0xC1, 0xA6, 0x81, 0xA7, 0x40, 0x67, 0x01, 0xA5, 0xC0, 0x65, 0x80, 0x64, 0x41, 0xA4, 0x00, 0x6C, 0xC1, 0xAC, 0x81, 0xAD, 0x40, 0x6D, 0x01, 0xAF, 0xC0, 0x6F, 0x80, 0x6E, 0x41, 0xAE, 0x01, 0xAA, 0xC0, 0x6A, 0x80, 0x6B, 0x41, 0xAB, 0x00, 0x69, 0xC1, 0xA9, 0x81, 0xA8, 0x40, 0x68, 0x00, 0x78, 0xC1, 0xB8, 0x81, 0xB9, 0x40, 0x79, 0x01, 0xBB, 0xC0, 0x7B, 0x80, 0x7A, 0x41, 0xBA, 0x01, 0xBE, 0xC0, 0x7E, 0x80, 0x7F, 0x41, 0xBF, 0x00, 0x7D, 0xC1, 0xBD, 0x81, 0xBC, 0x40, 0x7C, 0x01, 0xB4, 0xC0, 0x74, 0x80, 0x75, 0x41, 0xB5, 0x00, 0x77, 0xC1, 0xB7, 0x81, 0xB6, 0x40, 0x76, 0x00, 0x72, 0xC1, 0xB2, 0x81, 0xB3, 0x40, 0x73, 0x01, 0xB1, 0xC0, 0x71, 0x80, 0x70, 0x41, 0xB0, 0x00, 0x50, 0xC1, 0x90, 0x81, 0x91, 0x40, 0x51, 0x01, 0x93, 0xC0, 0x53, 0x80, 0x52, 0x41, 0x92, 0x01, 0x96, 0xC0, 0x56, 0x80, 0x57, 0x41, 0x97, 0x00, 0x55, 0xC1, 0x95, 0x81, 0x94, 0x40, 0x54, 0x01, 0x9C, 0xC0, 0x5C, 0x80, 0x5D, 0x41, 0x9D, 0x00, 0x5F, 0xC1, 0x9F, 0x81, 0x9E, 0x40, 0x5E, 0x00, 0x5A, 0xC1, 0x9A, 0x81, 0x9B, 0x40, 0x5B, 0x01, 0x99, 0xC0, 0x59, 0x80, 0x58, 0x41, 0x98, 0x01, 0x88, 0xC0, 0x48, 0x80, 0x49, 0x41, 0x89, 0x00, 0x4B, 0xC1, 0x8B, 0x81, 0x8A, 0x40, 0x4A, 0x00, 0x4E, 0xC1, 0x8E, 0x81, 0x8F, 0x40, 0x4F, 0x01, 0x8D, 0xC0, 0x4D, 0x80, 0x4C, 0x41, 0x8C, 0x00, 0x44, 0xC1, 0x84, 0x81, 0x85, 0x40, 0x45, 0x01, 0x87, 0xC0, 0x47, 0x80, 0x46, 0x41, 0x86, 0x01, 0x82, 0xC0, 0x42, 0x80, 0x43, 0x41, 0x83, 0x00, 0x41, 0xC1, 0x81, 0x81, 0x80, 0x40, 0x40 };
typedef unsigned __int64 QWORD;

// a1: game text buffer header with checksum
WORD setChecksum(BYTE* a1, WORD* masks)
{
	char* v2; 
	BYTE* v3; 
	unsigned __int16 v4;
	__int64 v5;
	__int16 v6; 
	unsigned __int8 v7; 
	unsigned __int16 v8;
	__int64 v9; 
	unsigned __int16 v10;
	unsigned __int16 v11; 
	char v14[0x48];

	v2 = v14;

	*(QWORD*)v2 = *(QWORD*)a1;
	v3 = a1 + 1;
	*((QWORD*)v2 + 1) = *(QWORD*)(a1 + 8);
	v4 = 0;
	*((QWORD*)v2 + 2) = *(QWORD*)(a1 + 16);
	v5 = 5i64;
	*((DWORD*)v2 + 7) = *(DWORD*)(a1 + 24);
	*((WORD*)v2 + 12) = *(WORD*)(a1 + 28);
	v6 = *(WORD*)(a1 + 30);
	do
	{
		v7 = v4 ^ *(BYTE*)(v3 - 1);
		v3 += 6i64;
		v8 = HIBYTE(v4) ^ masks[v7];
		v9 = (unsigned __int8)(HIBYTE(v4) ^ LOBYTE(masks[v7]) ^ *(BYTE*)(v3 - 6));
		v10 = ((unsigned __int16)(HIBYTE(v8) ^ masks[v9]) >> 8) ^ masks[(unsigned __int8)(HIBYTE(v8) ^ LOBYTE(masks[v9]) ^ *(BYTE*)(v3 - 5))];
		v11 = ((unsigned __int16)(HIBYTE(v10) ^ masks[(unsigned __int8)(v10 ^ *(BYTE*)(v3 - 4))]) >> 8) ^ masks[(unsigned __int8)(HIBYTE(v10) ^ LOBYTE(masks[(unsigned __int8)(v10 ^ *(BYTE*)(v3 - 4))]) ^ *(BYTE*)(v3 - 3))];
		v4 = HIBYTE(v11) ^ masks[(unsigned __int8)(v11 ^ *(BYTE*)(v3 - 2))];
		--v5;
	} while (v5);

	*(WORD*)(a1 + 30) = v4;  // override old checksum with new one
	return v4;
}

// inject decrypt intercept code
int hook(LPVOID function_address, LPVOID redirect_address) {
	int ProtectionNeeded = 0;

	if (function_address == 0 || redirect_address == 0) return 1;

	DWORD dwPflags = 0;

	MEMORY_BASIC_INFORMATION mbi;

	const SIZE_T cbInfo = sizeof(MEMORY_BASIC_INFORMATION);

	if (VirtualQuery(function_address, &mbi, cbInfo) != cbInfo) return false;

	if (!(mbi.Protect & PAGE_EXECUTE_READWRITE)) {

		if (!VirtualProtect(function_address, 40, PAGE_EXECUTE_READWRITE, &dwPflags)) {
			printf("VirtualProtect - Error Code: %d\n", GetLastError());
			ProtectionNeeded = 1; // need to reprotect this region
		}
	}

	*(BYTE*)((PBYTE)function_address) = 0xE9;  // jmp intrustion

	*(long*)((LPBYTE)function_address + 1) = ((DWORD)redirect_address - ((DWORD)function_address + 5));

	if (ProtectionNeeded) {
		if (!VirtualProtect(function_address, 40, dwPflags, &dwPflags)) {
			printf("VirtualProtect - Error Code: %d\n", GetLastError());
		}
	}

	return 0;
}

// a small asm stub that call DLL function to do real work

BYTE DLLStub[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x49\x81\xf8\x67\x03\xdf\x03\x74\x0c\x55"
"\xff\xf7\x41\x55\x41\x56\xe9\xde\x24\x87\xfc\x55\x49\x8b\xce\x49\x8b\xd0\xff\x15\xd6\xff\xff\xff\x5d\xc3\xc7";
/* disassemble of stub code*/
/*			     ptr_DLLfunc:
00 00 00 00      dq     00 00 00 00 00 00 00 00   ; update with DLL func address on  DLL load
00 00 00 00 
				 StubEntry:
49  81  f8       CMP        R8, 0x3df0367         ; update with text.bin file size on DLL load 
67  03  df  03
74  0c           JZ         CallDLL
 55              PUSH       RBP                   ; size not matching text buffer, jmp back to orignal decrypt function
ff  f7           PUSH       RDI
41  55           PUSH       R13
41  56           PUSH       R14
e9  de  24       JMP        BackToGameCode       ; jmp offset back to game code  on DLL load, let game decrpyt text the normal way
87  fc
			     CallDLL:                                        
55               PUSH       RBP

49  8b  ce       MOV        RCX ,R14		     ; decrypted buffer addr
49  8b  d0       MOV        RDX ,R8              ; decrypted size
ff  15  d7       CALL       qword ptr[ptr_DLLfunc]  ; read text from text.bin file
ff  ff  ff
c3               RET                             ; return to caller of decrpted text, bypass decrypt function
*/

typedef struct {	
	DWORD decryptFuncEntry; //the virtual address of decrypt fucntion entry point , address of  decrypt function "PUSH RBP" instruction
	DWORD fileOffset;       // game .exe file offset of ecrypted text buffer, first 4 bytes at this offset is the decrypted size 
	DWORD textSize;         // decrypted size, this is used to detect supported game version
	char* textFileName;     // the file name of decrypted text.bin file. 
} GameInfo;

char file_1_2[] = "text.bin";
char file_1_3[] = "text1302142.bin";

// supported game version
GameInfo GameVerInfo[] = {
	{0x12b4f5, 0x132d070, 0x03df0367, file_1_2},
	{0x12b4f5, 0x1364f10, 0x0494818D, file_1_3}
};

//  insert asm code to virtal address, install interception code
int addCode(LPVOID dest_address, unsigned char* codeBytes, int length) {
	int bChanged = 0;

	if (dest_address == 0 || codeBytes == 0) return 1;

	DWORD dwflags = 0;

	MEMORY_BASIC_INFORMATION memInfo;

	const SIZE_T sizeInfo = sizeof(MEMORY_BASIC_INFORMATION);
	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
	if (VirtualQuery(dest_address, &memInfo, sizeInfo) != sizeInfo) return false;

	if (!(memInfo.Protect & PAGE_EXECUTE_READWRITE)) {

		if (!VirtualProtect(dest_address, length, PAGE_EXECUTE_READWRITE, &dwflags)) {
			printf("VirtualProtect - Error Code: %d\n", GetLastError());
			// need to resume protection
			bChanged = 1;
		}
	}

	memcpy((BYTE*)dest_address, (BYTE*)codeBytes, length);

	if (bChanged) {
		if (!VirtualProtect(dest_address, length, dwflags, &dwflags)) {
			printf("VirtualProtect - Error Code: %d\n", GetLastError());
		}
	}

	return 0;
}

// set memory buffer size and calculate new buffer header checksum
int patchBufferSize(LPVOID buffer_address, LPVOID redirect_address, DWORD textsize) {
	int bProtectChanged = 0;

	if (buffer_address == 0 || redirect_address == 0) return 1;

	DWORD dwflags = 0;

	MEMORY_BASIC_INFORMATION mbi;

	const SIZE_T cbInfo = sizeof(MEMORY_BASIC_INFORMATION);

	if (VirtualQuery(buffer_address, &mbi, cbInfo) != cbInfo) return false;

	if (!(mbi.Protect & PAGE_EXECUTE_READWRITE)) {

		if (!VirtualProtect(buffer_address, 40, PAGE_EXECUTE_READWRITE, &dwflags)) {
			printf("VirtualProtect Error Code: %d\n", GetLastError());
			bProtectChanged = 1; // need to resume protection 
		}
	}

	*((DWORD *)buffer_address) = textsize;
	DWORD chksum = setChecksum((BYTE*)buffer_address, (WORD*) redirect_address);

	if (bProtectChanged) {
		if (!VirtualProtect(buffer_address, 40, dwflags, &dwflags)) {
			printf("VirtualProtect - Error Code: %d\n", GetLastError());
		}
	}

	return 0;
}

PIMAGE_SECTION_HEADER GetSectionInfo(HMODULE baseAddr, char* section_name)
{
	DWORD bindAddr = 0;
	int len_name = strlen(section_name);
	if (baseAddr)
	{
		PIMAGE_NT_HEADERS64 NtHeader = ImageNtHeader(baseAddr);
		WORD NumSections = NtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
		for (WORD i = 0; i < NumSections; i++)
		{
			if (!strncmp((char*)Section->Name, section_name, len_name))
			{			
				return Section;
			}

			//Section->Name, Section->VirtualAddress,
			//		Section->PointerToRawData, Section->SizeOfRawData
			Section++;
		}
	}
	return NULL;
}

int GameIndex = 0;
char binFilePath[MAX_PATH];

FILE* pBinFile;

// intercept assmebly calls this fuction to read decrypted text file
unsigned long DLLcallback(BYTE* textBuffer, unsigned long size)
{

	fopen_s(&pBinFile, binFilePath, "rb");
	if (pBinFile)
	{
		fread(textBuffer, size, 1, pBinFile);
		fclose(pBinFile);
	}
	return size;
}

bool m_hook = false;

void SetupHook()
{
	if (!m_hook)
	{

		BYTE* funcAddr, * redirectAddr, * bindAddr, * rdata_text;
		BYTE* enc_text_1_2_addr;
		BYTE* enc_text_1_3_addr;
		char* textbinfile;
		BYTE* checkText;
		DWORD bindSectionAddr;

		int codeSize;
		HMODULE baseAddr;   // get process base virtual address
		baseAddr = GetModuleHandle(NULL);

		// check encode buffer size
		bool bufferFound = false;
		PIMAGE_SECTION_HEADER pBindSection = GetSectionInfo(baseAddr, ".bind"); // find .bind section, hook code go there
		PIMAGE_SECTION_HEADER pRDataSection = GetSectionInfo(baseAddr, ".rdata"); // find .rdata section and encrypted buffer virtual address

		DWORD* encryptedBufferAddr;
		if (pBindSection && pRDataSection)
		{
			// calculate difference between raw FileOffest and virtual address offset
			long RdataAddrDiff = pRDataSection->VirtualAddress - pRDataSection->PointerToRawData;
			for (int i = 0; i < (sizeof(GameVerInfo) / sizeof(GameInfo)); i++)
			{
				// convert file offset to virtual addr
				encryptedBufferAddr = (DWORD*)((BYTE*)baseAddr + GameVerInfo[i].fileOffset + RdataAddrDiff);
				if (*encryptedBufferAddr == GameVerInfo[i].textSize)  //Check  text size in memory for a game version
				{
					GameIndex = i;  // found a supported game version
					bufferFound = true;
					break;
				}

			}
		}
		if (bufferFound && pBindSection)  // make sure we found a game match.
		{
			struct stat st;

			bindAddr = (BYTE*)baseAddr + pBindSection->VirtualAddress;

			// find text.bin file in same diretory as wrapper DLL
			GetModuleFileNameA(baseAddr, binFilePath, MAX_PATH);
			char* c = strrchr(binFilePath, '\\');
			if (c)
			{
				*(c + 1) = '\0';
				strcat(binFilePath, GameVerInfo[GameIndex].textFileName);
			}
			else strcpy(binFilePath, GameVerInfo[GameIndex].textFileName);

			if (stat(binFilePath, &st) == 0)  // get text.bin file size
			{
				DWORD new_size = st.st_size;

				patchBufferSize(encryptedBufferAddr, words, (DWORD)new_size);     // change original encrpyted buffer size and checksum 

				bindAddr = (BYTE*) baseAddr + pBindSection->VirtualAddress;  // virtual address of .bind section
				funcAddr = (BYTE*) baseAddr + GameVerInfo[GameIndex].decryptFuncEntry; // virtual addr of decryptor
				redirectAddr = bindAddr + 8;  // DLL stub starting point
				// install  decrytor hook
				if (*((DWORD*)funcAddr) == 0x55415755)  // make sure  decrptor function instructions is found
				{
					*((DWORD**)&(DLLStub[0])) = (DWORD *) DLLcallback;   // set addr of  callback that read text.bin file  
					*((DWORD*)&(DLLStub[11])) = new_size;     //tell stub code the new text buffer size
					*((DWORD*)&(DLLStub[25])) = ((BYTE*)funcAddr + 6 - ((BYTE*) bindAddr + 29)); // calculate relative offset for jmp back to descrptor

					hook(funcAddr, redirectAddr);     //install hook
					codeSize = sizeof(DLLStub);
					addCode(bindAddr, DLLStub, codeSize); //install hook body
				}
			}
		}
		m_hook = true;
	}
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);

	static HMODULE dsounddll;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Load dll
		char path[MAX_PATH];
		
		GetSystemDirectoryA(path, MAX_PATH);
		strcat_s(path, "\\dsound.dll");
		Log() << "Loading " << path;
		dsounddll = LoadLibraryA(path);

		// Get function addresses
		m_pDirectSoundCreate = (DirectSoundCreateProc)GetProcAddress(dsounddll, "DirectSoundCreate");
		m_pDirectSoundEnumerateA = (DirectSoundEnumerateAProc)GetProcAddress(dsounddll, "DirectSoundEnumerateA");
		m_pDirectSoundEnumerateW = (DirectSoundEnumerateWProc)GetProcAddress(dsounddll, "DirectSoundEnumerateW");
		m_pDllCanUnloadNow = (DllCanUnloadNowProc)GetProcAddress(dsounddll, "DllCanUnloadNow");
		m_pDllGetClassObject = (DllGetClassObjectProc)GetProcAddress(dsounddll, "DllGetClassObject");
		m_pDirectSoundCaptureCreate = (DirectSoundCaptureCreateProc)GetProcAddress(dsounddll, "DirectSoundCaptureCreate");
		m_pDirectSoundCaptureEnumerateA = (DirectSoundCaptureEnumerateAProc)GetProcAddress(dsounddll, "DirectSoundCaptureEnumerateA");
		m_pDirectSoundCaptureEnumerateW = (DirectSoundCaptureEnumerateWProc)GetProcAddress(dsounddll, "DirectSoundCaptureEnumerateW");
		m_pGetDeviceID = (GetDeviceIDProc)GetProcAddress(dsounddll, "GetDeviceID");
		m_pDirectSoundFullDuplexCreate = (DirectSoundFullDuplexCreateProc)GetProcAddress(dsounddll, "DirectSoundFullDuplexCreate");
		m_pDirectSoundCreate8 = (DirectSoundCreate8Proc)GetProcAddress(dsounddll, "DirectSoundCreate8");
		m_pDirectSoundCaptureCreate8 = (DirectSoundCaptureCreate8Proc)GetProcAddress(dsounddll, "DirectSoundCaptureCreate8");

		break;

	case DLL_PROCESS_DETACH:
		FreeLibrary(dsounddll);
		break;
	}

	return TRUE;
}

HRESULT WINAPI DirectSoundCreate(LPCGUID pcGuidDevice, LPDIRECTSOUND *ppDS, LPUNKNOWN pUnkOuter)
{
	SetupHook();
	if (!m_pDirectSoundCreate)
	{
		return E_FAIL;
	}

	HRESULT hr = m_pDirectSoundCreate(pcGuidDevice, ppDS, pUnkOuter);

	if (SUCCEEDED(hr) && ppDS)
	{
		*ppDS = new m_IDirectSound8((IDirectSound8*)*ppDS);
	}

	return hr;
}

HRESULT WINAPI DirectSoundEnumerateA(LPDSENUMCALLBACKA pDSEnumCallback, LPVOID pContext)
{
	if (!m_pDirectSoundEnumerateA)
	{
		return E_FAIL;
	}

	return m_pDirectSoundEnumerateA(pDSEnumCallback, pContext);
}

HRESULT WINAPI DirectSoundEnumerateW(LPDSENUMCALLBACKW pDSEnumCallback, LPVOID pContext)
{
	if (!m_pDirectSoundEnumerateW)
	{
		return E_FAIL;
	}

	return m_pDirectSoundEnumerateW(pDSEnumCallback, pContext);
}

HRESULT WINAPI DllCanUnloadNow()
{
	if (!m_pDllCanUnloadNow)
	{
		return E_FAIL;
	}

	return m_pDllCanUnloadNow();
}

HRESULT WINAPI DllGetClassObject(IN REFCLSID rclsid, IN REFIID riid, OUT LPVOID FAR* ppv)
{
	if (!m_pDllGetClassObject)
	{
		return E_FAIL;
	}

	HRESULT hr = m_pDllGetClassObject(rclsid, riid, ppv);

	if (SUCCEEDED(hr))
	{
		genericQueryInterface(riid, ppv);
	}

	return hr;
}

HRESULT WINAPI DirectSoundCaptureCreate(LPCGUID pcGuidDevice, LPDIRECTSOUNDCAPTURE *ppDSC, LPUNKNOWN pUnkOuter)
{
	if (!m_pDirectSoundCaptureCreate)
	{
		return E_FAIL;
	}

	HRESULT hr = m_pDirectSoundCaptureCreate(pcGuidDevice, ppDSC, pUnkOuter);

	if (SUCCEEDED(hr) && ppDSC)
	{
		*ppDSC = new m_IDirectSoundCapture8(*ppDSC);
	}

	return hr;
}

HRESULT WINAPI DirectSoundCaptureEnumerateA(LPDSENUMCALLBACKA pDSEnumCallback, LPVOID pContext)
{
	if (!m_pDirectSoundCaptureEnumerateA)
	{
		return E_FAIL;
	}

	return m_pDirectSoundCaptureEnumerateA(pDSEnumCallback, pContext);
}

HRESULT WINAPI DirectSoundCaptureEnumerateW(LPDSENUMCALLBACKW pDSEnumCallback, LPVOID pContext)
{
	if (!m_pDirectSoundCaptureEnumerateW)
	{
		return E_FAIL;
	}

	return m_pDirectSoundCaptureEnumerateW(pDSEnumCallback, pContext);
}

HRESULT WINAPI GetDeviceID(LPCGUID pGuidSrc, LPGUID pGuidDest)
{
	return m_pGetDeviceID(pGuidSrc, pGuidDest);
}

HRESULT WINAPI DirectSoundFullDuplexCreate(LPCGUID pcGuidCaptureDevice, LPCGUID pcGuidRenderDevice, LPCDSCBUFFERDESC pcDSCBufferDesc, LPCDSBUFFERDESC pcDSBufferDesc, HWND hWnd,
	DWORD dwLevel, LPDIRECTSOUNDFULLDUPLEX* ppDSFD, LPDIRECTSOUNDCAPTUREBUFFER8 *ppDSCBuffer8, LPDIRECTSOUNDBUFFER8 *ppDSBuffer8, LPUNKNOWN pUnkOuter)
{
	if (!m_pDirectSoundFullDuplexCreate)
	{
		return E_FAIL;
	}

	HRESULT hr = m_pDirectSoundFullDuplexCreate(pcGuidCaptureDevice, pcGuidRenderDevice, pcDSCBufferDesc, pcDSBufferDesc, hWnd, dwLevel, ppDSFD, ppDSCBuffer8, ppDSBuffer8, pUnkOuter);

	if (SUCCEEDED(hr))
	{
		if (ppDSFD)
		{
			*ppDSFD = new m_IDirectSoundFullDuplex8(*ppDSFD);
		}
		if (ppDSCBuffer8)
		{
			*ppDSCBuffer8 = new m_IDirectSoundCaptureBuffer8(*ppDSCBuffer8);
		}
		if (ppDSBuffer8)
		{
			*ppDSBuffer8 = new m_IDirectSoundBuffer8(*ppDSBuffer8);
		}
	}

	return hr;
}

HRESULT WINAPI DirectSoundCreate8(LPCGUID pcGuidDevice, LPDIRECTSOUND8 *ppDS8, LPUNKNOWN pUnkOuter)
{
	if (!m_pDirectSoundCreate8)
	{
		return E_FAIL;
	}

	HRESULT hr = m_pDirectSoundCreate8(pcGuidDevice, ppDS8, pUnkOuter);

	if (SUCCEEDED(hr) && ppDS8)
	{
		*ppDS8 = new m_IDirectSound8(*ppDS8);
	}

	return hr;
}

HRESULT WINAPI DirectSoundCaptureCreate8(LPCGUID pcGuidDevice, LPDIRECTSOUNDCAPTURE8 *ppDSC8, LPUNKNOWN pUnkOuter)
{
	if (!m_pDirectSoundCaptureCreate8)
	{
		return E_FAIL;
	}

	HRESULT hr = m_pDirectSoundCaptureCreate8(pcGuidDevice, ppDSC8, pUnkOuter);

	if (SUCCEEDED(hr) && ppDSC8)
	{
		*ppDSC8 = new m_IDirectSoundCapture8(*ppDSC8);
	}

	return hr;
}
