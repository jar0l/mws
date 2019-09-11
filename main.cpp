/* ------------------------------------------------------------------------------------
 * Mini Web Server v1.0
 * Created in 2019 by José A. Rojo L. 
 * ------------------------------------------------------------------------------------
 *
 * MIT License
 *  
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this 
 * software and associated documentation files (the "Software"), to deal in the Software 
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the  Software is furnished to do so, subject to the following 
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies 
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT  
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE   
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://opensource.org/licenses/MIT
 *
 */

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <vector>
#include <chrono>
#include <ctime>
#include <windows.h>
#include <shlwapi.h>
#include <security.h>
#include "http.h"
#include <wininet.h>

//------------------------------------------------------------------------------------

#define MAX_ULONG_STR ((ULONG) sizeof("4294967295"))

#define INITIALIZE_HTTP_RESPONSE(resp, status, reason)      \
    do                                                      \
    {                                                       \
        RtlZeroMemory( (resp), sizeof(*(resp)) );           \
        (resp)->StatusCode = (status);                      \
        (resp)->pReason = (reason);                         \
        (resp)->ReasonLength = (USHORT) strlen(reason);     \
    } while (FALSE)

#define ADD_KNOWN_HEADER(Response, HeaderId, RawValue)               		 \
    do                                                               		 \
    {                                                                		 \
        (Response).Headers.KnownHeaders[(HeaderId)].pRawValue =  (RawValue); \
        (Response).Headers.KnownHeaders[(HeaderId)].RawValueLength = 		 \
            (USHORT) strlen(RawValue);                               		 \
    } while(FALSE)

#define ALLOC_MEM(cb) HeapAlloc(GetProcessHeap(), 0, (cb))
#define FREE_MEM(ptr) HeapFree(GetProcessHeap(), 0, (ptr))

//------------------------------------------------------------------------------------

PCSTR           g_szAppName    = "Mini Web Server v1.0";
LPCWSTR         g_wsServerExit = L"/server/exit";
LPCWSTR         g_wsHttp       = L"http://";
PSTR            g_szOK         = (PSTR)"OK";
PCSTR           g_szError      = "[ERROR]: ";
PCSTR           g_szCode       = " > Code: ";
PCSTR           g_szUrlError   = "Invalid Url!\n";
LPCWSTR         g_pAbsPath     = NULL;
HANDLE          g_hThread      = NULL;
DWORD           g_Result       = NO_ERROR;
BOOL            g_bThreading   = FALSE;
HANDLE          g_hFile        = INVALID_HANDLE_VALUE;
HANDLE          g_hReqQueue    = NULL;
HTTP_REQUEST_ID g_RequestId;
std::wstring    g_wsRoot;

//------------------------------------------------------------------------------------

// for manipulators like std::endl
typedef std::ostream& (*stream_function)(std::ostream&);

class mws_ostream
{
	private:
		std::ofstream mws_fstream;
		
	public:
		mws_ostream () {};
		~mws_ostream ()
		{
			if (mws_fstream.is_open())
			{
				mws_fstream << '\n';
				mws_fstream.close();
			}
		}
		
		bool open (PCSTR file)
		{
			if (!mws_fstream.is_open())
			{
				mws_fstream.open(file, std::ofstream::out | std::ofstream::app);
				if (!mws_fstream.is_open())
					std::cout << g_szError << "Could not create the log file!\n";
			}
			
			return mws_fstream.is_open();
		}
		
		template<typename T> mws_ostream& operator << (const T& something)
		{
			std::cout << something;
			
			if (mws_fstream.is_open())
				mws_fstream << something;

			return *this;
		}
		
		mws_ostream& operator << (stream_function func)
		{
			func(std::cout);
			
			if (mws_fstream.is_open())
				func(mws_fstream);
			
			return *this;
		}
};

//------------------------------------------------------------------------------------

mws_ostream                                        g_mwsout;
std::chrono::time_point<std::chrono::system_clock> g_now;
std::time_t                                        g_date;

//------------------------------------------------------------------------------------

std::wstring StringToWString (const std::string& as)
{
	std::wstring result(as.length(), L'\0' );
	
	MultiByteToWideChar
	(
		  CP_ACP
		, 0
		, as.c_str()
		, as.length()
		, &result[0]
		, result.length()
	);
	
	return result;
}

//------------------------------------------------------------------------------------

std::wstring StringToWString (PCSTR sz)
{
	std::string result(sz);
	return StringToWString(result);
}

//------------------------------------------------------------------------------------

std::string WStringToString (std::wstring& ws)
{
	std::string result(ws.length(), '\0');
	
	WideCharToMultiByte
	(
		  CP_ACP
		, 0
		, ws.c_str()
		, ws.length()
		, &result[0]
		, result.length()
		, 0
		, 0
	);

	return result;
}

//------------------------------------------------------------------------------------

std::string WStringToString (PCWSTR ws)
{
	std::wstring result(ws);
	return WStringToString(result);
}

//------------------------------------------------------------------------------------

PSTR GetMimeType (const std::string &extension)
{
	PSTR  result = (PSTR)"application/octet-stream";
	PCSTR szExt  = extension.c_str();
	LONG  status = extension.empty();
	HKEY  hKey   = NULL;

	if (!status) status = RegOpenKeyExA
	(
		  HKEY_CLASSES_ROOT
		, szExt
		, 0
		, KEY_READ
		, &hKey
	);

	if (status == ERROR_SUCCESS)
	{
		char  szBuffer[256] = {0};
		DWORD dwBuffSize    = sizeof(szBuffer);
		
		status = RegQueryValueExA
		(
			  hKey
			, "Content Type"
			, NULL
			, NULL
			, (LPBYTE)szBuffer
			, &dwBuffSize
		);
		
		if (status == ERROR_SUCCESS)
			result = szBuffer;

		RegCloseKey(hKey);
	}
	
	if (status != ERROR_SUCCESS)
	{
		if (_stricmp(szExt, ".csv") == 0)
			result = (PSTR)"text/csv";
		
		else if (_stricmp(szExt, ".css") == 0)
			result = (PSTR)"text/css";
		
		else if (_stricmp(szExt, ".txt") == 0)
			result = (PSTR)"text/plain";
		
		else if (_stricmp(szExt, ".htm") == 0 || _stricmp(szExt, ".html") == 0)
			result = (PSTR)"text/html";
		
		else if (_stricmp(szExt, ".xhtml") == 0)
			result = (PSTR)"application/xhtml+xml";
		
		else if (_stricmp(szExt, ".js") == 0)
			result = (PSTR)"application/javascript";
		
		else if (_stricmp(szExt, ".json") == 0)
			result = (PSTR)"application/json";
		
		else if (_stricmp(szExt, ".xml") == 0)
			result = (PSTR)"application/xml";
		
		else if (_stricmp(szExt, ".pdf") == 0)
			result = (PSTR)"application/pdf";
		
		else if (_stricmp(szExt, ".zip") == 0)
			result = (PSTR)"application/zip";
		
		else if (_stricmp(szExt, ".rar") == 0)
			result = (PSTR)"application/x-rar-compressed";
		
		else if (_stricmp(szExt, ".7z") == 0)
			result = (PSTR)"application/x-7z-compressed";
		
		else if (_stricmp(szExt, ".tar") == 0)
			result = (PSTR)"application/x-tar";
		
		else if (_stricmp(szExt, ".swf") == 0)
			result = (PSTR)"application/x-shockwave-flash";
		
		else if (_stricmp(szExt, ".jar") == 0)
			result = (PSTR)"application/java-archive";
		
		else if (_stricmp(szExt, ".m3u8") == 0)
			result = (PSTR)"application/x-mpegurl";
		
		else if (_stricmp(szExt, ".tif") == 0 || _stricmp(szExt, ".tiff") == 0)
			result = (PSTR)"image/tiff";
		
		else if (_stricmp(szExt, ".svg") == 0)
			result = (PSTR)"image/svg+xml";
		
		else if (_stricmp(szExt, ".ico") == 0)
			result = (PSTR)"image/x-icon";
		
		else if (_stricmp(szExt, ".gif") == 0)
			result = (PSTR)"image/gif";
		
		else if (_stricmp(szExt, ".png") == 0)
			result = (PSTR)"image/png";
		
		else if (_stricmp(szExt, ".jpg") == 0 || _stricmp(szExt, ".jpeg") == 0)
			result = (PSTR)"image/jpeg";
		
		else if (_stricmp(szExt, ".webp") == 0)
			result = (PSTR)"image/webp";
		
		else if (_stricmp(szExt, ".webm") == 0)
			result = (PSTR)"video/webm";
		
		else if (_stricmp(szExt, ".wmv") == 0)
			result = (PSTR)"video/x-ms-wmv";
		
		else if (_stricmp(szExt, ".flv") == 0)
			result = (PSTR)"video/x-flv";	
		
		else if (_stricmp(szExt, ".3gp") == 0)
			result = (PSTR)"video/3gpp";
		
		else if (_stricmp(szExt, ".3g2") == 0)
			result = (PSTR)"video/3gpp2";
		
		else if (_stricmp(szExt, ".ogv") == 0)
			result = (PSTR)"video/ogg";
		
		else if (_stricmp(szExt, ".mp4") == 0)
			result = (PSTR)"video/mp4";
		
		else if (_stricmp(szExt, ".mov") == 0 || _stricmp(szExt, ".qt") == 0)
			result = (PSTR)"video/quicktime";

		else if (_stricmp(szExt, ".mpg") == 0 || _stricmp(szExt, ".mpeg") == 0)
			result = (PSTR)"video/mpeg";
		
		else if (_stricmp(szExt, ".avi") == 0)
			result = (PSTR)"video/x-msvideo";
		
		else if (_stricmp(szExt, ".ts") == 0)
			result = (PSTR)"video/mp2t";
		
		else if (_stricmp(szExt, ".weba") == 0)
			result = (PSTR)"audio/webm";
		
		else if (_stricmp(szExt, ".m3u") == 0)
			result = (PSTR)"audio/x-mpegurl";
		
		else if (_stricmp(szExt, ".mp3") == 0)
			result = (PSTR)"audio/mpeg";
		
		else if (_stricmp(szExt, ".m4a") == 0)
			result = (PSTR)"audio/m4a";
		
		else if (_stricmp(szExt, ".aac") == 0)
			result = (PSTR)"audio/aac";
		
		else if (_stricmp(szExt, ".oga") == 0)
			result = (PSTR)"audio/ogg";
		
		else if (_stricmp(szExt, ".mid") == 0 || _stricmp(szExt, ".midi") == 0)
			result = (PSTR)"audio/midi";

		else if (_stricmp(szExt, ".wav") == 0)
			result = (PSTR)"audio/x-wav";
		
		else if (_stricmp(szExt, ".ttf") == 0)
			result = (PSTR)"font/ttf";
		
		else if (_stricmp(szExt, ".woff") == 0)
			result = (PSTR)"font/woff";
		
		else if (_stricmp(szExt, ".woff2") == 0)
			result = (PSTR)"font/woff2";
	}
	
    return result;
}

//------------------------------------------------------------------------------------

void CloseHttpResponseFile ()
{
	if (g_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_hFile);
		g_hFile = INVALID_HANDLE_VALUE;
	}
}

//------------------------------------------------------------------------------------

void CloseHttpResponseThread ()
{
	CloseHttpResponseFile();

	if (g_hThread != NULL)
	{
		WaitForSingleObject(g_hThread, 500);

		if (g_bThreading)
		{
			TerminateThread(g_hThread, 0);
		    g_bThreading = FALSE;
		}

		CloseHandle(g_hThread);
		g_hThread = NULL;
	}
}

//------------------------------------------------------------------------------------

DWORD WINAPI HttpResponseThread (LPVOID lpParam) 
{ 
	HTTP_RESPONSE    response;
	HTTP_DATA_CHUNK  dataChunk;
	DWORD            bytesSent;
	std::wstring     wsAbsPath(g_pAbsPath);
	std::size_t      found;

	wsAbsPath.erase(0, 1);
	std::replace(wsAbsPath.begin(), wsAbsPath.end(), L'/', L'\\');
	wsAbsPath = g_wsRoot + wsAbsPath;
	
    if (PathIsDirectoryW(wsAbsPath.c_str()))
	{
		found = wsAbsPath.rfind(L'\\');
		if (found != wsAbsPath.length() - 1)
			wsAbsPath += L'\\';
		
		wsAbsPath += L"index.htm";
		if (!PathFileExistsW(wsAbsPath.c_str()))
			wsAbsPath += L"l";
	}

	g_hFile = CreateFileW
	(
		  wsAbsPath.c_str()
		, FILE_READ_DATA
		, 0
		, NULL
		, OPEN_EXISTING
		, 0
		, NULL 
	);
	
	RtlZeroMemory(&response, sizeof(HTTP_RESPONSE));

	if(g_hFile == INVALID_HANDLE_VALUE)
		response.StatusCode = 404;

	else
	{
		dataChunk.DataChunkType                                    = HttpDataChunkFromFileHandle;
		dataChunk.FromFileHandle.ByteRange.StartingOffset.QuadPart = 0;
		dataChunk.FromFileHandle.ByteRange.Length.QuadPart         = HTTP_BYTE_RANGE_TO_EOF;
		dataChunk.FromFileHandle.FileHandle                        = g_hFile;

		INITIALIZE_HTTP_RESPONSE(&response, 200, g_szOK);
		response.EntityChunkCount = 1;
		response.pEntityChunks    = &dataChunk;

		std::wstring wExtension(PathFindExtensionW(wsAbsPath.c_str()));
		ADD_KNOWN_HEADER
		(
			  response
			, HttpHeaderContentType
			, GetMimeType(WStringToString(wExtension))
		);
	}
	
	g_Result = HttpSendHttpResponse
	(
		  g_hReqQueue
		, g_RequestId
		, 0
		, &response
		, NULL
		, &bytesSent
		, NULL
		, 0
		, NULL
		, NULL
	);

	if (g_Result != NO_ERROR)
		g_mwsout << g_szError 
				 << "The http response sent in the thread failed!"
				 << g_szCode
				 << g_Result 
				 << "\n";

	CloseHttpResponseFile();
	g_bThreading = FALSE;
    return g_Result;
}

//------------------------------------------------------------------------------------

DWORD SendHttpResponse ()
{
	g_Result  = NO_ERROR;
	g_hThread = CreateThread
	(
		  NULL
        , 0
		, HttpResponseThread
		, NULL
        , 0
        , NULL
	);
	
	if (g_hThread != NULL)
	{
		g_bThreading = TRUE;
		WaitForSingleObject(g_hThread, 500);
	}
	
	else
	{
		g_mwsout << g_szError 
				 << "Could not create a thread to send the http response!"  
				 << g_szCode
				 << g_Result 
				 << "\n";
				  
		g_Result = ERROR_DS_THREAD_LIMIT_EXCEEDED;
	}
	
	return g_Result;
}

//------------------------------------------------------------------------------------

DWORD SendHttpResponse
(
	  IN USHORT      StatusCode
	, IN PSTR        pReason
	, IN PSTR        pEntity
){
	HTTP_RESPONSE    response;
	HTTP_DATA_CHUNK  dataChunk;
	DWORD            result;
	DWORD            bytesSent;

	INITIALIZE_HTTP_RESPONSE(&response, StatusCode, pReason);
	ADD_KNOWN_HEADER(response, HttpHeaderContentType, "text/plain");

	if (pEntity)
	{
		RtlZeroMemory(&dataChunk, sizeof(HTTP_DATA_CHUNK));

		dataChunk.DataChunkType           = HttpDataChunkFromMemory;
		dataChunk.FromMemory.pBuffer      = pEntity;
		dataChunk.FromMemory.BufferLength = (ULONG)strlen(pEntity);

		response.EntityChunkCount = 1;
		response.pEntityChunks    = &dataChunk;
	}

	result = HttpSendHttpResponse
	(
		  g_hReqQueue
		, g_RequestId
		, 0
		, &response
		, NULL
		, &bytesSent
		, NULL
		, 0
		, NULL
		, NULL
	);

	if (result != NO_ERROR)
		g_mwsout << g_szError 
				 << "The http response sent failed!" 
				 << g_szCode
				 << result 
				 << "\n";

	return result;
}

//------------------------------------------------------------------------------------

DWORD DoReceiveRequests ()
{
	ULONG              result;
	HTTP_REQUEST_ID    requestId;
	DWORD              bytesRead;
	PHTTP_REQUEST      pRequest;
	PCHAR              pRequestBuffer;
	ULONG              uRequestBufferLength;
	BOOL               bRequest  = TRUE;
	PCSTR              pRawValue = NULL;

	uRequestBufferLength = sizeof(HTTP_REQUEST) + 2048;
	pRequestBuffer = (PCHAR)ALLOC_MEM(uRequestBufferLength);

	if (pRequestBuffer == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	pRequest = (PHTTP_REQUEST)pRequestBuffer;
	HTTP_SET_NULL_ID(&requestId);

	while (bRequest)
	{
		RtlZeroMemory(pRequest, uRequestBufferLength);
		result = HttpReceiveHttpRequest
		(
			  g_hReqQueue
			, requestId
			, 0
			, pRequest
			, uRequestBufferLength
			, &bytesRead
			, NULL
		);

		if (result == NO_ERROR)
		{
			CloseHttpResponseThread();
			g_RequestId = pRequest->RequestId;
			g_pAbsPath  = pRequest->CookedUrl.pAbsPath;
			
            g_now  = std::chrono::system_clock::now();
			g_date = std::chrono::system_clock::to_time_t(g_now);
			g_mwsout << "\n" << std::ctime(&g_date);
			
			pRawValue = pRequest->Headers.KnownHeaders[HttpHeaderUserAgent].pRawValue;
			if (pRawValue)
				g_mwsout << "[User-Agent]: " << pRawValue << "\n";
			
			pRawValue = pRequest->Headers.KnownHeaders[HttpHeaderAccept].pRawValue;
			if (pRawValue)
				g_mwsout << "[Accept]: " << pRawValue << "\n";
			
			pRawValue = pRequest->Headers.KnownHeaders[HttpHeaderAcceptLanguage].pRawValue;
			if (pRawValue)
				g_mwsout << "[Accept-Language]: " << pRawValue << "\n";
			
			switch (pRequest->Verb)
			{
				case HttpVerbGET:
					g_mwsout << "[GET Request]: " 
							 << WStringToString(pRequest->CookedUrl.pFullUrl).c_str() 
							 << "\n";
						   
					if (wcscmp(g_pAbsPath, g_wsServerExit) == 0)
					{
						result = SendHttpResponse
						(
							  200
							, g_szOK
							, (PSTR)"[:\\]: Mini Web Server is no longer available!\r\n"
						);
						
						bRequest = FALSE;
					}
					
					else result = SendHttpResponse();
					break;

				default:
					g_mwsout << "[" << pRequest->Verb << " Request]: "
							 << WStringToString(pRequest->CookedUrl.pFullUrl).c_str() 
							 << "\n";

					result = SendHttpResponse
					(
						  503
						, (PSTR)"Not Implemented"
						, NULL
					);
					break;
			}

			if (result != NO_ERROR)
				break;

			HTTP_SET_NULL_ID(&requestId);
		}
		
		else if (result == ERROR_MORE_DATA)
		{
			FREE_MEM(pRequestBuffer);
			
			requestId            = pRequest->RequestId;
			uRequestBufferLength = bytesRead;
			pRequestBuffer       = (PCHAR)ALLOC_MEM(uRequestBufferLength);

			if (pRequestBuffer == NULL)
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			pRequest = (PHTTP_REQUEST)pRequestBuffer;
		}
		
		else if (result == ERROR_CONNECTION_INVALID && !HTTP_IS_NULL_ID(&requestId))
			HTTP_SET_NULL_ID(&requestId);
		
		else break;
	}

	if (pRequestBuffer)
		FREE_MEM(pRequestBuffer);
	
	return result;
}

//------------------------------------------------------------------------------------

void Help ()
{
	std::cout << " -------------------------------------------------\n"
			  << g_szAppName << "\n"
			  << " Created in 2019 by Jose A. Rojo L.\n"
			  << " -------------------------------------------------\n\n"
			  << " For more information you can see \"mws.pdf\" file.\n"
			  << " You can also go to https://github.com/jar0l/mws\n";
}

//------------------------------------------------------------------------------------

int main (int argc, char **argv)
{
	BOOL           bUrlAdded = FALSE;
	PCSTR          pRoot     = NULL;
	PCSTR          pLog      = NULL;
	std::size_t    nTmp      = 0;
	INTERNET_PORT  port      = 8080;
	std::wstring   fqUrl(L"http://localhost:8080/");
	HINTERNET      hIntSession;
	HINTERNET      hHttpSession;
	HINTERNET      hHttpRequest;
	
	if (argc < 2)
	{
		Help();	
		return 0;
	}
	
	else for (int i = 1; i < argc; i++)
	{
		if 
		(
			_stricmp(argv[1], "--help") == 0 || 
			_stricmp(argv[1], "-h") == 0     || 
			_stricmp(argv[1], "/?") == 0
		){
			Help();
			return 0;
		}
		
		else if (_stricmp(argv[i], "--stop") == 0)
		{
			if (++i < argc)
				fqUrl = StringToWString(argv[i]);
			
			if (fqUrl.empty())
			{
				std::cout << g_szError << g_szUrlError;
				return -2;
			}

			nTmp = fqUrl.length() - 1;
			if (fqUrl.rfind(L'/') ==  nTmp)
				fqUrl.erase(nTmp, 1);

			nTmp = fqUrl.rfind(L':');
			if (nTmp != std::wstring::npos && fqUrl.find(L'/') != nTmp + 1)
			{
				port = std::stoi(fqUrl.substr(nTmp + 1));
				fqUrl.erase(nTmp);
			}

			nTmp = fqUrl.rfind(L'/');
			if (nTmp != std::wstring::npos)
				fqUrl = fqUrl.substr(nTmp + 1);

			hIntSession = InternetOpenA
			(
				  g_szAppName
				, INTERNET_OPEN_TYPE_DIRECT
				, NULL
				, NULL
				, 0
			);
			
			nTmp = 1;
			if (hIntSession)
			{			
				hHttpSession = InternetConnectW
				(
					  hIntSession
					, fqUrl.c_str()
					, port
					, 0
					, 0
					, INTERNET_SERVICE_HTTP
					, 0
					, 0
				);
				
				if (hHttpSession)
				{				
					hHttpRequest = HttpOpenRequestW
					(
						  hHttpSession
						, L"GET" 
						, g_wsServerExit
						, 0
						, 0
						, 0
						, INTERNET_FLAG_RELOAD
						, 0
					);

					if (hHttpRequest)
					{
						if (HttpSendRequestA(hHttpRequest, "Content-Type: text/plain", 24, 0, 0))
							nTmp = 0;

						else std::cout << g_szError << "The server could not be stopped!\n";
						
						InternetCloseHandle(hHttpRequest);
					}

					InternetCloseHandle(hHttpSession);
				}
				
				InternetCloseHandle(hIntSession);
			}
			
			return nTmp;
		}
		
		else if (_stricmp(argv[i], "--log") == 0)
		{
			if (++i < argc)
				pLog = argv[i];
			
			else
			{
				std::cout << g_szError << "Log file name not specified!\n";
				return -3;
			}
		}
		
		else if (pRoot == NULL)
			pRoot = argv[i];
		
		else
		{
			fqUrl = StringToWString(pRoot);
			pRoot = argv[i];
			
			if (fqUrl.empty())
			{
				g_mwsout << g_szError << g_szUrlError;
				return -2;
			}
			
			nTmp = fqUrl.find(g_wsHttp);
			if(nTmp == std::wstring::npos)
				fqUrl = g_wsHttp + fqUrl;
			
			nTmp = fqUrl.rfind(L'/');
			if (nTmp != fqUrl.length() - 1)
				fqUrl += L'/';
		}
	}
	
	if (pLog != NULL && !g_mwsout.open(pLog))
		return -3;

	if (pRoot == NULL || strlen(pRoot) < 1 || !PathIsDirectoryA(pRoot))
	{
		std::cout << g_szError << "Invalid root directory!\n";
		return -3;
	}
	
	g_wsRoot = StringToWString(pRoot);
	nTmp     = g_wsRoot.rfind(L'\\');
	
	if (nTmp != g_wsRoot.length() - 1)
		g_wsRoot += L'\\';

	HTTPAPI_VERSION ver  = HTTPAPI_VERSION_1;
	ULONG           code = HttpInitialize(ver, HTTP_INITIALIZE_SERVER, NULL);

	if (code != NO_ERROR)
	{
		std::cout << g_szError << "Initialization failed!" << g_szCode << code << "\n";
		return code;
	}

	code = HttpCreateHttpHandle(&g_hReqQueue, 0);
	if (code != NO_ERROR)
	{
		std::cout << g_szError << "Create handle failed!" << g_szCode << code << "\n";
		goto CleanUp;
	}

    code = HttpAddUrl(g_hReqQueue, (PCWSTR)fqUrl.c_str(), NULL);
	if (code != NO_ERROR)
	{
		std::cout << g_szError << "Url failed!" << g_szCode << code << "\n";
		goto CleanUp;
	}

	bUrlAdded = TRUE;
    g_now     = std::chrono::system_clock::now();
	g_date    = std::chrono::system_clock::to_time_t(g_now);
	
	g_mwsout << std::ctime(&g_date)
			 << "[Listening Url]: " 
			 << WStringToString(fqUrl).c_str() 
			 << "\n";

	DoReceiveRequests();

CleanUp:

	if (bUrlAdded)
		HttpRemoveUrl(g_hReqQueue, (PCWSTR)fqUrl.c_str());

	if (g_hReqQueue)
		CloseHandle(g_hReqQueue);

	HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
	return code;
}
