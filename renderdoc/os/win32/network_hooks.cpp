/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2025 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <schannel.h>
#include <algorithm>
#include "core/core.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"

#include <string>
#include <vector>

// Network monitoring hooks for SSL/TLS and HTTP traffic
class NetworkHook : public LibraryHook
{
public:
  NetworkHook()
  {
    m_SSLConnections = 0;
    m_HTTPRequests = 0;
  }

  void RegisterHooks()
  {
    RDCLOG("Registering network monitoring hooks");

    // Register network libraries
    LibraryHooks::RegisterLibraryHook("wininet.dll", NULL);
    LibraryHooks::RegisterLibraryHook("schannel.dll", NULL);
    LibraryHooks::RegisterLibraryHook("crypt32.dll", NULL);
    LibraryHooks::RegisterLibraryHook("secur32.dll", NULL);

    // Hook HTTP functions
    HttpOpenRequestA.Register("wininet.dll", "HttpOpenRequestA", HttpOpenRequestA_hook);
    HttpOpenRequestW.Register("wininet.dll", "HttpOpenRequestW", HttpOpenRequestW_hook);
    HttpSendRequestA.Register("wininet.dll", "HttpSendRequestA", HttpSendRequestA_hook);
    HttpSendRequestW.Register("wininet.dll", "HttpSendRequestW", HttpSendRequestW_hook);
    InternetOpenA.Register("wininet.dll", "InternetOpenA", InternetOpenA_hook);
    InternetOpenW.Register("wininet.dll", "InternetOpenW", InternetOpenW_hook);

    // Hook SSL/TLS functions
    InternetConnectA.Register("wininet.dll", "InternetConnectA", InternetConnectA_hook);
    InternetConnectW.Register("wininet.dll", "InternetConnectW", InternetConnectW_hook);
    InternetReadFile.Register("wininet.dll", "InternetReadFile", InternetReadFile_hook);
    InternetWriteFile.Register("wininet.dll", "InternetWriteFile", InternetWriteFile_hook);

    // Hook SSL/TLS certificate functions
    CertOpenSystemStore.Register("crypt32.dll", "CertOpenSystemStore", CertOpenSystemStore_hook);
    CertFindCertificateInStore.Register("crypt32.dll", "CertFindCertificateInStore", CertFindCertificateInStore_hook);
  }

private:
  static NetworkHook networkhooks;

  int m_SSLConnections;
  int m_HTTPRequests;

  // HTTP Hook Functions
  HookedFunction<decltype(&HttpOpenRequestA)> HttpOpenRequestA;
  HookedFunction<decltype(&HttpOpenRequestW)> HttpOpenRequestW;
  HookedFunction<decltype(&HttpSendRequestA)> HttpSendRequestA;
  HookedFunction<decltype(&HttpSendRequestW)> HttpSendRequestW;
  HookedFunction<decltype(&InternetOpenA)> InternetOpenA;
  HookedFunction<decltype(&InternetOpenW)> InternetOpenW;
  HookedFunction<decltype(&InternetConnectA)> InternetConnectA;
  HookedFunction<decltype(&InternetConnectW)> InternetConnectW;
  HookedFunction<decltype(&InternetReadFile)> InternetReadFile;
  HookedFunction<decltype(&InternetWriteFile)> InternetWriteFile;
  HookedFunction<decltype(&CertOpenSystemStore)> CertOpenSystemStore;
  HookedFunction<decltype(&CertFindCertificateInStore)> CertFindCertificateInStore;

  static HINTERNET WINAPI HttpOpenRequestA_hook(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName,
                                               LPCSTR lpszVersion, LPCSTR lpszReferrer,
                                               LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
  {
    HINTERNET ret = networkhooks.HttpOpenRequestA()(hConnect, lpszVerb, lpszObjectName, lpszVersion, 
                                                   lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    
    if(ret)
    {
      networkhooks.m_HTTPRequests++;
      RDCLOG("[HTTP] %s %s", lpszVerb ? lpszVerb : "GET", lpszObjectName ? lpszObjectName : "/");
    }
    
    return ret;
  }

  static HINTERNET WINAPI HttpOpenRequestW_hook(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName,
                                               LPCWSTR lpszVersion, LPCWSTR lpszReferrer,
                                               LPCWSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
  {
    HINTERNET ret = networkhooks.HttpOpenRequestW()(hConnect, lpszVerb, lpszObjectName, lpszVersion, 
                                                   lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    
    if(ret)
    {
      networkhooks.m_HTTPRequests++;
      rdcstr verb = lpszVerb ? StringFormat::Wide2UTF8(lpszVerb) : "GET";
      rdcstr object = lpszObjectName ? StringFormat::Wide2UTF8(lpszObjectName) : "/";
      RDCLOG("[HTTP] %s %s", verb.c_str(), object.c_str());
    }
    
    return ret;
  }

  static BOOL WINAPI HttpSendRequestA_hook(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
                                         LPVOID lpOptional, DWORD dwOptionalLength)
  {
    BOOL ret = networkhooks.HttpSendRequestA()(hRequest, lpszHeaders, dwHeadersLength, 
                                              lpOptional, dwOptionalLength);
    
    if(ret && lpszHeaders)
    {
      RDCLOG("[HTTP] Headers: %s", lpszHeaders);
    }
    
    return ret;
  }

  static BOOL WINAPI HttpSendRequestW_hook(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
                                         LPVOID lpOptional, DWORD dwOptionalLength)
  {
    BOOL ret = networkhooks.HttpSendRequestW()(hRequest, lpszHeaders, dwHeadersLength, 
                                              lpOptional, dwOptionalLength);
    
    if(ret && lpszHeaders)
    {
      rdcstr headers = StringFormat::Wide2UTF8(lpszHeaders);
      RDCLOG("[HTTP] Headers: %s", headers.c_str());
    }
    
    return ret;
  }

  static HINTERNET WINAPI InternetOpenA_hook(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy,
                                           LPCSTR lpszProxyBypass, DWORD dwFlags)
  {
    HINTERNET ret = networkhooks.InternetOpenA()(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    
    if(ret)
    {
      RDCLOG("[HTTP] Internet session opened: %s", lpszAgent ? lpszAgent : "Unknown");
    }
    
    return ret;
  }

  static HINTERNET WINAPI InternetOpenW_hook(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy,
                                           LPCWSTR lpszProxyBypass, DWORD dwFlags)
  {
    HINTERNET ret = networkhooks.InternetOpenW()(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    
    if(ret)
    {
      rdcstr agent = lpszAgent ? StringFormat::Wide2UTF8(lpszAgent) : "Unknown";
      RDCLOG("[HTTP] Internet session opened: %s", agent.c_str());
    }
    
    return ret;
  }

  static HINTERNET WINAPI InternetConnectA_hook(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort,
                                               LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService,
                                               DWORD dwFlags, DWORD_PTR dwContext)
  {
    HINTERNET ret = networkhooks.InternetConnectA()(hInternet, lpszServerName, nServerPort, lpszUserName, 
                                                   lpszPassword, dwService, dwFlags, dwContext);
    
    if(ret)
    {
      networkhooks.m_SSLConnections++;
      RDCLOG("[SSL/TLS] Connection to %s:%d", lpszServerName ? lpszServerName : "Unknown", nServerPort);
    }
    
    return ret;
  }

  static HINTERNET WINAPI InternetConnectW_hook(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort,
                                               LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService,
                                               DWORD dwFlags, DWORD_PTR dwContext)
  {
    HINTERNET ret = networkhooks.InternetConnectW()(hInternet, lpszServerName, nServerPort, lpszUserName, 
                                                   lpszPassword, dwService, dwFlags, dwContext);
    
    if(ret)
    {
      networkhooks.m_SSLConnections++;
      rdcstr server = lpszServerName ? StringFormat::Wide2UTF8(lpszServerName) : "Unknown";
      RDCLOG("[SSL/TLS] Connection to %s:%d", server.c_str(), nServerPort);
    }
    
    return ret;
  }

  static BOOL WINAPI InternetReadFile_hook(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead,
                                          LPDWORD lpdwNumberOfBytesRead)
  {
    BOOL ret = networkhooks.InternetReadFile()(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    
    if(ret && lpBuffer && lpdwNumberOfBytesRead && *lpdwNumberOfBytesRead > 0)
    {
      // Log first 100 bytes of response
      DWORD logSize = std::min(*lpdwNumberOfBytesRead, (DWORD)100);
      rdcstr response = rdcstr((const char*)lpBuffer, logSize);
      RDCLOG("[HTTP] Response: %s", response.c_str());
    }
    
    return ret;
  }

  static BOOL WINAPI InternetWriteFile_hook(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToWrite,
                                          LPDWORD lpdwNumberOfBytesWritten)
  {
    BOOL ret = networkhooks.InternetWriteFile()(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    
    if(ret && lpBuffer && lpdwNumberOfBytesWritten && *lpdwNumberOfBytesWritten > 0)
    {
      // Log first 100 bytes of request
      DWORD logSize = std::min(*lpdwNumberOfBytesWritten, (DWORD)100);
      rdcstr request = rdcstr((const char*)lpBuffer, logSize);
      RDCLOG("[HTTP] Request: %s", request.c_str());
    }
    
    return ret;
  }

  static HCERTSTORE WINAPI CertOpenSystemStore_hook(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)
  {
    // Convert ANSI to Unicode for the real function
    std::wstring wSubsystemProtocol;
    if(szSubsystemProtocol)
    {
      int len = MultiByteToWideChar(CP_ACP, 0, szSubsystemProtocol, -1, NULL, 0);
      wSubsystemProtocol.resize(len - 1);
      MultiByteToWideChar(CP_ACP, 0, szSubsystemProtocol, -1, &wSubsystemProtocol[0], len);
    }
    
    HCERTSTORE ret = networkhooks.CertOpenSystemStore()(hProv, wSubsystemProtocol.c_str());
    
    if(ret)
    {
      RDCLOG("[SSL/TLS] Certificate store opened: %s", szSubsystemProtocol ? szSubsystemProtocol : "Unknown");
    }
    
    return ret;
  }

  static PCCERT_CONTEXT WINAPI CertFindCertificateInStore_hook(HCERTSTORE hCertStore, DWORD dwCertEncodingType,
                                                              DWORD dwFindFlags, DWORD dwFindType,
                                                              const void *pvFindPara, PCCERT_CONTEXT pPrevCertContext)
  {
    PCCERT_CONTEXT ret = networkhooks.CertFindCertificateInStore()(hCertStore, dwCertEncodingType, dwFindFlags, 
                                                                   dwFindType, pvFindPara, pPrevCertContext);
    
    if(ret)
    {
      RDCLOG("[SSL/TLS] Certificate found in store");
    }
    
    return ret;
  }
};

NetworkHook NetworkHook::networkhooks;
