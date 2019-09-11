# Mini Web Server (MWS)

**Introduction:**

MWS is a minimalist Web Server for Windows, based on the Microtoft [HTTP Server API](https://docs.microsoft.com/es-es/windows/win32/http/about-http-server-api) v1.0 and some [WinINet](https://docs.microsoft.com/es-es/windows/win32/wininet/about-wininet) functions, which provides a basic infrastructure to work with web pages locally.

**System requirements:** 

This application is a console executable for x86 processors, and it doesn’t require any installation process. Just copy the executable file to any folder you want, and run it with the desired command line option, according to your needs.

The minimum version of the recommended operating system is Windows Server 2003 with SP1 and Windows XP with SP2.

**Usage:**

        smws [url] root_directory
        dmws [url] root_directory

        lzsmws [url] root_directory
        lzdmws [url] root_directory
		
**Main arguments:**

        url                      (Optional) String that contains a properly formed
                                 [UrlPrefix](https://docs.microsoft.com/es-es/windows/win32/http/urlprefix-strings) that identifies the URL to be registered:
                                 http://host:port/
								 
        root_directory Root      directory that will serve as a web hosting.

**Other arguments:**

        --stop                   Stops the server from the specified URL. It isn't
                                 necessary to indicate the URL if the server was started
                                 with "http://localhost:8080/" by default.
								 
        --log                    Log server operations in the specified file.
		
**Examples:**

        smws "..\My Root Folder"
        start http://localhost:8080
        smws --stop
		
        smws "..\My Root Folder" –-log "D:\Mi Log Folder\My Log File.txt"
        start http://localhost:8080
        smws --stop
		
        smws 127.0.0.1:8080 www-root –-log mws-log.txt
        start http://127.0.0.1:8080
        smws --stop 127.0.0.1:8080
		
