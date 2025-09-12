#include <iostream>
#include <windows.h>
#include <random>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <cwchar>
#include <cwctype>
#include <stdio.h>
#include <io.h>
#include <cstdlib>
#include <limits>
#include <winioctl.h>

// Minimal storage property query definitions (avoid ntddstor.h dependency)
#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#define IOCTL_STORAGE_QUERY_PROPERTY  CTL_CODE(IOCTL_STORAGE_BASE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageDeviceSeekPenaltyProperty = 7
} STORAGE_PROPERTY_ID;

typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0
} STORAGE_QUERY_TYPE;

typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE QueryType;
    BYTE AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef struct _DEVICE_SEEK_PENALTY_DESCRIPTOR {
    DWORD Version;
    DWORD Size;
    BOOLEAN IncursSeekPenalty;
} DEVICE_SEEK_PENALTY_DESCRIPTOR, *PDEVICE_SEEK_PENALTY_DESCRIPTOR;
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <mutex>
#include <fstream>
#ifndef TOKEN_ELEVATION
typedef struct _TOKEN_ELEVATION {
    DWORD TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;
#endif

#ifndef TokenElevation
#define TokenElevation ((TOKEN_INFORMATION_CLASS) 20)
#endif

class SimpleMutex {
// RAII HANDLE wrapper
private:
    CRITICAL_SECTION cs;
public:
    SimpleMutex() { InitializeCriticalSection(&cs); }
    ~SimpleMutex() { DeleteCriticalSection(&cs); }
    void lock() { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
};

template<typename Mutex>
class simple_lock_guard {
private:
    Mutex& m;
public:
    explicit simple_lock_guard(Mutex& mutex) : m(mutex) { m.lock(); }
    ~simple_lock_guard() { m.unlock(); }
};


// Core function prototypes (refactored)
void listDrives();
bool FillRandom(BYTE* buffer, DWORD size, std::minstd_rand& rng);
bool FillRandom(BYTE* buffer, DWORD size, std::mt19937& rng);
bool IsValidDrive(wchar_t driveLetter);
bool getVolumeSize(wchar_t driveLetter, ULARGE_INTEGER& totalSize, ULARGE_INTEGER& freeSize);
void displayProgressBar(unsigned long long completed, unsigned long long total, const std::string& operation);
bool SendTrim(wchar_t driveLetter);
bool IsNTFS(wchar_t driveLetter);
bool OnePassHeaderWipe(const std::wstring& volumePath, unsigned long long bytes);
bool FormatDrive(wchar_t driveLetter, const std::wstring& fsType, const std::wstring& label);
void FillDriveAccumulate(wchar_t driveLetter);
bool QuickPassCycle(wchar_t driveLetter, const std::wstring& fsType, const std::wstring& label, bool doFiles);
void ParallelFill(wchar_t driveLetter, const std::wstring& fsType, size_t threads);

#if ENABLE_EXTRA_WIPES
void wipeEmptySpace(wchar_t driveLetter);
bool WipeMFT(const std::wstring& volumePath);
void SinglePassFileScatter(wchar_t driveLetter);
bool PerformOption1Sequence(wchar_t driveLetter, const std::wstring& fsType, const std::wstring& label);
void FullDriveRandomFill(wchar_t driveLetter);
#endif

SimpleMutex mtx;
volatile bool diskFull = false;

std::wstring generateRandomString(size_t length, std::minstd_rand& rng) {
    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::wstring result;
    std::uniform_int_distribution<> dist(0, sizeof(charset) / sizeof(wchar_t) - 2);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dist(rng)];
    }
    return result;
}

bool getVolumeSize(wchar_t driveLetter, ULARGE_INTEGER& totalSize, ULARGE_INTEGER& freeSize) {
    std::wstring volumePath = std::wstring(1, driveLetter) + L":\\";
    if (!GetDiskFreeSpaceExW(volumePath.c_str(), &freeSize, &totalSize, NULL)) {
        std::wcerr << L"[-] Error getting volume size for " << volumePath << L": " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

void displayProgressBar(unsigned long long completed, unsigned long long total, const std::string& operation) {
    simple_lock_guard<SimpleMutex> lock(mtx);
    const int barWidth = 70;
    float progress = total > 0 ? std::min(static_cast<float>(completed) / total, 1.0f) : 0.0f;
    std::cout << "\r[" << operation << "] [";
    int pos = static_cast<int>(barWidth * progress);
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << static_cast<int>(progress * 100.0) << " %";
    std::cout.flush();
}

bool FillRandom(BYTE* buffer, DWORD size, std::minstd_rand& rng) {
    std::uniform_int_distribution<BYTE> dist(0, 255);
    std::generate(buffer, buffer + size, [&]() { return dist(rng); });
    return true;
}

bool FillRandom(BYTE* buffer, DWORD size, std::mt19937& rng) {
    std::uniform_int_distribution<> dist(0, 255);
    for (DWORD i = 0; i < size; ++i) {
        buffer[i] = static_cast<BYTE>(dist(rng));
    }
    return true;
}

bool IsNTFS(wchar_t driveLetter) {
    std::wstring volumePath = std::wstring(1, driveLetter) + L":\\";
    WCHAR fileSystemName[MAX_PATH + 1];
    if (!GetVolumeInformationW(volumePath.c_str(), NULL, 0, NULL, NULL, NULL, fileSystemName, MAX_PATH + 1)) {
        std::wcerr << L"[-] Failed to get filesystem type for " << volumePath << L": " << GetLastError() << L"\n";
        return false;
    }
    return wcscmp(fileSystemName, L"NTFS") == 0;
}

void wipeEmptySpace(wchar_t driveLetter) {
    ULARGE_INTEGER totalSize, freeSize;
    if (!getVolumeSize(driveLetter, totalSize, freeSize)) {
        return;
    }

    unsigned long long totalFreeSpace = freeSize.QuadPart;
    unsigned long long completedTasks = 0;
    std::random_device rd;
    std::minstd_rand rng(rd()); 

    const size_t fileSize = 32 * 1024 * 1024; 
    size_t maxFiles = std::min(static_cast<size_t>(totalFreeSpace / fileSize), static_cast<size_t>(16384));
    std::vector<std::wstring> createdFiles;
    std::vector<std::wstring> createdFolders;
    createdFiles.reserve(maxFiles);
    createdFolders.reserve(maxFiles / 20); 

    std::wcout << L"[*] Creating and wiping " << maxFiles << L" 32 MB files across multiple folders on drive " << driveLetter << L"\n";

    const size_t bufferSize = 2 * 1024 * 1024; 
    std::vector<BYTE> buffer(bufferSize);
    
    
    FillRandom(buffer.data(), bufferSize, rng);
    
    bool writeFailed = false;
    size_t filesCreated = 0;
    const size_t filesPerFolder = 25; 

    while (filesCreated < maxFiles && !diskFull && !writeFailed) {
        std::wstring folderName = std::wstring(1, driveLetter) + L":\\" + generateRandomString(80, rng); 
        if (!CreateDirectoryW(folderName.c_str(), NULL)) {
            std::wcerr << L"[-] Failed to create folder: " << folderName << L", Error: " << GetLastError() << L"\n";
            writeFailed = true;
            break;
        }
        createdFolders.push_back(folderName);
        size_t filesInThisFolder = std::min(filesPerFolder, maxFiles - filesCreated);

        for (size_t i = 0; i < filesInThisFolder && !diskFull && !writeFailed; ++i) {
            if (filesCreated % 5 == 0) {
                ULARGE_INTEGER currentFreeSize;
                if (!getVolumeSize(driveLetter, totalSize, currentFreeSize)) {
                    std::wcerr << L"[-] Failed to get volume size during wipe: Error " << GetLastError() << L"\n";
                    diskFull = true;
                    break;
                }

                if (currentFreeSize.QuadPart < fileSize * 2) { 
                    simple_lock_guard<SimpleMutex> lock(mtx);
                    diskFull = true;
                    totalFreeSpace = completedTasks;
                    break;
                }
            }

            std::wstring fileName = folderName + L"\\" + generateRandomString(12, rng) + L"." + generateRandomString(8, rng);
            HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL); 
            if (hFile == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Failed to create file: " << fileName << L", Error: " << GetLastError() << L"\n";
                writeFailed = true;
                break;
            }

            size_t bytesWritten = 0;
            bool fileSuccess = true;
            size_t iterations = fileSize / bufferSize;
            
            for (size_t j = 0; j < iterations && fileSuccess; ++j) {
                if (j % 4 == 0) {
                    FillRandom(buffer.data(), bufferSize, rng);
                }
                
                DWORD bytesTransferred;
                if (!WriteFile(hFile, buffer.data(), bufferSize, &bytesTransferred, NULL) || bytesTransferred != bufferSize) {
                    std::wcerr << L"[-] Failed to write to file: " << fileName << L", Error: " << GetLastError() << L"\n";
                    fileSuccess = false;
                    writeFailed = true;
                    break;
                }
                bytesWritten += bytesTransferred;
            }

            
            FlushFileBuffers(hFile);
            CloseHandle(hFile);
            if (fileSuccess) {
                createdFiles.push_back(fileName);
                completedTasks += bytesWritten;
                filesCreated++;
            } else {
                DeleteFileW(fileName.c_str());
                break;
            }
            
            
            if (filesCreated % 3 == 0) {
                displayProgressBar(completedTasks, totalFreeSpace, "Wipe Empty Space");
            }
        }
    }
    size_t deletedFiles = 0;
    for (const auto& file : createdFiles) {
        SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(file.c_str())) {
            deletedFiles++;
        } else {
            std::wcerr << L"[-] Failed to delete file: " << file << L", Error: " << GetLastError() << L"\n";
        }
    }
    size_t deletedFolders = 0;
    for (const auto& folder : createdFolders) {
        SetFileAttributesW(folder.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (RemoveDirectoryW(folder.c_str())) {
            deletedFolders++;
        } else {
            std::wcerr << L"[-] Failed to remove folder: " << folder << L", Error: " << GetLastError() << L"\n";
        }
    }
    if (diskFull || writeFailed || completedTasks >= totalFreeSpace) {
        completedTasks = totalFreeSpace;
    }
    displayProgressBar(completedTasks, totalFreeSpace, "Wipe Empty Space");
    std::cout << std::endl;
    if (diskFull || writeFailed) {
        std::cout << "[!] Wiping stopped: Disk is full or an error occurred.\n";
    } else {
        std::wcout << L"[+] Wiped empty space on drive " << driveLetter << L" with " << deletedFiles << L" 1 MB files across " << deletedFolders << L" folders\n";
    }
    std::cout << "[+] Deleted " << deletedFiles << " of " << createdFiles.size() << " files and " << deletedFolders << " of " << createdFolders.size() << " folders.\n";
}

void wipeExistingFiles(wchar_t driveLetter) {
    std::random_device rd;
    std::minstd_rand rng(rd());
    std::vector<std::wstring> fileList;
    unsigned long long processedFiles = 0;
    unsigned long long totalFiles = 0;

    std::function<void(const std::wstring&)> collectFiles = [&](const std::wstring& currentPath) {
        std::wstring searchPath = currentPath + (currentPath.back() == L'\\' ? L"" : L"\\") + L"*.*";
        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        std::vector<std::wstring> subDirs;
        do {
            const wchar_t* name = findFileData.cFileName;
            if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0) continue;
            std::wstring fullPath = currentPath + (currentPath.back() == L'\\' ? L"" : L"\\") + name;
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (std::wstring(name) != L"$RECYCLE.BIN" && std::wstring(name) != L"System Volume Information") {
                    subDirs.push_back(fullPath);
                }
            } else {
                fileList.push_back(fullPath);
                totalFiles++;
            }
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);

        for (const auto& dir : subDirs) {
            collectFiles(dir);
        }
    };

    std::wstring rootPath = std::wstring(1, driveLetter) + L":\\";
    collectFiles(rootPath);

    if (totalFiles == 0) {
        std::cout << "[*] No accessible files found to wipe on drive " << (char)driveLetter << ":\n";
        return;
    }

    unsigned long long completedTasks = 0;
    unsigned long long totalTasks = totalFiles * 4;
    std::cout << "[*] File Wipe Operation Started (" << totalFiles << " files to process).\n";

    for (const auto& fullPath : fileList) {
        SetFileAttributesW(fullPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[-] Failed to open file: " << fullPath << L", Error: " << GetLastError() << L"\n";
            continue;
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            std::wcerr << L"[-] Failed to get size of file: " << fullPath << L", Error: " << GetLastError() << L"\n";
            CloseHandle(hFile);
            continue;
        }

        std::vector<BYTE> buffer(1024 * 1024);
        bool wipeSuccess = true;

        
        for (int pass = 0; pass < 2 && wipeSuccess; ++pass) {
            LARGE_INTEGER li = {0};
            if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN)) {
                std::wcerr << L"[-] Failed to set file pointer for: " << fullPath << L", Error: " << GetLastError() << L"\n";
                wipeSuccess = false;
                break;
            }

            for (LONGLONG offset = 0; offset < fileSize.QuadPart; offset += buffer.size()) {
                DWORD bytesToWrite = static_cast<DWORD>(std::min(static_cast<LONGLONG>(buffer.size()), fileSize.QuadPart - offset));
                
                
                if (pass == 0) {
                    
                    if (offset % (buffer.size() * 8) == 0) {
                        FillRandom(buffer.data(), bytesToWrite, rng);
                    }
                } else {
                    
                    std::fill(buffer.begin(), buffer.begin() + bytesToWrite, 0x00);
                }

                DWORD bytesWritten;
                if (!WriteFile(hFile, buffer.data(), bytesToWrite, &bytesWritten, NULL) || bytesWritten != bytesToWrite) {
                    std::wcerr << L"[-] Failed to write pass " << pass + 1 << L" for: " << fullPath << L", Error: " << GetLastError() << L"\n";
                    wipeSuccess = false;
                    break;
                }
            }

            
            if (pass == 1 && !FlushFileBuffers(hFile)) {
                std::wcerr << L"[-] Failed to flush file: " << fullPath << L", Error: " << GetLastError() << L"\n";
                wipeSuccess = false;
            }

            if (wipeSuccess) {
                completedTasks++;
            }
        }

        CloseHandle(hFile);

        if (wipeSuccess) {
            
            std::wstring tempName = fullPath.substr(0, fullPath.find_last_of(L'\\') + 1) + generateRandomString(8, rng) + L"." + generateRandomString(8, rng);
            if (MoveFileW(fullPath.c_str(), tempName.c_str())) {
                completedTasks++;
                if (DeleteFileW(tempName.c_str())) {
                    completedTasks++;
                } else {
                    std::wcerr << L"[-] Failed to delete file: " << tempName << L", Error: " << GetLastError() << L"\n";
                }
            } else {
                std::wcerr << L"[-] Failed to rename file: " << fullPath << L", Error: " << GetLastError() << L"\n";
            }
        }

        processedFiles++; 
        if (processedFiles % 25 == 0) { 
            displayProgressBar(completedTasks, totalTasks, "Wipe Files");
        }
    }

    std::function<void(const std::wstring&)> removeDirs = [&](const std::wstring& currentPath) {
        std::wstring searchPath = currentPath + (currentPath.back() == L'\\' ? L"" : L"\\") + L"*.*";
        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        std::vector<std::wstring> subDirs;
        do {
            const wchar_t* name = findFileData.cFileName;
            if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0) continue;
            std::wstring fullPath = currentPath + (currentPath.back() == L'\\' ? L"" : L"\\") + name;
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (std::wstring(name) != L"$RECYCLE.BIN" && std::wstring(name) != L"System Volume Information") {
                    subDirs.push_back(fullPath);
                }
            }
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);

        for (const auto& dir : subDirs) {
            removeDirs(dir);
        }

        if (currentPath == rootPath) {
            return;
        }

        SetFileAttributesW(currentPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (!RemoveDirectoryW(currentPath.c_str())) {
            DWORD error = GetLastError();
            if (error != ERROR_DIR_NOT_EMPTY) { 
                std::wcerr << L"[-] Failed to remove directory: " << currentPath << L", Error: " << error << L"\n";
            }
        }
    };

    removeDirs(rootPath);

    displayProgressBar(completedTasks, totalTasks, "Wipe Files");
    std::cout << "\r" << std::string(100, ' ') << "\r"; 
    std::cout << "[+] Completed wiping, renaming, and deleting " << processedFiles << " of " << totalFiles << " accessible files and folders on drive " << (char)driveLetter << ":\n";
}


bool WipeMFT(const std::wstring& volumePath) {
    HANDLE hVolume = CreateFileW(
        volumePath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        NULL
    );

    if (hVolume == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to open volume " << volumePath << L". Error: " << GetLastError() << std::endl;
        std::wcerr << L"    Make sure you are running as Administrator and the drive is not in use." << std::endl;
        return false;
    }

    DWORD bytesReturned;
    if (!DeviceIoControl(hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        std::wcerr << L"[-] Failed to lock volume " << volumePath << L". It may be in use. Error: " << GetLastError() << std::endl;
        CloseHandle(hVolume);
        return false;
    }

    if (!DeviceIoControl(hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        std::wcerr << L"[-] Failed to dismount volume " << volumePath << L". Error: " << GetLastError() << std::endl;
        DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        CloseHandle(hVolume);
        return false;
    }

    std::wcout << L"[*] Volume locked and dismounted. Proceeding with low-level wipe." << std::endl;

    LARGE_INTEGER startOffset = {0};
    if (!SetFilePointerEx(hVolume, startOffset, NULL, FILE_BEGIN)) {
        std::wcerr << L"[-] Failed to seek to the beginning of the volume " << volumePath << L". Error: " << GetLastError() << std::endl;
        DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        CloseHandle(hVolume);
        return false;
    }

    const DWORD wipeSize = 1024 * 1024 * 4; // Overwrite the first 4MB of the drive
    std::vector<BYTE> buffer(wipeSize);
    
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<BYTE> dist(0, 255);
    std::generate(buffer.begin(), buffer.end(), [&]() { return dist(rng); });

    DWORD bytesWritten;
    if (!WriteFile(hVolume, buffer.data(), wipeSize, &bytesWritten, NULL) || bytesWritten != wipeSize) {
        std::wcerr << L"[-] Failed to perform low-level write on " << volumePath << L". Error: " << GetLastError() << std::endl;
        DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        CloseHandle(hVolume);
        return false;
    }

    std::wcout << L"[+] Successfully overwrote " << bytesWritten << " bytes at the beginning of " << volumePath << std::endl;
    
    DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    CloseHandle(hVolume);
    return true;
}

bool SendTrim(wchar_t driveLetter) {
    std::string command = "defrag ";
    command += (char)driveLetter;
    command += ": /L";  

    std::cout << "[*] Running TRIM on drive " << (char)driveLetter << "...\n";
    int result = system(command.c_str());
    
    if (result == 0) {
        std::cout << "[+] TRIM completed successfully on " << (char)driveLetter << ":\n";
        return true;
    } else {
        std::cerr << "[-] TRIM failed on drive " << (char)driveLetter << " (exit code " << result << ")\n";
        return false;
    }
}

void listDrives() {
    std::cout << "Available drives:" << std::endl;
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        std::wstring drivePath = std::wstring(1, drive) + L":\\";
        DWORD dwAttrib = GetFileAttributesW(drivePath.c_str());
        if (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wcout << drive << L": " << drivePath << std::endl;
        }
    }
}

bool IsValidDrive(wchar_t driveLetter) {
    std::wstring drivePath = std::wstring(1, towupper(driveLetter)) + L":\\";
    DWORD dwAttrib = GetFileAttributesW(drivePath.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Added forward declarations for new helpers
struct Config { bool simulate=false; bool forceSystem=false; bool trimAtEnd=true; unsigned long long headerWipeSize=1024ULL*1024ULL; };
static Config gConfig;

bool IsSystemDrive(wchar_t d) {
    wchar_t winDir[MAX_PATH];
    if(GetWindowsDirectoryW(winDir, MAX_PATH)) return towupper(d)==towupper(winDir[0]);
    return false;
}
bool IsLikelySSD(wchar_t driveLetter) {
    std::wstring volPath = L"\\\\.\\" + std::wstring(1, driveLetter) + L":";
    HANDLE h = CreateFileW(volPath.c_str(), 0, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    STORAGE_PROPERTY_QUERY q{}; q.PropertyId = StorageDeviceSeekPenaltyProperty; q.QueryType = PropertyStandardQuery; DEVICE_SEEK_PENALTY_DESCRIPTOR dsc{}; DWORD br=0;
    bool ssd=false; if(DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q,sizeof(q), &dsc,sizeof(dsc), &br, NULL)) { if(!dsc.IncursSeekPenalty) ssd=true; }
    CloseHandle(h); return ssd;
}
void PrintSSDNUKELogo() {
    std::cout << R"(

__| |__________________________________________________________________________| |__
__   __________________________________________________________________________   __
  | |                                                                          | |  
  | | ____    _  _____  _      ____   ____ ____  _   _ ____  ____  _____ ____  | |  
  | ||  _ \  / \|_   _|/ \    / ___| / ___|  _ \| | | | __ )| __ )| ____|  _ \ | |  
  | || | | |/ _ \ | | / _ \   \___ \| |   | |_) | | | |  _ \|  _ \|  _| | |_) || |  
  | || |_| / ___ \| |/ ___ \   ___) | |___|  _ <| |_| | |_) | |_) | |___|  _ < | |  
  | ||____/_/   \_|_/_/   \_\ |____/ \____|_| \_\\___/|____/|____/|_____|_| \_\| |  
__| |__________________________________________________________________________| |__
__   __________________________________________________________________________   __
  | |                                                                          | |  
                                   By: Om Makwana
)" << std::endl;
}


static void PrintUsage() {
    std::cout << "Usage: KABOOM.exe [options]\n"
              << "  --simulate            Dry run (no format / overwrite)\n"
              << "  --force-system        Allow wiping system drive\n"
              << "  --header-bytes=N      Set header wipe bytes (default 1048576)\n"
              << "  --no-trim             Skip TRIM on SSD after completion\n"
              << "  --help                Show this help and exit\n\n";
}
static void ParseArgs(int argc, char* argv[]) {
    for(int i=1;i<argc;i++) {
        std::string a(argv[i]);
        if(a=="--simulate") gConfig.simulate=true; else if(a=="--force-system") gConfig.forceSystem=true; else if(a=="--no-trim") gConfig.trimAtEnd=false; else if(a.rfind("--header-bytes=",0)==0) {
            try { gConfig.headerWipeSize = std::stoull(a.substr(15)); if(!gConfig.headerWipeSize) gConfig.headerWipeSize=1024ULL*1024ULL; } catch(...) {}
        } else if(a=="--help"||a=="-h") { PrintUsage(); exit(0);} }
}
int main(int argc, char* argv[]) {
    ParseArgs(argc, argv);
    PrintSSDNUKELogo();

    std::cout << "\n============================================\n";
    std::cout << "WARNING: Misuse of this application may cause\n";
    std::cout << "         irreversible data loss.\n";
    std::cout << "         Proceed at your own risk.\n";
    std::cout << "============================================\n\n";

    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    if (!isElevated) {
        std::cerr << "[-] This program requires administrative privileges. Please run as Administrator.\n";
        return 1;
    }

    if(gConfig.simulate) std::cout << "[SIMULATION MODE ENABLED]\n";
    int choice = 0;
    std::cout << "Select Wipe Method:\n\n";
    std::cout << "  1. Low Security (MFT Destruction)    \n";
    std::cout << "  2. Medium Security (Wipe all data + MFT Destruction)\n";
    std::cout << "  3. High Security   (Wipe all data + Empty Space + MFT Destruction)\n";
    std::cout << "\nEnter choice (1-3): ";
    std::cin >> choice;

    if (choice < 1 || choice > 3) {
        std::cerr << "[-] Invalid option selected.\n";
        return 1;
    }

    int fsChoice = 0;
    std::cout << "\nSelect target filesystem after wipe (will format):\n";
    std::cout << "  1. NTFS\n";
    std::cout << "  2. exFAT\n";
    std::cout << "  3. FAT32\n";
    std::cout << "Enter choice (1-3): ";
    std::cin >> fsChoice;
    if (fsChoice < 1 || fsChoice > 3) { std::cerr << "[-] Invalid filesystem choice.\n"; return 1; }
    std::wstring fsType = (fsChoice==1?L"NTFS":(fsChoice==2?L"exFAT":L"FAT32"));
    std::wstring fsLabel = L"WIPED";

    listDrives();
    char driveLetter;
    std::cout << "\nEnter the drive letter (e.g., 'D') for Wipe: ";
    std::cin >> driveLetter;
    wchar_t wDriveLetter = towupper(static_cast<wchar_t>(driveLetter));

    if (!IsValidDrive(wDriveLetter)) {
        std::cerr << "[-] Invalid or inaccessible drive: " << driveLetter << "\n";
        return 1;
    }
    if(IsSystemDrive(wDriveLetter) && !gConfig.forceSystem) { std::cerr << "[!] Refusing system drive (use --force-system to override).\n"; return 1; }
    ULARGE_INTEGER totalSize{}, freeSize{}; getVolumeSize(wDriveLetter,totalSize,freeSize);
    bool ssd = IsLikelySSD(wDriveLetter);
    std::wstring fsExisting=L"Unknown"; WCHAR fsBuf[MAX_PATH+1]; std::wstring root=std::wstring(1,wDriveLetter)+L":\\"; if(GetVolumeInformationW(root.c_str(),NULL,0,NULL,NULL,NULL,fsBuf,MAX_PATH+1)) fsExisting=fsBuf;
    std::cout << "\nDrive Summary:\n";
    std::wcout << L"  Drive: " << wDriveLetter << L":\\ Current FS: " << fsExisting << L" Target FS: " << fsType << L"\n";
    std::cout << "  Size: " << (unsigned long long)(totalSize.QuadPart/ (1024ULL*1024ULL*1024ULL)) << " GB  Free: " << (unsigned long long)(freeSize.QuadPart/(1024ULL*1024ULL*1024ULL)) << " GB\n";
    std::cout << "  Media: " << (ssd?"SSD":"HDD/Unknown") << "  Cycles: " << (choice==1?1:(choice==2?2:3)) << "  HeaderBytes: " << gConfig.headerWipeSize << "\n";
    if(gConfig.simulate) std::cout << "  MODE: SIMULATION (no destructive ops)\n";
    std::cout << "\nType YES to confirm: "; std::string confirm; std::cin >> confirm; if(confirm != "YES") { std::cout << "Aborted.\n"; return 0; }
    std::cout << "[*] Starting wipe operations on drive " << driveLetter << "...\n";

    // Remove old final format + unified post message: moved after cycles
    
    int cycles = (choice == 1 ? 1 : (choice == 2 ? 2 : 3));
    for(int i=0;i<cycles;i++) {
        std::cout << "[*] Cycle " << (i+1) << "/" << cycles << "...\n";
        if(!QuickPassCycle(wDriveLetter, fsType, fsLabel, true)) { std::cerr << "[!] Cycle failed.\n"; break; }
    }
    if(!gConfig.simulate) FormatDrive(wDriveLetter, fsType, fsLabel);
    if(!gConfig.simulate && gConfig.trimAtEnd && ssd) { std::cout << "[*] SSD detected: issuing TRIM...\n"; SendTrim(wDriveLetter); }

    std::cout << "\r" << std::string(100, ' ') << "\r";
    std::cout << "[+] Multi-cycle operation completed.\n";
    std::wcout << L"[+] Final filesystem: " << fsType << L"\n";
    std::cout << "\nPress ENTER to exit...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    return 0;
}

bool QuickPassCycle(wchar_t driveLetter, const std::wstring& fsType, const std::wstring& label, bool doFiles) {
    if(!gConfig.simulate && !FormatDrive(driveLetter, fsType, label)) return false;
    if(doFiles) {
#if defined(_GLIBCXX_HAS_GTHREADS) || defined(_MSC_VER)
        ParallelFill(driveLetter, fsType, 2);
#else
        FillDriveAccumulate(driveLetter);
#endif
    }
    std::wstring volumePath = L"\\\\.\\" + std::wstring(1, driveLetter) + L":";
    if(!gConfig.simulate) OnePassHeaderWipe(volumePath, gConfig.headerWipeSize);
    return true;
}
bool OnePassHeaderWipe(const std::wstring& volumePath, unsigned long long bytes) {
    if(bytes==0) return true;
    HANDLE hVolume = CreateFileW(volumePath.c_str(), GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                                 FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Header wipe: open failed for " << volumePath << L" Error: " << GetLastError() << L"\n";
        return false;
    }
    DWORD bytesReturned;
    if (!DeviceIoControl(hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL)) { CloseHandle(hVolume); return false; }
    DeviceIoControl(hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    LARGE_INTEGER startOffset; startOffset.QuadPart = 0; if(!SetFilePointerEx(hVolume, startOffset, NULL, FILE_BEGIN)) { DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME, NULL,0,NULL,0,&bytesReturned,NULL); CloseHandle(hVolume); return false; }
    const size_t chunk = 1024*1024; std::vector<BYTE> buffer(chunk); std::random_device rd; std::mt19937 rng(rd()); std::uniform_int_distribution<int> dist(0,255);
    unsigned long long remaining = bytes; DWORD wrote=0; bool ok=true; while(remaining>0) { size_t thisWrite = (size_t)std::min<unsigned long long>(remaining, buffer.size()); std::generate(buffer.begin(), buffer.begin()+thisWrite, [&](){return (BYTE)dist(rng);}); if(!WriteFile(hVolume, buffer.data(), (DWORD)thisWrite, &wrote, NULL) || wrote!=thisWrite){ ok=false; break;} remaining -= wrote; }
    DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL); CloseHandle(hVolume); return ok;
}

void SinglePassFileScatter(wchar_t driveLetter) {
    ULARGE_INTEGER totalSize, freeSize; if(!getVolumeSize(driveLetter,totalSize,freeSize)) return; 
    std::random_device rd; std::minstd_rand rng(rd());
    const size_t fileSize = 4 * 1024 * 1024; // 4MB files
    size_t maxFiles = (size_t)std::min<unsigned long long>(freeSize.QuadPart / fileSize, 256ULL);
    if(maxFiles==0) return;
    const size_t bufferSize = 1 * 1024 * 1024;
    std::vector<BYTE> buffer(bufferSize);
    FillRandom(buffer.data(), (DWORD)bufferSize, rng);
    size_t created=0; unsigned long long writtenTotal=0;
    while(created < maxFiles) {
        std::wstring fileName = std::wstring(1, driveLetter) + L":\\" + generateRandomString(12, rng) + L".tmp";
        HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if(hFile==INVALID_HANDLE_VALUE) break;
        size_t iterations = fileSize / bufferSize;
        for(size_t i=0;i<iterations;i++) {
            if(i % 4 == 0) FillRandom(buffer.data(), (DWORD)bufferSize, rng);
            DWORD bw; if(!WriteFile(hFile, buffer.data(), (DWORD)bufferSize, &bw, NULL) || bw != bufferSize) { break; }
            writtenTotal += bw;
        }
        FlushFileBuffers(hFile); CloseHandle(hFile);
        SetFileAttributesW(fileName.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(fileName.c_str());
        created++;
        if(created % 8 == 0) displayProgressBar(writtenTotal, freeSize.QuadPart, "Scatter Pass");
        if(writtenTotal > freeSize.QuadPart * 9 / 10) break;
    }
    displayProgressBar(freeSize.QuadPart, freeSize.QuadPart, "Scatter Pass"); std::cout << "\n";
}

bool PerformOption1Sequence(wchar_t driveLetter, const std::wstring& fsType, const std::wstring& label) {
    // Reordered: initial full format -> file fill -> destructive header wipe -> final format
    std::wstring volumePath = L"\\\\.\\" + std::wstring(1, driveLetter) + L":";
    std::wcout << L"[*] Phase 0: Initial format to prepare filesystem...\n";
    if(!FormatDrive(driveLetter, fsType, label)) {
        std::wcerr << L"[!] Initial format failed; aborting Option 1 sequence.\n";
        return false;
    }
    std::wcout << L"[*] Phase 1: Accumulate random files until space is nearly exhausted...\n";
    FillDriveAccumulate(driveLetter);
    std::wcout << L"[*] Phase 2: Destructive header wipe (filesystem will be lost)...\n";
    OnePassHeaderWipe(volumePath, 1024ULL*1024ULL);
    std::wcout << L"[*] Phase 3: Final format restoring filesystem...\n";
    if(!FormatDrive(driveLetter, fsType, label)) {
        std::wcerr << L"[!] Final format failed after destructive wipe.\n";
        return false;
    }
    std::wcout << L"[+] Option 1 sequence completed.\n";
    return true;
}

void FullDriveRandomFill(wchar_t driveLetter) {
    ULARGE_INTEGER totalSize, freeSize; if(!getVolumeSize(driveLetter,totalSize,freeSize)) return;
    std::random_device rd; std::minstd_rand rng(rd());
    const size_t fileSize = 64 * 1024 * 1024; // 64MB chunks for speed
    const size_t bufferSize = 4 * 1024 * 1024; // 4MB buffer
    std::vector<BYTE> buffer(bufferSize);
    FillRandom(buffer.data(), (DWORD)bufferSize, rng);
    unsigned long long writtenTotal = 0;
    size_t fileIndex = 0;
    std::vector<std::wstring> createdFiles;
    while(true) {
        ULARGE_INTEGER curFree; if(!getVolumeSize(driveLetter,totalSize,curFree)) break;
        if(curFree.QuadPart < (bufferSize * 2)) break; // stop when almost full
        std::wstring fileName = std::wstring(1, driveLetter) + L":\\" + generateRandomString(12, rng) + L".tmp";
        HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if(hFile == INVALID_HANDLE_VALUE) break;
        createdFiles.push_back(fileName);
        unsigned long long fileWritten = 0;
        while(fileWritten < fileSize) {
            if(fileWritten % (bufferSize * 8ULL) == 0) FillRandom(buffer.data(), (DWORD)bufferSize, rng);
            DWORD toWrite = (DWORD)bufferSize;
            DWORD bw = 0;
            if(!WriteFile(hFile, buffer.data(), toWrite, &bw, NULL) || bw != toWrite) { break; }
            fileWritten += bw; writtenTotal += bw;
            if(fileWritten >= fileSize) break;
            if((fileWritten & ((bufferSize*16)-1)) == 0) displayProgressBar(writtenTotal, freeSize.QuadPart, "Full Fill");
            ULARGE_INTEGER freeCheck; if(!getVolumeSize(driveLetter,totalSize,freeCheck)) break; if(freeCheck.QuadPart < bufferSize*2) break;        }
        FlushFileBuffers(hFile); CloseHandle(hFile);
        ULARGE_INTEGER freeCheck; if(!getVolumeSize(driveLetter,totalSize,freeCheck)) break; if(freeCheck.QuadPart < bufferSize*2) break;
    }
    displayProgressBar(freeSize.QuadPart, freeSize.QuadPart, "Full Fill"); std::cout << "\n";
    // Delete all created files
    for(const auto &f: createdFiles) { SetFileAttributesW(f.c_str(), FILE_ATTRIBUTE_NORMAL); DeleteFileW(f.c_str()); }
}

bool FormatDrive(wchar_t driveLetter, const std::wstring& fsType, const std::wstring& label) {
    std::wstring cmd = L"cmd /c echo.| format " + std::wstring(1, driveLetter) + L": /FS:" + fsType + L" /V:" + label + L" /Q /X";
    std::wcout << L"[*] Formatting drive " << driveLetter << L": as " << fsType << L"...\n";
    int r = _wsystem(cmd.c_str());
    if (r != 0) {
        std::wcerr << L"[-] Format failed with code " << r << L"\n";
        return false;
    }
    std::wcout << L"[+] Drive formatted to " << fsType << L" successfully.\n";
    return true;
}

void FillDriveAccumulate(wchar_t driveLetter) {
    ULARGE_INTEGER totalSize, freeSize; if(!getVolumeSize(driveLetter,totalSize,freeSize)) return;
    std::mt19937 rng((unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    const size_t bufferSize = 16 * 1024 * 1024; // 16MB write buffer
    const unsigned long long fileSize = 64ULL * 1024ULL * 1024ULL; // fixed 64MB per temp file
    const unsigned long long refillInterval = 256ULL * 1024ULL * 1024ULL; // refresh buffer every 256MB total written
    std::vector<BYTE> buffer(bufferSize);
    FillRandom(buffer.data(), (DWORD)bufferSize, rng);
    unsigned long long writtenTotal = 0; unsigned long long sinceRefill = 0; size_t fileIndex=0;
    while(true) {
        ULARGE_INTEGER curFree; if(!getVolumeSize(driveLetter,totalSize,curFree)) break;
        if(curFree.QuadPart < (LONGLONG)(fileSize + bufferSize)) break; // leave small slack
        // random filename
        std::wstring name; {
            std::uniform_int_distribution<int> dist(0,35);
            static const wchar_t alpha[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
            name.reserve(16);
            for(int i=0;i<12;i++) name.push_back(alpha[dist(rng)]);
            name += L".tmp"; }
        std::wstring filePath = std::wstring(1, driveLetter) + L":\\" + name;
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if(hFile==INVALID_HANDLE_VALUE) break;
        // preallocate
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)fileSize; SetFilePointerEx(hFile, li, NULL, FILE_BEGIN); SetEndOfFile(hFile); LARGE_INTEGER start; start.QuadPart=0; SetFilePointerEx(hFile,start,NULL,FILE_BEGIN);
        unsigned long long fileWritten=0;
        while(fileWritten < fileSize) {
            DWORD toWrite = (DWORD)std::min<unsigned long long>(bufferSize, fileSize - fileWritten);
            DWORD bw=0; if(!WriteFile(hFile, buffer.data(), toWrite, &bw, NULL) || bw != toWrite) { break; }
            fileWritten += bw; writtenTotal += bw; sinceRefill += bw;
            if(sinceRefill >= refillInterval) { FillRandom(buffer.data(), (DWORD)bufferSize, rng); sinceRefill = 0; }
        }
        FlushFileBuffers(hFile); CloseHandle(hFile);
        fileIndex++;
        if((writtenTotal & ((128ULL*1024ULL*1024ULL)-1)) == 0) displayProgressBar(writtenTotal, freeSize.QuadPart, "Fixed Files");
    }
    ULARGE_INTEGER finalFree; if(getVolumeSize(driveLetter,totalSize,finalFree)) displayProgressBar(freeSize.QuadPart - finalFree.QuadPart, freeSize.QuadPart, "Fixed Files");
    std::cout << "\n";
}

void ParallelFill(wchar_t driveLetter, const std::wstring& fsType, size_t threads) {
#ifndef __GLIBCXX__
    threads = 1; // fallback
#endif
#ifndef _GLIBCXX_HAS_GTHREADS
    threads = 1;
#endif
    ULARGE_INTEGER totalSize, freeSize; if(!getVolumeSize(driveLetter,totalSize,freeSize)) return;
    std::atomic<unsigned long long> written{0};
    std::atomic<bool> stop{false};
    const size_t bufferSize = 8 * 1024 * 1024;
    const unsigned long long fileSize = 32ULL * 1024ULL * 1024ULL;
    auto worker = [&](int id){
#if defined(_GLIBCXX_HAS_GTHREADS) || defined(_MSC_VER)
        std::mt19937 rng((unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ (id*0x9e3779b9));
        std::uniform_int_distribution<int> dist(0,35); const wchar_t alpha[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
        std::vector<BYTE> buffer(bufferSize);
        FillRandom(buffer.data(), (DWORD)bufferSize, rng);
        while(!stop.load()) {
            ULARGE_INTEGER curFree; if(!getVolumeSize(driveLetter,totalSize,curFree)) break;
            if(curFree.QuadPart < (LONGLONG)(fileSize + bufferSize)) { stop.store(true); break; }
            std::wstring name; name.reserve(20); for(int i=0;i<12;i++) name.push_back(alpha[dist(rng)]); name+=L".tmp";
            std::wstring path = std::wstring(1, driveLetter) + L":\\" + name;
            HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if(hFile==INVALID_HANDLE_VALUE) continue;
            LARGE_INTEGER li; li.QuadPart = (LONGLONG)fileSize; SetFilePointerEx(hFile, li, NULL, FILE_BEGIN); SetEndOfFile(hFile); LARGE_INTEGER zero; zero.QuadPart=0; SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
            unsigned long long fileWritten=0; while(fileWritten < fileSize && !stop.load()) {
                DWORD chunk = (DWORD)std::min<unsigned long long>(bufferSize, fileSize - fileWritten);
                DWORD bw=0; if(!WriteFile(hFile, buffer.data(), chunk, &bw, NULL) || bw != chunk) { break; }
                fileWritten += bw; unsigned long long total = written.fetch_add(bw) + bw;
                if((total & ((256ULL*1024ULL*1024ULL)-1)) == 0) displayProgressBar(total, freeSize.QuadPart, "Parallel Fill");
            }
            FlushFileBuffers(hFile); CloseHandle(hFile);
        }
#else
        // Fallback single-thread simple fill
        FillDriveAccumulate(driveLetter);
        stop.store(true);
#endif
    };
#if defined(_GLIBCXX_HAS_GTHREADS) || defined(_MSC_VER)
    std::vector<std::thread> pool; size_t tCount = std::max<size_t>(1, threads);
    for(size_t i=0;i<tCount;i++) pool.emplace_back(worker, (int)i);
    for(auto &t: pool) t.join();
#else
    worker(0);
#endif
    displayProgressBar(written.load(), freeSize.QuadPart, "Parallel Fill"); std::cout << "\n";
}

#ifndef HAVE_STD_THREAD
#define HAVE_STD_THREAD 1
#endif
