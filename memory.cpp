#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>

namespace addon {

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Number;
using v8::Array;
using v8::Value;
using v8::Exception;
 
struct StockPid
{
    pid_t pid;
    char buff[512];
    FILE *pid_pipe;
    char command[512];
} stockthepid;
 
void GetProcessPid(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1 || !args[0]->IsString()) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid arguments").ToLocalChecked()));
        return;
    }

    v8::String::Utf8Value processName(args.GetIsolate(), args[0]->ToString(args.GetIsolate()->GetCurrentContext()).ToLocalChecked());
    
    const char *processname = *processName;
    FILE *pid_pipe;
    char command[512];
    char buff[512];
    pid_t pid;

    sprintf(command, "pidof -s %s", processname);
    pid_pipe = popen(command, "r");
    fgets(buff, 512, pid_pipe);
    pid = strtoul(buff, NULL, 10);
 
    if (pid == 0) {
        printf("App Var is not launch ! \n");
        pclose(pid_pipe);
        exit(-1);
    }

//     if (pid == 0) {
//     printf("App Var is not launch ! \n");
//     pclose(pid_pipe);
//     v8::Isolate* isolate = v8::Isolate::GetCurrent();
//     isolate->ThrowException(v8::Exception::Error(v8::String::NewFromUtf8(isolate, "App Var is not launch !")));
//     return;
// }

    args.GetReturnValue().Set(Number::New(isolate, static_cast<double>(pid)));
}

bool isCapableToRead(int pid, uintptr_t address, void* buffer, size_t size) {
    std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
    std::ifstream mem_file(mem_path, std::ios::binary);

    if (!mem_file.is_open()) {
        std::cerr << "Error opening mem file: " << mem_path << std::endl;
        return false;
    }

    mem_file.seekg(address);
    mem_file.read(reinterpret_cast<char*>(buffer), size);
    mem_file.close();

    return true;
}

std::vector<std::pair<unsigned long, unsigned long>> getMemoryRanges(int pid) {
    std::vector<std::pair<unsigned long, unsigned long>> ranges;

    // Generate the path to the maps file for the specified process
    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";

    // Open the maps file
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        std::cerr << "Error opening maps file: " << mapsPath << std::endl;
        return ranges;
    }

    // Read the maps file line by line
    std::string line;
    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        unsigned long start, end;
        char dash;
        iss >> std::hex >> start >> dash >> end;

        // Store the start and end addresses in the vector
        ranges.push_back(std::make_pair(start, end));
    }

    // Close the maps file
    mapsFile.close();

    return ranges;
}

std::vector<uintptr_t> getAllVariables(int pid) {
    std::vector<uintptr_t> variableAddresses;

    // Define a range of memory addresses to scan (adjust as needed)
    std::vector<std::pair<unsigned long, unsigned long>> memoryRanges = getMemoryRanges(pid);

    // Specify the size of the memory block to read
    size_t blockSize = sizeof(int);

    // Buffer to store the read memory
    char buffer[sizeof(int)];

    for (const auto& range : memoryRanges) {
        unsigned long startAddress = range.first;
        unsigned long endAddress = range.second;

        for (uintptr_t address = startAddress; address <= endAddress; address += blockSize) {
            if (isCapableToRead(pid, address, buffer, blockSize)) {
                // If the read is successful, add the address to the list
                variableAddresses.push_back(address);
            }
        }
    }


    return variableAddresses;
}


void GetProcessAddresses(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Local<Array> result = Array::New(isolate, 0);

    // Get process ID from the argument (assuming it's passed as the first argument)
    int pid = args[0]->Int32Value(isolate->GetCurrentContext()).FromJust();

    // Call the C++ function
    std::vector<uintptr_t> addresses = getAllVariables(pid);

    // Convert the C++ vector to a JavaScript array
    for (size_t i = 0; i < addresses.size(); ++i) {
        // result->Set(isolate->GetCurrentContext(), static_cast<int>(i), v8::Number::New(isolate, static_cast<double>(addresses[i])));
        result->Set(isolate->GetCurrentContext(), static_cast<uint32_t>(i), String::NewFromUtf8(isolate, std::to_string(addresses[i]).c_str()).ToLocalChecked());
    }

    args.GetReturnValue().Set(result);
}

 
void ReadProcessMemory(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 2) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments").ToLocalChecked()));
        return;
    }

    double arg = args[0]->NumberValue(isolate->GetCurrentContext()).ToChecked();
    pid_t pid = static_cast<pid_t>(arg);
    unsigned long address = static_cast<unsigned long>(args[1]->NumberValue(isolate->GetCurrentContext()).FromJust());

    int buf = 0;

    int err_code = ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    if (err_code == -1) {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Error attaching to process").ToLocalChecked()));
        return;
    }

    wait(NULL);

    buf = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
    if (buf == -1)
    {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Error reading process memory").ToLocalChecked()));
        return;
    }

    err_code = ptrace(PTRACE_DETACH, pid, NULL, NULL);

    if (err_code == -1) {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Error detaching from process").ToLocalChecked()));
        return;
    }

    args.GetReturnValue().Set(Number::New(isolate, buf));
}
 
void WriteProcessMemory(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 3) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments").ToLocalChecked()));
        return;
    }

    int buf = 0;
    double arg = args[0]->NumberValue(isolate->GetCurrentContext()).ToChecked();
    pid_t pid = static_cast<pid_t>(arg);
    unsigned long address = static_cast<unsigned long>(args[1]->NumberValue(isolate->GetCurrentContext()).FromJust());
    int value = static_cast<int>(args[2]->NumberValue(isolate->GetCurrentContext()).FromJust());
 
    int err_code = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (err_code == -1)
    {
        printf("%s\n", "error 1");
        exit(-1);
    }
 
    wait(NULL);
    printf("Write the new value ! \n");
    for(int i = 0; i < 1; i++) {
        buf = ptrace(PTRACE_POKEDATA, pid, address + i * sizeof(int), value);
        if (buf == -1)
        {
            printf("%s\n", "error 2");
            exit(-1);
        }
        printf("The new value has just been added! \n");
    } 
    err_code = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (err_code == -1) 
    {
        printf("%s\n", "error 3");
        exit(-1);
    }
}
 
void Init(Local<Object> exports, Local<Object> module)
{
    NODE_SET_METHOD(exports, "getProcessPid", GetProcessPid);
    NODE_SET_METHOD(exports, "getProcessAddresses", GetProcessAddresses);
    NODE_SET_METHOD(exports, "readProcessMemory", ReadProcessMemory);
    NODE_SET_METHOD(exports, "writeProcessMemory", WriteProcessMemory);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Init)
} 