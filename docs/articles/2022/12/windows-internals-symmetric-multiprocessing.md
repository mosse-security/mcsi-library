:orphan:
(windows-internals-symmetric-multiprocessing)=

# Windows Internals: Symmetric Multiprocessing

What is Symmetric Multiprocessing (SMP) in Windows Internals? 

Symmetric multiprocessing (also known as SMP) is a type of computing architecture used in Windows internals which allows multiple processors to work together to complete a single task. It is a form of parallel computing in which multiple processors are connected to a single system, allowing them to share resources and workloads. SMP is used in most modern computers, including personal computers, servers and supercomputers. SMP works by allowing the processors to communicate with each other, dividing up the tasks needed to complete a given task.      

This allows the workload to be spread across multiple processors, resulting in better performance and improved efficiency. SMP has become increasingly important in Windows internals, as more modern computers are equipped with multiple processors.     

This allows for more complex and powerful tasks to be completed, which would not be possible on a single-processor system. SMP also allows for better scalability, as more processors can be added to the system to increase its performance. The main advantage of SMP is its ability to take advantage of the power of multiple processors at the same time.     

By utilizing all of the available processors, a task can be completed in a much shorter amount of time. This can be especially beneficial for large-scale applications that require a lot of computing power. SMP also has some disadvantages, such as the complexity of the system. In order for the different processors to communicate with each other, a lot of software and hardware must be set up, which can be very time-consuming.      

Additionally, the performance of the system can be limited by the number of processors in the system. Despite its drawbacks, SMP is still a very important part of Windows internals. It allows for the most efficient use of available resources, resulting in improved performance and better scalability. In the future, more and more computers will be equipped with multiple processors, making SMP even more important.     

In order to take full advantage of SMP, an understanding of the underlying architecture is required. This includes knowledge of how the different processors are connected and how data is shared between them. Additionally, an understanding of the operating system and its components is also necessary.       

The most important component of SMP is the operating system. It is responsible for managing the system’s resources, as well as dealing with the communication between the different processors. Windows internals provide a powerful set of APIs that allow developers to take advantage of SMP.        

The Windows operating system also provides support for a variety of different types of SMP architectures, such as NUMA and Symmetric Multi-Processing (SMP). NUMA stands for Non-Uniform Memory Access and is used for systems with more than two processors.      

In this architecture, each processor has its own memory, allowing for faster access to data. Symmetric Multi-Processing (SMP) is the most commonly used form of SMP. In this architecture, all of the processors are connected to a single system and share resources and workloads.      

This allows for more efficient use of the available resources, resulting in improved performance. Despite its advantages, SMP is not without its drawbacks. As mentioned earlier, the complexity of the system can be a problem, as it requires a lot of software and hardware setup.        

Additionally, the performance of the system can be limited by the number of processors in the system. Overall, SMP is an important part of Windows internals. By utilizing multiple processors, tasks can be completed in a much shorter amount of time, resulting in improved performance and better scalability.     

In order to take full advantage of SMP, an understanding of the underlying architecture is required. Additionally, the Windows operating system provides support for a variety of different types of SMP architectures, such as NUMA and Symmetric Multi-Processing (SMP).

## Using Powershell 

How to use Windows Symmetric multiprocessing?    

To use Windows Symmetric multiprocessing (SMP), you will need to use a few PowerShell cmdlets.     

First, you'll need to use the `Get-Processor` cmdlet to list all of the processors in your system:    

```powershell
PS C:\> Get-Processor 

CPUID: 0 
Name: Intel Core i7 
NumberOfCores: 4 
NumberOfLogicalProcessors: 8 

CPUID: 1 
Name: Intel Core i7 
NumberOfCores: 4 
NumberOfLogicalProcessors: 8 
```

This command will return the processor ID, name, number of cores, and number of logical processors for each processor in your system.      

Next, you'll need to use the `Set-ProcessorGroup` cmdlet to create a processor group and assign the processors to the group:     

```powershell
PS C:\> Set-ProcessorGroup -Name SMP -Processors (Get-Processor).CPUID
```

This command creates a processor group named SMP and assigns all of the processors to the group.    

Finally, you can use the `Get-ProcessorGroup` cmdlet to view the processor group and its members:     

```powershell
PS C:\> Get-ProcessorGroup -Name SMP 

Name: SMP 
Processors: 0, 1 
```

This command displays the processor group name and the processors that are members of the group.      

With this, you are now able to use Windows Symmetric multiprocessing in your system.       

Note that you may also need to configure specific applications to use the processor group for SMP.      

## Practical cases in C++

The following code sample demonstrates how to use Symmetric Multiprocessing (SMP) in Microsoft Windows. This sample is written in C++ and requires the Windows SDK.

```cpp
#include <windows.h>

// Function prototype for the function that will be executed by each thread.
DWORD WINAPI ThreadProc( LPVOID lpParameter );

// The function that will be executed by each thread.
DWORD WINAPI ThreadProc( LPVOID lpParameter ) {
    // Get the affinity mask from the parameter.
    DWORD_PTR dwProcessAffinityMask = *((DWORD_PTR*)lpParameter);

    // Set the thread's affinity mask.
    SetThreadAffinityMask( GetCurrentThread(), dwProcessAffinityMask );
    
    // Perform thread-specific work here.
    
    return 0;
}

// The main() function of the program.
int main() {
    // Create a handle to the thread.
    HANDLE hThread;

    // Set the thread's affinity mask to use all available processors.
    DWORD_PTR dwProcessAffinityMask;
    GetProcessAffinityMask( GetCurrentProcess(), &dwProcessAffinityMask, NULL );

    // Create the thread, passing the affinity mask as the parameter.
    hThread = CreateThread( NULL, 0, ThreadProc, &dwProcessAffinityMask, 0, NULL );

    // Wait for the thread to finish.
    WaitForSingleObject( hThread, INFINITE );

    // Close the thread handle.
    CloseHandle( hThread );

    return 0;
}
```

Another example shows how to use Windows Symmetric Multiprocessing (SMP) to create four processors on a single computer.

```cpp
#include <windows.h>

// Define the number of processors on the system.
#define NUM_PROCESSORS 4

int main()
{
    // Set the number of processors to use.
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    sysinfo.dwNumberOfProcessors = NUM_PROCESSORS;
    SetSystemInfo(&sysinfo);

    // Get the current affinity mask.
    DWORD_PTR proc_affinity_mask;
    GetProcessAffinityMask(GetCurrentProcess(), &proc_affinity_mask, NULL);

    // Create a new affinity mask with all processors enabled.
    DWORD_PTR new_affinity_mask = 0;
    for (int i = 0; i < NUM_PROCESSORS; i++)
    {
        new_affinity_mask |= (1 << i);
    }

    // Set the affinity mask.
    SetProcessAffinityMask(GetCurrentProcess(), new_affinity_mask);

    // Do work here.

    // Restore the original affinity mask.
    SetProcessAffinityMask(GetCurrentProcess(), proc_affinity_mask);

    return 0;
}
```

## .NET API

What about `.NET`? The `System.Threading.Tasks.Parallel` library in `.NET` provides a set of APIs that allow you to use symmetric multiprocessing in your applications. The following example code uses this library to run a code block in parallel on multiple threads.     

```csharp
// Create a delegate to the method that will be executed in parallel 
Action<int> ActionDelegate = (input) => { 
    // Insert code to be executed here 
};

// Create the parallel options object 
ParallelOptions opts = new ParallelOptions(); 
opts.MaxDegreeOfParallelism = 8; // Number of threads to run in parallel 

// Execute the code block in parallel 
Parallel.For(0, 10, opts, ActionDelegate); 

// Wait for all threads to finish 
Parallel.WaitAll(opts);
```