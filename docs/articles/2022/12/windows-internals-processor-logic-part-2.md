:orphan:
(windows-internals-processor-logic-part-2)=

# Windows Internals: Processor logic - Part 2

## Affinity

The Windows operating system allows you to set processor affinity for applications, which is a feature that allows you to control which processor cores an application can use. This is useful if you want to ensure that a certain application or process runs on a specific processor core or cores. You can also use processor affinity to limit the amount of resources or core usage that a particular application can use.

When setting processor affinity, you can choose which cores an application or process can use. You can select one or more cores, or you can choose to have the application run on all available cores.

The process of setting processor affinity is relatively simple. First, open the “Task Manager” window. In the “Processes” tab, find the application or process that you want to set affinity for, and then right-click on it. Select “Set Affinity” from the context menu, and then you will be presented with a dialog box. In this box, you can select which cores the application or process can use.

When you are done, click “OK” and the processor affinity will be set. Note that you may need to restart the application or process for the changes to take effect.

Processor affinity can be a great way to ensure that an application or process runs on the cores you have chosen. It can also be useful for limiting the amount of resources or core usage that a particular application can use. If you are having trouble with an application or process running too slowly, or if you want to ensure that it runs on a certain processor core, then setting processor affinity may be the solution.

The following C++ code snippet is how to set processors affinity:

```cpp
#include <windows.h>
#include <vector>

// Get the number of CPUs available on this machine.
int GetNumberOfProcessors() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}

// Set the processor affinity of the current process. 
void SetProcessorAffinity(std::vector<int>& processor_ids) {
    DWORD_PTR process_mask = 0;
    DWORD_PTR system_mask;

    // Get the system affinity mask.
    GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask);

    // Create a new affinity mask where we only set the bits for the processors
    // specified in the processor_ids vector.
    for (int i = 0; i < processor_ids.size(); ++i) {
        process_mask |= (1 << processor_ids[i]);
    }

    // Set the new processor affinity mask.
    SetProcessAffinityMask(GetCurrentProcess(), process_mask);
}
```

## Windows Threads Processors

In Windows operating systems, the kernel control block (KCB) is a data structure that is used by the kernel to store important information about each thread. This data structure contains fields that store information such as the thread ID, its state, the stack address, and the current CPU number.

The CPU number is an important field of the KCB that helps the kernel to determine which processor core the thread is currently running on. It is also used to determine which CPU core should be used to execute a thread if the thread is moved from one core to another. The CPU number is stored in a field called the "current CPU number", which is updated whenever the thread is moved to a different core.

The value stored in the current CPU number field is a unique number that is assigned to each processor core. This number is used to identify the processor core that the thread currently belongs to. The CPU number is set to -1 when the thread is not running on any processor core.

The CPU number stored in the KCB is an important piece of information that helps the kernel manage threads and determine what processor core a thread should be assigned to. Without this information, the kernel would not be able to determine which processor core a thread should be running on.

The last processor that a Windows thread ran on is determined by the operating system scheduler. The scheduler is responsible for assigning threads to processors, so it will decide which processor a thread will run on at any given time. There is no way to know for sure which processor a thread last ran on without having access to the operating system scheduler.

The Windows thread next processor API enables applications to specify the processor on which the next thread is to be scheduled. This API is used to optimize the scheduling of threads on different processors, as well as to ensure that threads are distributed evenly across the available processors. The Windows thread next processor API is available on Windows 8 and later versions.

For selecting CPU for current thread we can run something like this:

```cpp
#include <windows.h>

// Assumes that the system has at least two CPUs
const DWORD_PTR CPU1 = 1;
const DWORD_PTR CPU2 = 2;

// Selects CPU1 for the current thread
void select_cpu1() {
    SetThreadAffinityMask(GetCurrentThread(), CPU1);
}

// Selects CPU2 for the current thread
void select_cpu2() {
    SetThreadAffinityMask(GetCurrentThread(), CPU2);
}
```

## Ideal node for NUMA systems


NUMA (Non-Uniform Memory Access) systems are a type of computer architecture that allow multiple processors to access memory more efficiently. A NUMA system consists of multiple nodes, each with its own processor, memory, and communication links to the other nodes. The goal of a NUMA system is to provide the best possible performance by minimizing the amount of time it takes for a processor to access memory.

When it comes to Windows, the ideal node setup in NUMA systems is one that is optimized for the operating system. Windows is designed to be able to access memory quickly and efficiently, so having a node that is optimized for the operating system can greatly improve performance. 

The ideal node setup for Windows should include a processor that is capable of handling the operating system’s demands, as well as enough memory to store all the necessary data. The processor and memory should be balanced to ensure that the operating system is able to access both of them quickly and efficiently. 

Additionally, the node should be connected to the other nodes via a high-speed communication link. This will ensure that data can be transferred quickly between nodes and that the operating system can take advantage of the increased speed. 

Finally, the physical layout of the node should be designed with the operating system in mind. Having a layout that allows the operating system to access memory quickly and efficiently will help to maximize the performance of the system. 

By optimizing a node for Windows in a NUMA system, users will be able to get the best performance possible from their system. With the right setup, Windows can take full advantage of the increased speed and efficiency of the NUMA system to provide users with the best possible experience.