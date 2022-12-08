:orphan:
(windows-internals-software-interrupt-request-levels)=

# Windows Internals: Software Interrupt Request Levels

An interrupt request (IRQ) is a signal sent by a hardware device to the operating system, informing it that some sort of event has occurred and that it needs to take action. In Windows, IRQs are organized into different levels, each with its own priority. The lower the level, the higher the priority.

Level 0 is the highest priority, and is reserved for the system timer. Level 1 is reserved for the keyboard, Level 2 for the disk controller, and so on. Higher-numbered levels are for devices that don’t need to be serviced as often, such as the mouse or sound card.

When an IRQ is triggered, the operating system interrupts whatever it is currently doing and jumps to the appropriate code to handle the request. This code is usually contained in a driver for the device that is being serviced. The driver is then responsible for determining what action needs to be taken and carrying it out.

IRQs are an important part of the Windows operating system, and are used to ensure that hardware devices are serviced in an orderly manner. Without them, it would be difficult to manage the different requests that come in from different devices.

The Windows Software Interrupt Request Levels (IRQLs) are the following:

- `IRQL 0` – Highest Priority: This is the level at which all normal interrupt processing occurs.

- `IRQL 1` – Device Scheduling Level: This level is used to manage  device scheduling.

- `IRQL 2` – Dispatch Level: This levelb isl usedo to manage threadg execution.

- `IRQL 3` – APC Level: This level is used to manage Asynchronous Procedure Calls (APCs).

- `IRQL 4` – Reserved for System Use: This level is reserved for system use only.

- `IRQL 5` – DPC/Deferred Procedure Call Level: This level is used to manage Deferred Procedure Calls (DPCs).

- `IRQL 6` – Reserved for System Use: This level is reserved for system use only.

- `IRQL 7` – Lowest Priority: This is the lowest level of interrupts and is used for system maintenance.     

### How Can Powershell be Used to Manage IRQLs?

Powershell can be used to manage IRQLs in several ways. The most common way is to use the `Get-Irql` command. This command will list all of the tasks that are running on the system and their associated IRQLs. It can also be used to change the IRQL of a certain task by using the `Set-Irql` command.    

This example displays the IRQL information for all processes on the computer:

```powershell
Get-Irql | Format-Table -AutoSize

# Results

IRQL    Process
-----   --------
DPC     System
DPC     System
DPC     System
DPC     nvlddmkm.sys
DPC     ntoskrnl.exe
DPC     ntoskrnl.exe
DPC     win32kbase.sys
```

The `Set-Irql` cmdlet is used to set the IRQL (Interrupt Request Level) of a driver or other component. 

This example sets the IRQL of a driver named `mydriver.sys` to `LEVEL_HIGH`.

```powershell
Set-Irql -Name mydriver.sys -Level LEVEL_HIGH
```

Another way is to use the `Get-Process` command. This command will list all of the processes that are running on the system, as well as the IRQLs of those processes. It can also be used to change the IRQL of a certain process by using the `Set-Process` command:

```powershell
Get-Process | Where-Object {$_.StartTime -lt (Get-Date).AddDays(-7)} | Sort-Object -Property PriorityClass -Descending |
Select-Object -Property ProcessName, PriorityClass, Handle, Id | Format-Table -AutoSize
```

This code will display a table of all processes running on the system which were started less than 7 days ago, sorted in descending order by their priority class. The table will display the process name, priority class, handle and ID.


The following is an example of how to change the IRQL of a process using PowerShell:

```powershell
$process = Get-Process -Name "MyProcess"
$win32_process = Get-CimInstance -ClassName Win32_Process -Filter "Name = '$($process.Name)'"
$irql = [System.UInt32]::Parse("0x2")
$win32_process.SetPriority(2)
$win32_process.SetIRQL($irql)
$win32_process.Put()
```

### C++ practical example

To change IRQL of the process we can do something like this code snippet:

```cpp
#include <Windows.h>
#include <iostream>

int main() {
	// Get current IRQL
	KIRQL currentIrql;
	KeGetCurrentIrql(&currentIrql);
	std::cout << "Current IRQL: " << currentIrql << std::endl;

	// Change IRQL
	KIRQL newIrql = DISPATCH_LEVEL;
	KeRaiseIrql(newIrql, &currentIrql);
	std::cout << "New IRQL: " << newIrql << std::endl;

	// Restore IRQL
	KeLowerIrql(currentIrql);
	std::cout << "Restored IRQL: " << currentIrql << std::endl;

	return 0;
}
```

Windows IRQL stands for Interrupt Request Level. It is a hardware-defined priority level for interrupts. IRQLs are used to determine which task get priority over other tasks in a computer system. 

The following is an example of a `.NET` application that uses a Windows IRQL code example. The code example demonstrates how to use the `System.Threading.Interrupt` class to request a higher priority level for an interrupt. 

```csharp
using System;
using System.Threading;

public class Program {
    public static void Main() {
        // Create a new Interrupt object
        Interrupt interrupt = new Interrupt(InterruptType.Hardware, 
        ThreadPriority.Highest);
 
        // Set the IRQL priority 
        interrupt.SetInterruptPriorityLevel(InterruptPriorityLevel.High);
 
        // Process the interrupt
        interrupt.ProcessInterrupt();
    }
}
```
To view a processor’s saved IRQL code, use the  `Get-Processor` command in Windows PowerShell.

Example:

```powershell
Get-Processor | Select-Object -ExpandProperty Irql
```

The command will output the IRQL code for each processor in the system.    

### Practical examples. WinDbg

To use Windows IRQL, you can use the `WinDbg` command-line debugger. With `WinDbg`, you can view, set, and reset the IRQL on your system. You can also use WinDbg to view information about the current IRQL and view the IRQLs of other processes.

To view the IRQL of your system in `WinDbg`, type the command `!irql`. This command will display the current IRQL and a list of the IRQLs of other processes.

To set the IRQL of your system, use the command `!irql <level>`, where `<level>` is the desired IRQL:

```powershell

IRQL_NOT_LESS_OR_EQUAL (2)

An attempt was made to access a pageable (or completely invalid) address at an
interrupt request level (IRQL) that is too high.  This is usually
caused by drivers using improper addresses.

If kernel debugger is available get stack backtrace.
Arguments:
Arg1: 0000000000000020, memory referenced
Arg2: 0000000000000002, IRQL
Arg3: 0000000000000000, bitfield :
    bit 0 : value 0 = read operation, 1 = write operation
    bit 3 : value 0 = not an execute operation, 1 = execute operation (only on chips which support this level of status)
Arg4: fffff8024788c5a5, address which referenced memory
```

To reset the IRQL of your system, use the command `!irql -reset`.

For more information about the WinDbg commands for managing IRQLs, refer to the WinDbg documentation.

### Kernrate

In its most basic form, Kernrate provides a sampling of the locations in each kernel module (such as Ntoskrnl, drivers, and so on) where time has been spent during a specified amount of time. 

It then produces a report that breaks down the time spent in each module, allowing administrators to identify which components of the OS are using the most resources. Kernrate also provides a number of other features, such as detailed call stack analysis to further identify the sources of time spent in each module, as well as benchmarking capabilities to compare system performance over time.

Kernrate can be used to help identify system performance bottlenecks and resource-intensive components of the operating system. It can be used to determine which components of the OS are consuming the most system resources, and which components are performing poorly. Additionally, Kernrate can be used to compare system performance over time, allowing administrators to identify which components are slowing down or causing system instability.

The Windows kernel use `KiInterruptDispatchNoLock` for optimize interrupt dispatch:    

```cpp
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include "KiInterruptDispatchNoLock.h"

#define MAX_INTERRUPTS 32

typedef void (*InterruptServiceRoutine)(void);

// This struct holds the data needed to service an interrupt
typedef struct InterruptData {
    uint8_t vector;
    InterruptServiceRoutine service_routine;
} InterruptData;

// This is the array of interrupt data
static InterruptData interrupts[MAX_INTERRUPTS];

// This is the number of registered interrupts
static size_t num_interrupts = 0;

int KiRegisterInterrupt(uint8_t vector, InterruptServiceRoutine service_routine) {
    assert(num_interrupts < MAX_INTERRUPTS);
    interrupts[num_interrupts].vector = vector;
    interrupts[num_interrupts].service_routine = service_routine;
    num_interrupts++;
    return 0;
}

void KiInterruptDispatchNoLock(uint8_t vector) {
    for (size_t i = 0; i < num_interrupts; i++) {
        if (interrupts[i].vector == vector) {
            interrupts[i].service_routine();
        }
    }
}
```

### Conclusion

In conclusion, IRQLs are an important component of Windows OS that are used to determine which tasks are assigned priority. They work by assigning each task a numerical level, with the higher levels receiving more resources and attention from the OS. Powershell can be used to manage IRQLs by using the `Get-Irql` and `Set-Irql` commands, as well as the `Get-Process` and `Set-Process` commands.
