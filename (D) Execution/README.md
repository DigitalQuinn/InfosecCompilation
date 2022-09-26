# Execution

**Execution** consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery.

<br>
<hr>

# Table of Contents
- [Command & Scripting Interpreter](#command--scripting-interpreter)
  - [PowerShell](#powershell)
  - [AppleScript](#applescript)
  - [Windows Command Shell](#windows-command-shell)
  - [Unix Shell](#unix-shell)
  - [Visual Basic](#visual-basic)
  - [Python](#python)
  - [JavaScript](#javascript)
  - [Network Device CLI](#network-device-cli)
- [Container Administration Command](#container-administration-command)
- [Deploy Container](#deploy-container)
- [Exploitation for Client Execution](#exploitation-for-client-execution)
- [Inter-Process Communication](#inter-process-communication)
  - [Component Object Model](#component-object-model)
  - [Dynamic Data Exchange](#dynamic-data-exchange)
  - [XPC Services](#xpc-services)
- [Native API](#native-api)
- [Scheduled Tasks / Jobs](#scheduled-tasks--jobs)
  - [At](#at)
  - [Cron](#cron)
  - [Scheduled Task](#scheduled-tasks)
  - [Systemd Timers](#systemd-timers)
  - [Container Orchestration Job](#container-orchestration-job)
- [Shared Modules](#shared-modules)
- [Software Deployment Tools](#software-deployment-tools)
- [System Services](#system-services)
  - [Launchctl](#launchctl)
  - [Service Execution](#service-execution)
- [User Execution](#user-execution)
  - [Malicious Link](#malicious-link)
  - [Malicious File](#malicious-file)
  - [Malicious Image](#malicious-image)
- [Windows Management Instrumentation](#windows-management-instrumentation)

<br>
<hr>

# Command & Scripting Interpreter 
Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities.

Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various Remote Services in order to achieve remote Execution.

<br>

## PowerShell 
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.[1] Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
* **Start-Process cmdlet:** Can be used to run an executable
* **Invoke-Command cmdlet:** Runs a command locally or on a remote computer 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.
* A number of PowerShell-based offensive testing tools are available, including Empire, PowerSploit, PoshC2, and PSAttack.

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management. Automation assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI).

<br>

## AppleScript 
**AppleScript:** A macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents. These AppleEvent messages can be sent independently or easily scripted with AppleScript. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely.

* Scripts can be run from the command-line via osascript /path/to/script or osascript -e "script here"
* Scripts can be executed in numerous ways including Mail rules, Calendar.app alarms, and Automator workflows
* AppleScripts can also be executed as plain text shell scripts by adding `` #!/usr/bin/osascript `` to the start of the script file

AppleScripts do not need to call osascript to execute, however, they may be executed from within mach-O binaries by using the macOS Native APIs NSAppleScript or OSAScript, both of which execute code independent of the `` /usr/bin/osascript `` command line utility.

Adversaries may abuse AppleScript to execute various behaviors, such as interacting with an open SSH connection, moving to remote machines, and even presenting users with fake dialog boxes. These events cannot start applications remotely (they can start them locally), but they can interact with applications if they're already running remotely. On macOS 10.10 Yosemite and higher, AppleScript has the ability to execute Native APIs, which otherwise would require compilation and execution in a mach-O binary file format. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via Python

<br>

## Windows Command Shell 
The Windows command shell (cmd) is the primary command prompt on Windows systems, which can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. The command prompt can be invoked remotely via Remote Services such as SSH.

**Batch files:** (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may leverage cmd to execute various commands and payloads
* Common uses include cmd to execute a single command, or abusing cmd interactively with input and output forwarded over a command and control channel.

<br>

## Unix Shell 
Unix shells are the primary command prompt on Linux and macOS systems. Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.

* Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with SSH. Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence.

<br>

## Visual Basic 
VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API, and is integrated and supported in the .NET Framework and cross-platform .NET Core.

**VBA:** An event-driven programming language built into Microsoft Office and several third-party applications
* Enables documents to contain macros used to automate the execution of tasks and other functionality on the host. 
  
**VBScript:** The default scripting language on Windows hosts and can also be used in place of JavaScript on HTML Application (HTA) webpages served to Internet Explorer 

Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into Spearphishing Attachment payloads (which may also involve Mark-of-the-Web Bypass to enable execution)

<br>

## Python 
**Python:**A scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line or via scripts that can be written and distributed to different systems. Python code can also be compiled into binary executables.

Python comes with many built-in packages to interact with the underlying system, such as file operations and device I/O. Adversaries can use these libraries to download and execute commands or other scripts as well as perform various malicious behaviors.

<br>

## JavaScript 
**JavaScript (JS):** A platform-independent scripting language commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser

* JScript is the Microsoft implementation of the same scripting standard
* Interpreted via the Windows Script engine and thus integrated with many components of Windows such as the Component Object Model and Internet Explorer HTML Application (HTA) pages

**JavaScript for Automation (JXA):** A macOS scripting language based on JavaScript, included as part of Apple’s Open Scripting Architecture (OSA). Apple’s OSA provides scripting capabilities to control applications, interface with the operating system, and bridge access into the rest of Apple’s internal APIs

* OSA only supports JXA and AppleScript -- Scripts can be executed via the command line utility osascript, they can be compiled into applications or script files via osacompile, and they can be compiled and executed in memory of other programs by leveraging the OSAKit Framework

Adversaries may abuse various implementations of JavaScript to execute various behaviors. Common uses include hosting malicious scripts on websites as part of a Drive-by Compromise or downloading and executing these script files as secondary payloads. Since these payloads are text-based, it is also very common for adversaries to obfuscate their content as part of Obfuscated Files or Information

<br>

## Network Device CLI 
**CLI:** The primary means through which users and administrators interact with the device in order to view system information, modify device operations, or perform diagnostic and administrative functions. CLIs typically contain various permission levels required for different commands.

* Scripting interpreters automate tasks and extend functionality beyond the command set included in the network OS. The CLI and scripting interpreter are accessible through a direct console connection, or through remote means, such as telnet or SSH.

Adversaries can use the network CLI to change how network devices behave and operate. The CLI may be used to manipulate traffic flows to intercept or manipulate data, modify startup configuration parameters to load malicious system software, or to disable security features or logging to avoid detection.

<br>
<hr>

# Container Administration Command 
A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.

* In Docker, adversaries may specify an entrypoint during container deployment that executes a script or command, or they may use a command such as docker exec to execute a command within a running container
* In Kubernetes, if an adversary has sufficient permissions, they may gain remote execution in a container in the cluster via interaction with the Kubernetes API server, the kubelet, or by running a command such as kubectl exec

<br>
<hr>

# Deploy Container 
Adversaries may deploy a container into an environment to facilitate execution or evade defenses. Adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.

Containers can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow. Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime.

<br>
<hr>

# Exploitation for Client Execution 
Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.

**Several types exist:**

* **Browser-based Exploitation**
Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser

* **Office Applications**
Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run

* **Common Third-party Applications**
Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. 

<br>
<hr>

# Inter-Process Communication 
**IPC:** Used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern

Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model
* Linux environments support several different IPC mechanisms, two of which being sockets and pipes. Higher level execution mediums, such as those of Command and Scripting Interpreters, may also leverage underlying IPC mechanisms
  
Adversaries may also use Remote Services such as Distributed Component Object Model to facilitate remote IPC execution

<br>

## Component Object Model 
COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE). Remote COM execution is facilitated by Remote Services such as Distributed Component Object Model (DCOM).

Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and Visual Basic. 
* Specific COM objects also exist to directly perform functions beyond code execution, such as creating a Scheduled Task/Job, fileless download/execution, and other adversary behaviors related to privilege escalation and persistence.

<br>

## Dynamic Data Exchange 
**DDE:** A client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

* Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by Component Object Model, DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys

* Microsoft Office documents can be poisoned with DDE commands, directly or through embedded files, and used to deliver execution via Phishing campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros
* Adversaries may infect payloads to execute applications and/or commands on a victim device by way of embedding DDE formulas within a CSV file intended to be opened through a Windows spreadsheet program.
* DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to a Command and Scripting Interpreter
  * DDE execution can be invoked remotely via Remote Services such as Distributed Component Object Model (DCOM)

<br>

## XPC Services 
macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools
* Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service C API or the high level NSXPCConnection API in order to handle tasks that require elevated privileges
* Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services
  * Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon

Adversaries can abuse XPC services to execute malicious content. Requests for malicious execution can be passed through the application's XPC Services handler. This may also include identifying and abusing improper XPC client

<br>
<hr>

# Native API 
Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. These native APIs are leveraged by the OS during system boot as well as carrying out tasks and requests during routine operations.

* Native API functions may be directed invoked via system calls / syscalls, but these features are also often exposed to user-mode applications via interfaces and libraries
  * Windows API CreateProcess() or GNU fork() will allow programs and scripts to start other processes -- This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.

* Higher level software frameworks (Microsoft .NET and macOS Cocoa) are also available to interact with native APIs -- These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.

The native API and its hierarchy of interfaces provide mechanisms to interact with and utilize various components of a victimized system. While invoking API functions, adversaries may also attempt to bypass defensive tools (ex: unhooking monitored functions via Disable or Modify Tools)

<br>
<hr>

# Scheduled Tasks / Jobs 
Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met. 

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account. Adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process.

<br>

## At 
``at`` utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date

On Linux and macOS, ``at`` may be invoked by the superuser as well as any users added to the ``at.allow`` file
* If the ``at.allow`` file does not exist, the ``at.deny`` file is checked
* Every username not listed in ``at.deny`` is allowed to invoke at. If the ``at.deny`` exists and is empty, global use of at is permitted
* If neither file exists (which is often the baseline) only the superuser is allowed to use at

Adversaries may use ``at`` to execute programs at system startup or on a scheduled basis for Persistence. ``at`` can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM)

In Linux environments, adversaries may also abuse ``at`` to break out of restricted environments by using a task to spawn an interactive system shell or to run system commands. Similarly, ``at`` may also be used for Privilege Escalation if the binary is allowed to run as superuser via sudo

<br>

## Cron 
The ``cron`` utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths.

An adversary may use cron in Linux or Unix environments to execute programs at system startup or on a scheduled basis for Persistence.

<br>

## Scheduled Tasks 
Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code

There are multiple ways to access the Task Scheduler in Windows
* **schtasks** can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel
* Adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.

The deprecated ``at`` utility could also be abused by adversaries, though at.exe can not access tasks created with schtasks or the Control Panel

* Windows Task Scheduler can execute programs at system startup or on a scheduled basis for persistence
  * Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM)
  * Adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes

<br>

## Systemd Timers 
Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments
* Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH

* Each ``.timer`` file must have a corresponding ``.service`` file with the same name. 
* .service files are Systemd Service unit files that are managed by the systemd system and service manager.[3] Privileged timers are written to ``/etc/systemd/system/`` and ``/usr/lib/systemd/system`` while user level are written to ``~/.config/systemd/user/``

An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.

<br>

## Container Orchestration Job 
Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.

In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster. 

<br>
<hr>

# Shared Modules 
The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API

The module loader can load DLLs via:

* specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;

* EXPORT forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);

* an NTFS junction or symlink program.exe.local with the fully-qualified or relative pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded EXPORTs;

* <file name="filename.extension" loadFrom="fully-qualified or relative pathname"> in an embedded or external "application manifest"
  * The file name refers to an entry in the IMPORT directory or a forwarded EXPORT

Adversaries may use this functionality as a way to execute arbitrary payloads on a victim system. Malware may execute share modules to load additional components or features

<br>
<hr>

# Software Deployment Tools 
Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.).

Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

<br>
<hr>

# System Services 
Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.

<br>

## Launchctl 
Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.

Adversaries use launchctl to execute commands and programs as Launch Agents or Launch Daemons

Common subcommands include: launchctl load,launchctl unload, and launchctl start
Adversaries can use scripts or manually run the commands ``launchctl load -w "%s/Library/LaunchAgents/%s"`` or ``/bin/launchctl load`` to execute Launch Agents or Launch Daemons

<br>

## Service Execution 
The Windows service control manager (services.exe) is an interface to manage and manipulate services. The service control manager is accessible to users via GUI components as well as system utilities such as sc.exe and Net

**PsExec:** Used to execute commands or payloads via a temporary Windows service created through the service control manager API
* Tools such as PsExec and sc.exe can accept remote servers as arguments and may be used to conduct remote execution

Adversaries may leverage these mechanisms to execute malicious content by executing a new or modified service

<br>
<hr>

# User Execution 
Users may be subjected to social engineering to get them to execute malicious code by, opening a malicious document file or link

Adversaries may also deceive users into performing actions such as enabling remote access software, allowing direct control of the system to the adversary, or downloading and executing malware for user execution

<br>

## Malicious Link 
Users may be subjected to social engineering to get them to click on a link that will lead to code execution
* Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via Exploitation for Client Execution
* Links may also lead users to download files that require execution via Malicious File.

<br>

## Malicious File 
Users may be subjected to social engineering to get them to open a file that will lead to code execution
* Adversaries may use several types of files that require a user to execute them, (.doc, .pdf, .xls, etc.)
* Adversaries may employ various forms of masquerading and obfuscated files or information to increase the likelihood that a user will open and successfully execute a malicious file

<br>

## Malicious Image 
Backdoored images may be uploaded to a public repository via upload malware, and users may then download and deploy an instance or container from the image without realizing the image is malicious, thus bypassing techniques that specifically achieve Initial Access
* Adversaries may also name images a certain way to increase the chance of users mistakenly deploying an instance or container from the image (ex: Match Legitimate Name or Location)

<br>
<hr>

# Windows Management Instrumentation 
**WMI:** An administration feature that provides a uniform environment to access Windows system components. The WMI service enables both local and remote access, though the latter is facilitated by Remote Services such as Distributed Component Object Model (DCOM) and Windows Remote Management (WinRM)
* Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS

An adversary can use WMI to interact with local and remote systems and use it as a means to execute various behaviors, such as gathering information for Discovery as well as remote Execution of files as part of Lateral Movement