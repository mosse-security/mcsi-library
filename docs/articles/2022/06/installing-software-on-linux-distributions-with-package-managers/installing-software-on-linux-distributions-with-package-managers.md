:orphan:
(installing-software-on-linux-distributions-with-package-managers)=
# Installing Software on Linux Distributions With Package Managers
 

When using Linux systems on a regular basis, you may need to install additional software applications. This task can be done using package managers. Depending on the *[type](a-gentle-introduction-to-digital-forensics-on-linux)* of Linux distribution, different package managers can be used. This blog post introduces you to the various packages managers available across Linux distributions.

## Revisiting Windows

On a Windows computer, to install a software application, you may proceed to download the executable in *.exe* or *.msi* format. In some cases, you may be required to install additional dependencies as DLLs (Dynamic Link Library files).

Similarly, on Linux systems too, some software applications require the installation of additional dependencies. Let’s see how the package managers help to accomplish this. 

## Introducing Linux Package Managers

Different package managers are used across different Linux distributions (distros). The following list provides a brief account of the package managers used on four major distribution types:

### On Debian-based Distros

On Debian-based distros like Ubuntu and Kali, software applications are distributed as files with the extension *.deb*. When you intend to download an application for Ubuntu on your computer, say ‘Teamviewer’, you would end up downloading the *.deb* file for it. 

To install the *.deb* file, a command-line tool called `dpkg` would be used with the following syntax:

`dpkg -i [package.deb] `

Where `-i` stands for ‘install’. `dpkg` is referred to as a package manager. It is also used to remove, store and provide information about *.deb* packages. What `dpkg` does not do, is install any additional dependencies required by the package. It simply displays a message about unmet dependencies.

There is another package manager called *apt* used in the command-line as `apt`. You can use it to install a *.deb* files as follows:

`apt install [package.deb]`

`apt` will automatically identify additional dependencies and install those for you.

`apt` also has access to a repository of software applications available for your Linux installation. You can also install packages from the repository. Typically, when you wish to install a package from the repository, you will not specify the extension for the package, you will just provide the name of the package. If you wish to install *python* on your machine using apt, the command for the same would look like this:

`apt install python`

By default, the latest available version would get installed. You can also specify the exact version of *python* to be installed.

There is another package manager for Debian-based distributions called *Aptitude*. Research about it!

### On RPM-based Distros

On RPM-based distros like Fedora and CentOS, software applications are distributed as files with the extension *.rpm*. When you intend to download an application for Fedora on your computer, you would end up downloading the *.rpm* file for it. 

To install the *.rpm* file, a command-line tool called `rpm` would be used with the following syntax:

`rpm -i [package.rpm]`

Where `-i` stands for ‘install’. `rpm` is referred to as a package manager. It is also used to remove, store and provide information about *.rpm* packages. `rpm`, like `dpkg` does not install any additional dependencies required by the package. It simply displays a message about unmet dependencies.

There are other package managers available for RPM-based distros that can install a software application along with its dependencies. They are `yum` and `dnf`. `yum` stands for ‘Yellow Dog Updater, Modified’ while `dnf` stands for ‘Dandified YUM’. 

`dnf` is an improved version of `yum`. There are technical differences in how they work under the hood. Both can be used to install *.rpm* packages as follows:

`yum localinstall [package.rpm]`

`dnf localinstall [package.rpm]`

`yum` and `dnf` are capable of downloading software packages from repositories. Here too, when you download a package from a repository, you will simply provide the name of the package to be downloaded and installed.

### On Arch-Linux based Distros

On Arch-Linux based distros like Arch Linux and Manjaro, software applications are packaged as *.tar* files compressed either using ZStandard compression or XZ compression. This means packages are distributed either with the extension *.tar.zst* or *.tar.xz*

A command-line package manager called `pacman` can be used to install software applications. It can install some software dependencies, while other dependencies must be installed manually.

Software can also be downloaded from the Arch User Repository (AUR) using `pacman`.

### On SUSE-based Distros

On SUSE-based distros like SUSE Enterprise and Open SUSE, software applications are distributed as *.rpm* files. 

Packages can be installed using `rpm` tool as in RPM-based distros. But it will not install any dependencies.

There are two more package managers designed for use on SUSE-based distros: *zypper* and *YaST* which stands for ‘Yet Another Setup Tool’. Both package managers can install software packages along with their dependencies. However, *zypper* is command-line based and *YaST* is GUI-based.

The list provided above is just a subset of all the package managers available across all Linux distributions. Once you have knowledge about how some package managers work, you will be able to adapt and work with other ones.

## Why should cybersecurity professionals know about Linux Package Managers?

- As a digital forensics examiner, you may need to identify the packages that have been installed or removed from a system recently. Knowing which Linux distribution you are presented with, will help you identify the package managers used and traverse through its historical activity.
- As a penetration tester/red teamer, you may need to set up malicious packages on a system.
- As a cloud security professional, you will need to set up various applications on your cloud resources using package managers.
- As a system/network security professional, you will be required to keep the system up to date with security flaws patches. For this, you must be aware of how to install and update packages from legitimate sources.

## Project Idea

Here is a project idea for you:

- Set up Ubuntu on a Linux virtual machine
- Use the ‘apt’ package manager tool to download ‘Teamviewer’ application on your machine
- Head over to the official website, download the *.deb* package for ‘Teamviewer’ and install it
- Do you observe any differences in the process?