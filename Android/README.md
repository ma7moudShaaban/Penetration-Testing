# Android Penetration Testing

## Environment Setup 

Follow these steps to set up your environment:

1. Install an Emulator: Install an emulator such as Nox Player on your Windows machine.
2. You need Kali linux tools so you should connect your Kali Linux virtual machine to your emulator. One way to achieve this is through SSH port forwarding. Here's how you can do it:
    - Root your emulator
    - Install OpenSSH server on Windows if it's not installed by default.
    - Start the SSH server using PowerShell as an administrator:
                `Start-Service sshd`
    - Ensure that the SSH service is running:
                `Get-Service sshd`
    - SSH from your Kali Linux virtual machine. Note that Nox Player runs on port 62001 by default:
                `ssh WINDOWS-USER@WINDOWS-IP -L 62001:127.0.0.1:62001`
    - Connect to your emulator using adb:
                `adb connect 127.0.0.1:62001`

**With this setup, you can begin your Android penetration testing using the tools available in Kali Linux.**

# Resources: 
- https://github.com/OWASP/owasp-mastg/blob/master/Document/0x05b-Android-Security-Testing.md
- Useful writups:
    - https://medium.com/@jooelsaka/an-interesting-bug-that-i-found-in-android-mobile-application-becf25c8c4d8
    -  https://medium.com/@amolbhavar/how-i-get-1000-bounty-for-discovering-account-takeover-in-android-application-3c4f54fbde39

## Labs
- Investigator Hack the box
- SeeTheSharpFlag Hack the box
- SuperMarket Hack the box