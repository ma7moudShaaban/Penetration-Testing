# IOS Reverse Engineering
- [Extracting the IPA file](#extracting-the-ipa-file)
    - [Method 1](#method-1)
    - [Method 2](#method-2)
- [Decompiling the App](#decompiling-the-app)


## Extracting the IPA file
### Method 1 
- Using Filza File Manager
    1. Install Filza from Cydia or Sileo (if not already installed).
    2. Open Filza and navigate to the `/var/containers/Bundle/Application/` directory.
    3. Inside, you will see multiple folders named with UUIDs (random alphanumeric characters). Each of these contains an app's .app bundle.
    4. Instead of tapping into each folder, you’ll notice that Filza already resolves the app names next to the folder, making it easy to identify the app (e.g., DVIA-v2.app) without opening each folder.
### Method 2 
- Using SSH to List Installed Apps
- You can use SSH to directly list all installed apps and their paths.

    1. Open a terminal and SSH into your device: `ssh root@10.11.1.1`
    2. Run the following command to list all installed app directories: `find /var/containers/Bundle/Application/ -name "*.app"`
        - This will list the UUID directories, and inside each directory, you will find the app bundles (e.g., DVIA-2.app).

- Take note of the app's directory (e.g., `/var/containers/Bundle/Application/70961402-4C6E-4FF6-B316-59D3ED83828F/DVIA-v2.app`).

- **Packaging the App into an IPA**
- An IPA is essentially a zipped archive containing the app's .app folder and a Payload directory.
- Step 1: Create the Payload Directory
    - SSH into the device and navigate to a writable directory (e.g., /tmp/): `cd /tmp/`
    - Create a directory named Payload: `mkdir Payload`
    - Copy the app bundle into the Payload directory: `cp -r /var/containers/Bundle/Application/70961402-4C6E-4FF6-B316-59D3ED83828F/DVIA-v2.app /tmp/Payload/`

> [!NOTE]
> Replace the UUID to match the UUID on your device.

- Step 2: Compress the Payload Directory into an IPA
    - Navigate to /tmp/: `cd /tmp/`
    - Compress the Payload folder into a .zip file: `zip -r DVIA-v2.ipa Payload`
    - You should now have an IPA file located at `/tmp/DVIA-v2.ipa`.

- **Transferring the IPA to Your Computer**
- Now that you have the IPA file, you need to transfer it to your computer.

- On your computer, use the scp command to copy the IPA file from the iOS device to your computer.
`scp root@10.11.1.1:/tmp/DVIA-v2.ipa ~/Downloads/`
- This command copies the IPA file from the device to your downloads.
- **Clean Up Temporary Files**
- After transferring the IPA, it’s a good idea to remove the temporary files from your device.
    1. SSH into your device (if not already connected).
    2. Remove the Payload folder and the IPA file from /tmp/: `rm -rf /tmp/Payload /tmp/DVIA-v2.ipa`



## Decompiling the App
- [AppleWiki](https://theapplewiki.com/wiki/Dev:Reverse_Engineering_Tools)

### Part 1: Install the IPSW Toolset and Swift
- You can install the IPSW Toolset using Homebrew on macOS. Follow the steps below to set it up.
- **Step 1: Install IPSW Toolset**
    - You can install the IPSW Toolset with the command below:
    - MacOS:
    `brew install blacktop/tap/ipsw`
    - Ubuntu:
    `sudo snap install ipsw`
- This installs the IPSW Toolset, including class-dump and swift-dump.
- **Step 2: Verify IPSW Toolset Installation**
    - Check if IPSW was installed successfully by running:
    `ipsw --help`
    - This command should display a list of available commands, such as class-dump and swift-dump.
- **Step 3: Install Swift**
    - You can install the Swift with the instructions below:
    - MacOS: Install XCode (which bundles Swift) or use the standalone macOS Package Installer.
    - Ubuntu: 
    ```bash
    sudo apt install -y curl
    curl -L https://swiftlygo.xyz/install.sh | bash
    sudo swiftlygo install latest
    ```
- **Step 4: Verify Swift Installation**
    - Check if Swift was installed successfully by running:
    `swift --help`
    - This command should display a list of available commands, such as build and run.

### Part 2: Extract the IPA File
- The next step is to extract the contents of your IPA file.
- **Step 1: Unzip the IPA File**
    - An IPA is essentially a ZIP archive containing the app’s code and resources. You can extract it using unzip:

    - Navigate to the directory where your IPA is located and run: `unzip ./DVIA-v2.ipa`
    - This extracts the contents of the IPA to the specified output directory. The extracted contents will include a folder named Payload which contains the .app directory for the app.

- **Step 2: Locate the App Binary**
    - Inside the Payload folder, you'll find the .app folder, which contains the app’s binary (usually a file without an extension). And the app binary is located inside the .app folder.

    - For example, if the app is called DVIA-v2, the binary would be found here: `./Payload/DVIA-v2.app/DVIA-v2`
    - This file is the main binary that you will use for decompiling.
### Part 3: Dumping Objective-C Classes Using class-dump
- Now that you've located the app binary, you can use class-dump to extract the Objective-C classes.
- **Step 1: Run class-dump on the App Binary**
    - Use the ipsw class-dump command to dump the Objective-C classes from the binary: `ipsw class-dump ./Payload/DVIA-v2.app/DVIA-v2 --headers -o ./class_dump`
    - This command extracts all the Objective-C class headers from the app binary and saves them in the specified output directory.
- **Step 2: Review Dumped Headers**
    - Once the class-dump process is complete, you can navigate to the output directory and review the extracted header files, which will contain information about the app's Objective-C classes, methods, and properties.

### Part 4: Dumping Swift Classes Using swift-dump
- If the app is written in Swift, you can use swift-dump to extract and demangle Swift class and method names.
- **Step 1: Run swift-dump on the App Binary**
    - Use the ipsw swift-dump command to extract Swift class information from the binary:

    - macOS:
    ```bash
    ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 > ./swift_dump_mangled.txt
    ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 --demangle > ./swift_dump_demangled.txt
    ```
    - Ubuntu:
    ```bash
    SWIFT_DEMANGLE="$(find /usr/libexec -type f -executable -name "swift-demangle")"
    ​
    ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 > ./swift_dump_mangled.txt
    ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 | $SWIFT_DEMANGLE --simplified > ./swift_dump_demangled.txt
    ```
    - This command extracts all Swift classes and mangled and demangled method names, saving them in the specified file.

- **Step 2: Review Demangled Swift Symbols**
    - Once swift-dump finishes running, go to the output directory and review the dumped Swift symbols. The demangled symbols will include class names, method names, and other Swift metadata that you can analyze.

### Part 5: Automating the Process for a Single IPA File
- If you want to automate this process for a single IPA file, you can use the following script:
```bash
#!/bin/bash
​
# Check if an IPA file was provided
if [ -z "$1" ]; then
echo "Usage: $0 <path_to_ipa_file>"
exit 1
fi
​
IPA_FILE="$1"
​
# Check if the IPA file exists
if [ ! -f "$IPA_FILE" ]; then
echo "[@] Error: IPA file not found!"
exit 1
fi
​
# Get the app name from the IPA file
APP_NAME="$(basename ""$IPA_FILE"" .ipa)"
OUTPUT_DIR="$(dirname ""$IPA_FILE"" | xargs readlink -f)"
​
# Create output directory
OUTPUT_DIR="$OUTPUT_DIR/$APP_NAME"
mkdir -p "$OUTPUT_DIR"
​
# Unzip the IPA contents
UNZIP_DIR="$OUTPUT_DIR/_extracted"
echo "[*] Extracting IPA contents..."
mkdir -p "$UNZIP_DIR"
unzip -q "$IPA_FILE" -d "$UNZIP_DIR"
​
# Locate the .app directory
APP_PATH=$(find "$UNZIP_DIR" -name "*.app" -type d)
​
if [ -z "$APP_PATH" ]; then
echo "[@] No .app found in $UNZIP_DIR, exiting..."
exit 1
fi
​
BINARY="$APP_PATH/$(basename ""$APP_PATH"" .app)"
​
# Check if the binary exists (file without an extension in the .app folder)
if [ ! -f "$BINARY" ]; then
echo "[@] No binary found in $APP_PATH, exiting..."
exit 1
fi
​
# Create directories for class dumps
CLASS_DUMP_OUTPUT="$OUTPUT_DIR/class_dump"
SWIFT_DUMP_OUTPUT="$OUTPUT_DIR/swift_dump"
mkdir -p "$CLASS_DUMP_OUTPUT"
mkdir -p "$SWIFT_DUMP_OUTPUT"
​
# Dump Objective-C classes using class-dump
echo "[*] Dumping Objective-C classes for $APP_NAME..."
ipsw class-dump "$BINARY" --headers -o "$CLASS_DUMP_OUTPUT"
​
# Dump Swift classes using swift-dump
echo "[*] Dumping Swift classes for $APP_NAME..."
ipsw swift-dump "$BINARY" > "$SWIFT_DUMP_OUTPUT/$APP_NAME-mangled.txt"
ipsw swift-dump "$BINARY" --demangle > "$SWIFT_DUMP_OUTPUT/$APP_NAME-demangled.txt"
​
echo "[+] Decompilation completed for $APP_NAME"
This script automates the process of dumping both Objective-C and Swift classes for apps.
```

