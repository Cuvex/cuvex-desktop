# CUVEX Decryption Tool for Desktop #

Cuvex Decryption Tool is a desktop application that allows Cuvex owners to decrypt the content of their NFC encrypted cards without the Cuvex device.  

You can explore all the Cuvex device and Company information [here](https://cuvex.io/).

The source code for the Cuvex firmware can be explored [here](https://github.com/Cuvex/Firmware).

## How to Use This Tool ##

### Windows Instructions ###

1. Export the content of a card in a binary file using the Cuvex App in an Android or iPhone device with NFC support.
2. Send the binary file to your PC
3. Go to the [downloads page](https://github.com/Cuvex/cuvex-desktop/releases) and download the zip file for windows to a location you can easily find, like your Downloads folder.
4. We **STRONGLY RECOMMEND** to verify your downloaded package, so you can avoid any tampering or corruption of the file.
5. In the same downloads page, find the SHA256 checksum for the windows package. It should be a string of 64 alphanumeric chars, for example:  
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```  
Copy this entire string carefully. You will use this value later in the verification step.  
6. Open PowerShell from the windows menu or press Windows + S and type 'PowerShell' and open the application.  
7. Navigate to the Download Folder in PowerShell by typing the Path to that folder.  
In most cases, the browser will save the downloaded file in the 'Downloads' folder, so if this is your case, in PowerShell type or paste the following and hit Enter:  
```  
cd $HOME\Downloads
```  
8. To verify your download, type the following command, replacing YOUR-FILE.zip with the name of your downloaded file, and REFERENCE_CHECKSUM with the SHA-256 checksum you copied in step 5:  
```
if ((Get-FileHash -Algorithm SHA256 YOUR-FILE.zip).Hash -eq "REFERENCE_CHECKSUM") {Write-Output 'OK'} else { Write-Output 'Error'}  
```  
Press Enter to run the command.  
9. If the checksum matches, you will see:  
```  
OK
```  
In this case you can proceed to use the application.  
Otherwise, the output will be:  
```  
Error
```  
If this happens, you **SHOULD NOT** use the application. Try downloading the file again, as it may have been corrupted.  
10. If the verification result is OK, unzip the downloaded file and execute it as any other Windows application. Follow the instructions to decrypt your card.  For security reasons you can only decrypt one card at a time, and you will be required to disconnect from internet while you use this tool.  
This application does not require to be installed in your system.  We recommend that you delete the zip file and the cuvex.exe executable file when you finish using them, and when you need them again, download them from the official website and follow these instructions.  

### MacOSX Instructions ###

1. Export the content of a card in a binary file using the Cuvex App in an Android or iPhone device with NFC support.
2. Send the binary file to your Mac OS computer.  
3. Go to the [downloads page](https://github.com/Cuvex/cuvex-desktop/releases/tag/v1.1.0) and download the file corresponding to your computer's processor.  If you have an Apple M series processor (1, 2, 3, 4 or later) select the file that contains the text "macos-arm64" in the name.  If your computer has an Intel processor, select the file that contains the text "macos-x86_64". Save the file in a location that you can easily locate, like your Downloads folder.
4. We **STRONGLY RECOMMEND** to verify your downloaded file, to avoid any tampering or corruption of the application.
5. In the same downloads page, find the SHA256 checksum corresponding to the file you downloaded. It should be a string of 64 alphanumeric chars, for example:  
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```  
Copy this entire string carefully. You will use this value later in the verification step.  
6. Open a Terminal. Press Command + Space, type Terminal, and press Enter.  
7. Navigate to the Download Folder in the Terminal window by typing the Path to that folder.  
In most cases, the browser will save the downloaded file in the 'Downloads' folder, so if this is your case, in the Terminal window type or paste the following and hit Enter:  
```  
cd ~/Downloads
```  
8. To verify your download, type the following command, replacing YOUR-FILE.zip with the name of your downloaded file, and REFERENCE_CHECKSUM with the SHA-256 checksum you copied in step 5:  
```
if [ "$(shasum -a 256 YOUR-FILE.zip | awk '{print $1}')" = "REFERENCE_CHECKSUM" ]; then echo "OK"; else echo "Error"; fi  
```  
Press Enter to run the command.  
9. If the checksum matches, you will see:  
```  
OK
```  
In this case you can proceed to use the application.  
Otherwise, the output will be:  
```  
Error
```  
If this happens, you **SHOULD NOT** use the application. Try downloading the file again, as it may have been corrupted.  
10. If the verification result is OK, unzip the downloaded file and execute it as any other Mac OSX application.  
In case you are using Safari, it may request your permission to allow "objects.githubusercontent.com" to download files to your computer. You must allow it.
If the Operative System shows you a dialog with the text "macOS cannot verify the developer of cuvex.app. Are you sure you want to open it?", or "Cuvex is an app created by (the name of your navigatior: Safari, Chrome, Firefox, etc.)  Are you sure you want to open it?", or a similar text, you must click on the button "Open".  
In some cases it will be necessary to open System Settings, select "Security & privacy", in the "General" tab go to the "Allow apps downloaded from" section, and right from the text "cuvex was block from use because it is not from an identified developer", click on the button "Open Anyway".  
Follow the instructions to decrypt your card.  For security reasons you can only decrypt one card at a time, and you will be required to disconnect from internet while you use this tool.  
This application does not require to be installed in your system.  We recommend that you delete the zip file and the cuvex.app executable file when you finish using them, and when you need them again, download them from the official website and follow these instructions.  

### Linux Instructions ###

1. Export the content of a card in a binary file using the Cuvex App in an Android or iPhone device with NFC support.
2. Send the binary file to your computer.  
3. Go to the [downloads page](https://github.com/Cuvex/cuvex-desktop/releases) and download the file corresponding to linux.  Save the file in a location that you can easily locate, like your Downloads folder.  
4. We **STRONGLY RECOMMEND** to verify your downloaded file, to avoid any tampering or corruption of the application.
5. In the same downloads page, find the SHA256 checksum corresponding to the file you downloaded. It should be a string of 64 alphanumeric chars, for example:  
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```  
Copy this entire string carefully. You will use this value later in the verification step.  
6. Open a Terminal: Press Ctrl + Alt + T or open Terminal from the applications menu.  
7. Navigate to the Download Folder in the Terminal by typing the Path to that folder.  
In most cases, the browser will save the downloaded file in the 'Downloads' folder, so if this is your case, in the Terminal window type or paste the following and hit Enter:  
```  
cd ~/Downloads
```  
8. To verify your download, type the following command, replacing YOUR-FILE.zip with the name of your downloaded file, and REFERENCE_CHECKSUM with the SHA-256 checksum you copied in step 5:  
```
if [ "$(shasum -a 256 YOUR-FILE.zip | awk '{print $1}')" = "REFERENCE_CHECKSUM" ]; then echo "OK"; else echo "Error"; fi  
```  
Press Enter to run the command.  
9. If the checksum matches, you will see:  
```  
OK
```  
In this case you can proceed to use the application.  
Otherwise, the output will be:  
```  
Error
```  
If this happens, you **SHOULD NOT** use the application. Try downloading the file again, as it may have been corrupted.  
10. If the verification result is OK, unzip the downloaded file.
11. Give execution permissions to the unziped file with:
```  
chmod +x /PATH/cuvex
```  
Replace /PATH with the absolute or relative path to the unzipped file.  
12. You can execute it by double clicking the file in your file manager window or with the following command in console (you have to navigate to the folder containing the excutable, or you can use its absolute or relative path):
```  
./cuvex
```  
Follow the instructions to decrypt your card.  For security reasons you can only decrypt one card at a time, and you will be required to disconnect from internet while you use this tool.  
This application does not require to be installed in your system.  We recommend that you delete the zip file and the cuvex.app executable file when you finish using them, and when you need them again, download them from the official website and follow these instructions.  
