# dotNET_WinDBG

This python script is designed to automate .NET analysis with WinDBG. It can be used to analyse a PowerShell script or to unpack a binary packed using a .NET packer.

You can find more information and use cases on the Talos blog post: http://blog.talosintelligence.com

Be careful, the analysed binary/PowerShell script will be executed on the system. In malware analysis context, please use a Virtual Machine.

# Prerequisites

* WinDBG installed

* pykd extension: https://pykd.codeplex.com/

# Usage

Load SOS extension in WinDBG (to enable .NET analysis support)

```
.loadby sos clr
```

Load pykd extension

```
.load pykd
```

Load dotNET_WinDBG

```
!py c:\path\to\DotNETPlugin.py
```

Additionally, if the SOS extension does not load, you can use the following command to break point after loading the .NET environment inside of your binary. At this time, you should be able to load the SOS extension.

```
sxe ld clrjit ; g
```

# Configuration

The configuration is at the beginning of the python script:

```
dump_byte_array=1
dump_byte_array_path="c:\\users\\user\\Desktop\\"
Debug=False
JsonDebug=True

bp_list = [ ["system.dll", "System.Diagnostics.Process.Start"],
            ["system.dll", "System.Net.WebClient.DownloadFile"],
            ["mscorlib.dll", "System.Reflection.Assembly.Load"]
          ]
```

The dump_byte_array variable allows to automatically dump byte arrays in the dump_byte_array_path directory.

The Debug variable variable allows to display debug during the execution of the script.

The JsonDebug variable allows to display output in JSON format.

Finally the bp_list variable contains the analysed API. In the example, 3 APIs are tracked by the script.

# Example for output

```
0:020> .loadby sos clr
0:020> .load pykd
0:020> !py c:\Users\lucifer\Downloads\PYKD_BOOTSTRAPPER_2.0.0.13\DotNETPlugin_v3.py
{
  "date": 1500306926, 
  "bp": "System.Diagnostics.Process.Start(System.Diagnostics.ProcessStartInfo)", 
  "arguments": {
    "0": {
      "fields": {
        "0": {
          "Type": "System.String", 
          "Name": "fileName", 
          "string": "C:\\WINDOWS\\system32\\calc.exe"
        }, 
        "1": {
          "Type": "System.String", 
          "Name": "arguments", 
          "string": ""
        }, 
        "2": {
          "Type": "System.String", 
          "Name": "directory", 
          "string": "C:\\Users\\lucifer"
        }, 
        "3": {
          "Type": "System.String", 
          "Name": "verb", 
          "string": ""
        }, 
        "4": {
          "Type": "System.Int32", 
          "Name": "windowStyle", 
          "value": "0"
        }, 
        "5": {
          "Type": "System.Boolean", 
          "Name": "errorDialog", 
          "value": "0"
        }, 
        "6": {
          "Type": "System.IntPtr", 
          "Name": "errorDialogParentHandle", 
          "value": "0"
        }, 
        "7": {
          "Type": "System.Boolean", 
          "Name": "useShellExecute", 
          "value": "1"
        }, 
        "8": {
          "Type": "System.String", 
          "Name": "userName", 
          "string": ""
        }, 
        "9": {
          "Type": "System.String", 
          "Name": "domain", 
          "string": ""
        }, 
        "10": {
          "Type": "...rity.SecureString", 
          "Name": "password", 
          "value": "0000000000000000"
        }, 
        "11": {
          "Type": "System.String", 
          "Name": "passwordInClearText", 
          "string": ""
        }, 
        "12": {
          "Type": "System.Boolean", 
          "Name": "loadUserProfile", 
          "value": "1"
        }, 
        "13": {
          "Type": "System.Boolean", 
          "Name": "redirectStandardInput", 
          "value": "0"
        }, 
        "14": {
          "Type": "System.Boolean", 
          "Name": "redirectStandardOutput", 
          "value": "0"
        }, 
        "15": {
          "Type": "System.Boolean", 
          "Name": "redirectStandardError", 
          "value": "0"
        }, 
        "16": {
          "Type": "System.Text.Encoding", 
          "Name": "standardOutputEncoding", 
          "value": "0000000000000000"
        }, 
        "17": {
          "Type": "System.Text.Encoding", 
          "Name": "standardErrorEncoding", 
          "value": "0000000000000000"
        }, 
        "18": {
          "Type": "System.Boolean", 
          "Name": "createNoWindow", 
          "value": "0"
        }, 
        "19": {
          "Type": "System.WeakReference", 
          "Name": "weakParentProcess", 
          "value": "0000000000000000"
        }, 
        "20": {
          "Type": "....StringDictionary", 
          "Name": "environmentVariables", 
          "value": "0000000000000000"
        }, 
        "21": {
          "Type": "...tring,", 
          "Name": "environment", 
          "value": "instance"
        }
      }, 
      "name": "startInfo", 
      "offset": "0x0000025c1c572170"
    }
  }
}
```
