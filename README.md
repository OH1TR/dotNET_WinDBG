# dotNET_WinDBG

This python script is designed to automate .NET analysis with WinDBG. It can be used to analyse a PowerShell script or to unpack a binary packed using a .NET packer.

You can find more information and use cases on the Talos blog post: http://blog.talosintelligence.com/2017/07/unravelling-net-with-help-of-windbg.html

Be careful, the analysed binary/PowerShell script will be executed on the system. In malware analysis context, please use a Virtual Machine.

# Prerequisites

* WinDBG installed

* pykd extension: https://pykd.codeplex.com/

# Finding good break point candidates

Decompile assembly with ildasm and parse calls with DumpILCalls.py

```
ildasm target.exe /OUT=code.il /source /quo /uni
DumpILCalls.py code.il bp_list.txt
```

You can comment out methods with # on bp_list.txt

# Usage

Set break point after loading the .NET environment inside of your binary. Dll name varies, run assembly and use lm to find correct name. (*jit.dll)

Run until .NET is loaded.

Load SOS extension.

Load pykd extension.

Load dotNET_WinDBG

```
sxe ld mscorjit.dll
g
.cordll -ve -u -l
.load C:\Temp\pykd_ext_2.0.0.24\x86\pykd
!py c:\path\to\DotNETPlugin.py C:\path\to\bp_list.txt
```


# Configuration

The configuration is at the beginning of the python script:

```
dump_byte_array=1
dump_byte_array_path="c:\\users\\user\\Desktop"
Debug=False
JsonDebug=True
```

The dump_byte_array variable allows to automatically dump byte arrays in the dump_byte_array_path directory.

The Debug variable variable allows to display debug during the execution of the script.

The JsonDebug variable allows to display output in JSON format.


# Example for output

```
0:020> .loadby sos clr
0:020> .load pykd
0:020> !py c:\Users\lucifer\DotNETPlugin.py
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
