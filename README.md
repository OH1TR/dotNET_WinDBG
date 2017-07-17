# dotNET_WinDBG

This python script is designed to automate .NET analysis with WinDBG. It can be used to analyse a PowerShell script or to unpack a binary packed using a .NET packer.

You can find more information and use cases on the Talos blog post: http://blog.talosintelligence.com

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
