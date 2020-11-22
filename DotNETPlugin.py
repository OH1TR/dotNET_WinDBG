from pykd import *
import time
import re as regex
import json
import os.path
from os import path

# sxe ld clrjit
#.loadby sos clr
#.load pykd
#!py c:\path\to\DotNETPlugin.py

dump_byte_array=1
dump_byte_array_path="c:\\Temp"
Debug=True
JsonDebug=True

bp_list = []

def Custom_print(to_print):
  if Debug == True:
    print(to_print)
  
def json_print(to_print):
  if JsonDebug == True:
    print(json.dumps(to_print, indent=2))


class parse_clrstack_output:

  def check_endofarg(self, line):
    if line=="":
      return True
    else:
      return False
	  
  def __init__(self):
    self.hexaPattern = "^[0-9a-fA-F]+ +[0-9a-fA-F]+ +.*$"
    self.ParamPatten = ".*PARAMETERS:$"
    self.param = 0
    self.global_arg = ""
    self.bp = ""
    self.args = []

  def parse(self, output):
    for line in output.splitlines():
      if self.check_endofarg(line):
        break
      else:
        self.global_arg = self.global_arg + line + "\n"
        hex = regex.search(self.hexaPattern, line)
        if hex:
          self.bp = line
        par = regex.search(self.ParamPatten, line)
        if par:
          self.param = 1
          continue
        if self.param == 1:
          self.args.append(line.strip())
    return self.global_arg, self.bp, self.args
	
class parse_objdump_output:	  
  def __init__(self):
    self.FieldsPatten = "^Fields:$"
    self.hexaPattern = "^[0-9a-fA-F].*$"
    self.status = 0
    self.field = 0
    self.fieldsarray = []

  def parse(self, output):
    for line in output.splitlines():
      fields = regex.search(self.FieldsPatten, line)
      if fields:
        self.field = 1
        continue
      if self.field == 1:
        if line == "None":
          self.status = 0
          self.field = 2
        else:
          hex = regex.search(self.hexaPattern, line)
          if hex:
            self.fieldsarray.append(line)
          self.status = 1
    return self.status, self.fieldsarray
		
class handle_magic(pykd.eventHandler):
  def getAddress(self, localAddr):
    res = pykd.dbgCommand("db " + localAddr)
    return res.split()[0].replace("`", "")

  def __init__(self):
    Custom_print("[.NET plugin] Beginning, loading breakpoints...")
    self.load_breakpoints()
    Custom_print("[.NET plugin] Setting breakpoints...")
    self.bp = []
    for bp in bp_list:
      cmd = "!bpmd "+bp[0]+" "+bp[1]
      dbgCommand(cmd)
      dbgCommand(cmd)
      try:
        output = dbgCommand("bl")
        dbgCommand("!bpmd -clearall")
        dbgCommand("bc *")
        for line in output.splitlines():
          words = line.split()
          address = self.getAddress(words[-1])
          Custom_print("[.NET plugin] breakpoint: "+bp[0]+" "+bp[1]+" "+words[-1]+"("+address+")")
          self.bp.append(pykd.setBp(int(address, 16), self.handle_bp))
      except:
        pass
    Custom_print( "[.NET plugin] Let's go...")
    Custom_print( "")
    pykd.go()
	
  def dump_byte_array_fct(self, output, offset):
    self.ok = 0
    self.size=""
    for line in output.splitlines():
      typere = regex.search("^Name:.*$", line)
      if typere:
        type = line.split(":")[1].replace(" ","")
        if type == "System.Byte[]":
          self.ok = 1
      sizere = regex.search("^Size:.*$", line)
      if sizere:
        self.size = line.split(":")[1].split("(")[0].replace(" ","")
    if self.ok == 1:
      print( "[.NET plugin] let's dump "+offset+"+8 Size:"+self.size )
      cmd = ".writemem "+dump_byte_array_path+"\\dump_"+str(int(time.time()))+"_"+offset+"_"+self.size+".dmp "+offset+"+8 L"+self.size
      Custom_print( "\t"+cmd )
      dbgCommand(cmd)
	
  def handle_bp(self):
        
    current_time=int(time.time())
    output_json={}
    output = dbgCommand("!CLRStack -p")
    output = dbgCommand("!CLRStack -p")
    argument = parse_clrstack_output()
    global_arg, bp, args = argument.parse(output)
	
    Custom_print( "[.NET plugin] Breakpoint: "+' '.join(bp.split()[2:]))
    output_json["bp"] = ''.join(bp.split()[2:])
    output_json["date"] = current_time
	
    try:
      if bp.split("(")[-1].split(")")[0] == "":
        Custom_print( "[.NET plugin] No argument..." )
        json_print(output_json)
        return False
    except:
      json_print(output_json)
      return False
	
    i=0
    args_json = {}
    for arg in args:
      fields_json = {}
      words = arg.split()
      Custom_print( "[.NET plugin] Argument "+str(i)+": "+words[0] )
      i = i+1
      cmd = "!DumpObj "+words[-1]
      Custom_print( "[.NET plugin] "+cmd )
      output = dbgCommand(cmd)
      f = parse_objdump_output()
      status, fields = f.parse(output)
      self.StrPattern = "String:.*"
      return_strArg = regex.findall(self.StrPattern, output)
      if status == 0:
        #No field
        Custom_print( "\t"+output.replace("\n","\n\t")+"\n" )
      else:
        #Parse fileds
        Custom_print( "\t"+output.replace("\n","\n\t")+"\n" )
        j = 0
        for field in fields:
          fieldarray=field.split()        
          if fieldarray[3] == "System.String":
            cmd = "!DumpObj "+fieldarray[-2]
            output = dbgCommand(cmd)
            self.badPattern = "this object has an invalid CLASS field"
            bad = regex.search(self.badPattern, output)
            if bad:
              fields_json[j] = {"Name": fieldarray[-1], "Type": fieldarray[3], "string": ""}
              j=j+1
              pass
            else:
              self.StrPattern = "String:.*"
              return_str = regex.findall(self.StrPattern, output)
              if return_str:
                fields_json[j] = {"Name": fieldarray[-1], "Type": fieldarray[3] , "string": ''.join(return_str[0].split()[1:])}
              else:
                fields_json[j] = {"Name": fieldarray[-1], "Type": fieldarray[3], "string": ""}
              Custom_print( "\t\t[.NET plugin] "+cmd)
              Custom_print( "\t\t"+output.replace("\n","\n\t\t")+"\n")
          else:
            fields_json[j] = {"Name": fieldarray[-1], "Type": fieldarray[3] , "value": fieldarray[6]}
          j=j+1
      if return_strArg:
        args_json[i-1] = {"name": words[0], "offset": words[-1], "fields": fields_json, "string": ''.join(return_strArg[0].split()[1:])}
      else:
        args_json[i-1] = {"name": words[0], "offset": words[-1], "fields": fields_json}
      if dump_byte_array == 1:
        #Dump if type is bytearray
        self.dump_byte_array_fct(output, words[-1])
      Custom_print( "\n")
    output_json["arguments"] = args_json
    json_print(output_json)
    return False

  def load_breakpoints(self):
    with open(sys.argv[1], 'r') as f:
      for line in f.readlines():
        if len(line)>0 and not line.startswith('#'):
            tokens=line.split('!')
            if(len(tokens)>1):
                bp_list.append([tokens[0],tokens[1]])

if __name__== "__main__":
  if(len(sys.argv)!=2):
    print("Usage: !py c:\path\\to\\DotNETPlugin.py c:\path\\to\\bp_list.txt")
    print("bp_file.txt is list of dll and method name pairs. Use DumpILCalls.py to generate")
    exit()
    
  if(not path.exists(dump_byte_array_path)):
    Custom_print("Warning, dump_byte_array_path does not exist:"+dump_byte_array_path)

    d_handle = handle_magic()
