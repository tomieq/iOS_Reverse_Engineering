#Demangles Swift class, function, and variable names
#@author LaurieWired
#@category Swift

# NOTES:
# Requires Swift to be installed on the machine
# Takes some time to run for larger applications

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
from java.lang import System
import subprocess

def demangle_swift_name(mangled_name):
    os_name = System.getProperty("os.name").lower()

    # Determine the correct command based on the OS
    if "mac" in os_name:
        cmd = 'xcrun swift-demangle --simplified --compact'
        mangled_name = "'{}'".format(mangled_name)  # Surround with single quotes

    else:
        cmd = 'swift-demangle --simplified --compact'

    # Run as subprocess
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    proc.stdin.write(mangled_name)
    proc.stdin.close()
    demangled = proc.stdout.read().strip()
    proc.wait()
   
    # Return demangler output. If it's not a Swift type, it will just return original name
    return demangled

def get_arguments(name):
   tmp = name.split("(", 1)
   if len(tmp) > 1:
      return "(" + tmp[1]
   return ""

def clean_demangled_name(name):
    # Remove everything after the opening parenthesis (removes function arguments)
    tmp = name.split("(", 1)[0]
    parts = tmp.split(" ")
    name = parts[-1].strip("'")
   
    # Replace spaces and other undesired characters
    name = name.replace(" ", "_")
    name = name.replace("<", "_")
    name = name.replace(">", "_")

    return name

def beautify_swift_program():

    # Demangle function names
    print("Renaming functions")
    for func in currentProgram.getFunctionManager().getFunctions(True):
        demangled_name = demangle_swift_name(func.getName())
        cleaned_name = clean_demangled_name(demangled_name)
        
       
        if cleaned_name != func.getName():
            args = get_arguments(demangled_name)
            print("Original: {}, New: {}{}".format(func.getName(), cleaned_name, args))
           
            # Set new function name and comment
            func.setComment("Original: {}\nDemangled: {}\n{}{}".format(func.getName(), demangled_name, cleaned_name, args))
            func.setName(cleaned_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)

    # Demangle labels if they are Swift types
    print("\nRenaming labels. May take some time...")
    for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.LABEL:
            demangled_name = demangle_swift_name(symbol.getName())
            cleaned_name = clean_demangled_name(demangled_name)
           
            if cleaned_name != symbol.getName():
                args = get_arguments(demangled_name)
                print("Original: {}, New: {}{}".format(symbol.getName(), cleaned_name, args))
               
                # Set new label name and comment
                # Ghidra already also renames pointers to labels as well
                currentProgram.getListing().setComment(symbol.getAddress(), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, "Original: {}\nDemangled: {}\n{}{}".format(symbol.getName(), demangled_name, cleaned_name, args))
                symbol.setName(cleaned_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)

beautify_swift_program()
