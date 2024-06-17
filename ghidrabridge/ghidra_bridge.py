import concurrent
import hashlib
import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from tqdm import tqdm
import re

class GhidraBridge():
    def __init__(self, ghidra_project_dir=None, cspec=None, processor=None):
        self.ghidra_project_dir = ghidra_project_dir
        self.cspec = cspec
        self.processor = processor

    def brute_force_processor(self, binary):
        list_of_processors = self.list_all_possible_processors()
        valid_processors = []
        for processor in list_of_processors:
            bridge = GhidraBridge(processor=processor)
            functions = bridge.get_all_function_names_and_addresses(binary)
            if functions != {}:
                valid_processors.append(processor)

        return valid_processors

    def list_all_possible_processors(self):
        return ['6502:LE:16:default',
        '65C02:LE:16:default',
        '68000:BE:32:default',
        '68000:BE:32:MC68030',
        '68000:BE:32:MC68020',
        '68000:BE:32:Coldfire',
        '8048:LE:16:default',
        '8051:BE:16:default',
        '80251:BE:24:default',
        '80390:BE:24:default',
        '8051:BE:24:mx51',
        '8085:LE:16:default',
        'AARCH64:LE:64:v8A',
        'AARCH64:BE:64:v8A',
        'AARCH64:LE:32:ilp32',
        'AARCH64:BE:32:ilp32',
        'AARCH64:LE:64:AppleSilicon',
        'ARM:LE:32:v8',
        'ARM:LE:32:v8T',
        'ARM:LEBE:32:v8LEInstruction',
        'ARM:BE:32:v8',
        'ARM:BE:32:v8T',
        'ARM:LE:32:v7',
        'ARM:LEBE:32:v7LEInstruction',
        'ARM:BE:32:v7',
        'ARM:LE:32:Cortex',
        'ARM:BE:32:Cortex',
        'ARM:LE:32:v6',
        'ARM:BE:32:v6',
        'ARM:LE:32:v5t',
        'ARM:BE:32:v5t',
        'ARM:LE:32:v5',
        'ARM:BE:32:v5',
        'ARM:LE:32:v4t',
        'ARM:BE:32:v4t',
        'ARM:LE:32:v4',
        'ARM:BE:32:v4',
        'avr32:BE:32:default',
        'avr8:LE:16:default',
        'avr8:LE:16:extended',
        'avr8:LE:16:atmega256',
        'avr8:LE:24:xmega',
        'CP1600:BE:16:default',
        'CR16C:LE:16:default',
        'Dalvik:LE:32:default',
        'Dalvik:LE:32:DEX_Base',
        'Dalvik:LE:32:DEX_KitKat',
        'Dalvik:LE:32:ODEX_KitKat',
        'Dalvik:LE:32:DEX_Lollipop',
        'Dalvik:LE:32:Marshmallow',
        'Dalvik:LE:32:DEX_Nougat',
        'Dalvik:LE:32:DEX_Oreo',
        'Dalvik:LE:32:DEX_Pie',
        'Dalvik:LE:32:DEX_Android10',
        'Dalvik:LE:32:DEX_Android11',
        'Dalvik:LE:32:DEX_Android12',
        'Dalvik:LE:32:DEX_Android13',
        'DATA:LE:64:default',
        'DATA:BE:64:default',
        'HC05:BE:16:default',
        'HC05:BE:16:M68HC05TB',
        'HC08:BE:16:default',
        'HC08:BE:16:MC68HC908QY4',
        'HCS08:BE:16:default',
        'HCS08:BE:16:MC9S08GB60',
        'HC-12:BE:16:default',
        'HCS-12:BE:24:default',
        'HCS-12X:BE:24:default',
        'HCS12:BE:24:default',
        'JVM:BE:32:default',
        'M8C:BE:16:default',
        '6809:BE:16:default',
        'H6309:BE:16:default',
        '6805:BE:16:default',
        'MCS96:LE:16:default',
        'MIPS:BE:32:default',
        'MIPS:LE:32:default',
        'MIPS:BE:32:R6',
        'MIPS:LE:32:R6',
        'MIPS:BE:64:default',
        'MIPS:LE:64:default',
        'MIPS:BE:64:micro',
        'MIPS:LE:64:micro',
        'MIPS:BE:64:R6',
        'MIPS:LE:64:R6',
        'MIPS:BE:64:64-32addr',
        'MIPS:LE:64:64-32addr',
        'MIPS:LE:64:micro64-32addr',
        'MIPS:BE:64:micro64-32addr',
        'MIPS:BE:64:64-32R6addr',
        'MIPS:LE:64:64-32R6addr',
        'MIPS:BE:32:micro',
        'MIPS:LE:32:micro',
        'pa-risc:BE:32:default',
        'PIC-12:LE:16:PIC-12C5xx',
        'PIC-16:LE:16:PIC-16',
        'PIC-16:LE:16:PIC-16F',
        'PIC-16:LE:16:PIC-16C5x',
        'PIC-17:LE:16:PIC-17C7xx',
        'PIC-18:LE:24:PIC-18',
        'PIC-24E:LE:24:default',
        'PIC-24F:LE:24:default',
        'PIC-24H:LE:24:default',
        'dsPIC30F:LE:24:default',
        'dsPIC33F:LE:24:default',
        'dsPIC33E:LE:24:default',
        'dsPIC33C:LE:24:default',
        'PowerPC:BE:32:default',
        'PowerPC:LE:32:default',
        'PowerPC:BE:64:default',
        'PowerPC:BE:64:64-32addr',
        'PowerPC:LE:64:64-32addr',
        'PowerPC:LE:64:default',
        'PowerPC:BE:32:4xx',
        'PowerPC:LE:32:4xx',
        'PowerPC:BE:32:MPC8270',
        'PowerPC:BE:32:QUICC',
        'PowerPC:LE:32:QUICC',
        'PowerPC:BE:32:e500',
        'PowerPC:LE:32:e500',
        'PowerPC:BE:64:A2-32addr',
        'PowerPC:LE:64:A2-32addr',
        'PowerPC:BE:64:A2ALT-32addr',
        'PowerPC:LE:64:A2ALT-32addr',
        'PowerPC:BE:64:A2ALT',
        'PowerPC:LE:64:A2ALT',
        'PowerPC:BE:64:VLE-32addr',
        'PowerPC:BE:64:VLEALT-32addr',
        'RISCV:LE:64:RV64I',
        'RISCV:LE:64:RV64IC',
        'RISCV:LE:64:RV64G',
        'RISCV:LE:64:RV64GC',
        'RISCV:LE:64:default',
        'RISCV:LE:32:RV32I',
        'RISCV:LE:32:RV32IC',
        'RISCV:LE:32:RV32IMC',
        'RISCV:LE:32:RV32G',
        'RISCV:LE:32:RV32GC',
        'RISCV:LE:32:default',
        'sparc:BE:32:default',
        'sparc:BE:64:default',
        'SuperH:BE:32:SH-2A',
        'SuperH:BE:32:SH-2',
        'SuperH:BE:32:SH-1',
        'SuperH4:BE:32:default',
        'SuperH4:LE:32:default',
        'TI_MSP430:LE:16:default',
        'TI_MSP430X:LE:32:default',
        'tricore:LE:32:default',
        'tricore:LE:32:tc29x',
        'tricore:LE:32:tc172x',
        'tricore:LE:32:tc176x',
        'V850:LE:32:default',
        'x86:LE:32:default',
        'x86:LE:32:System Management Mode',
        'x86:LE:16:Real Mode',
        'x86:LE:16:Protected Mode',
        'x86:LE:64:default',
        'z80:LE:16:default',
        'z8401x:LE:16:default',
        'z180:LE:16:default',
        'z182:LE:16:default']

    def _execute_blocking_command(self, command_as_list):
        if command_as_list != None:
            #print("Executing command: {}".format(command_as_list))
            result = subprocess.run(command_as_list, capture_output=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            return result

    def generate_script_for_getting_registers_for_function(self, target_function):
        script = """from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities

# Tested with Ghidra v9.1 and v9.1.1, future releases are likely to simplify
# and/or expand the EmulatorHelper class in the API.

# == Helper functions ======================================================
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getSymbolAddress(symbolName):
    symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName, None)
    if (symbol != None):
        return symbol.getAddress()
    else:
        raise("Failed to locate label: {}".format(symbolName))

def getProgramRegisterList(currentProgram):
    pc = currentProgram.getProgramContext()
    return pc.registers

# == Main function =========================================================
def main():
    CONTROLLED_RETURN_OFFSET = 0

    # Identify function to be emulated
    mainFunctionEntry = getSymbolAddress("FUN_00400dd0")

    # Establish emulation helper, please check out the API docs
    # for `EmulatorHelper` - there's a lot of helpful things
    # to help make architecture agnostic emulator tools.
    emuHelper = EmulatorHelper(currentProgram)

    # Set controlled return location so we can identify return from emulated function
    controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET)

    # Set initial RIP
    mainFunctionEntryLong = int("0x{}".format(mainFunctionEntry), 16)
    emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)

    # For x86_64 `registers` contains 872 registers! You probably don't
    # want to print all of these. Just be aware, and print what you need.
    # To see all supported registers. just print `registers`.
    # We won't use this, it's just here to show you how to query
    # valid registers for your target architecture.
    registers = getProgramRegisterList(currentProgram)
    print("registers_start")
    print(registers)
    print("registers_end")
    # Cleanup resources and release hold on currentProgram
    emuHelper.dispose()

# == Invoke main ===========================================================
main()""".replace("<function>",target_function)

        return script

    def generate_function_rename_script(seld, old_function_name, new_function_name):
        script = """# Import the necessary Ghidra modules
from ghidra.program.model.listing import FunctionManager
from ghidra.util.exception import DuplicateNameException
from ghidra.util.exception import InvalidInputException
from ghidra.program.model.symbol import RefType, SymbolType

# Get the current program
program = getCurrentProgram()

# Get the function manager for the current program
function_manager = program.getFunctionManager()

def get_function_by_name(name):
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getSymbols(name)
    for symbol in symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            return getFunctionAt(symbol.getAddress())
    return None
SymbolType
def rename_function(function, new_name):
    try:


        # Rename the function
        function.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
    except DuplicateNameException as e:
        print("Error: Duplicate function name - {}".format(e))
    except InvalidInputException as e:
        print("Error: Invalid input - {}".format(e))
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))

# Example usage:
# Specify the address of the function you want to rename
function_address = get_function_by_name("<old_name>")  # Change this to the address of your function
new_function_name = "<new_name>"  # Change this to the new name you want to assign

# Rename the function
rename_function(function_address, new_function_name)""".replace("<old_name>",f"{old_function_name}").replace("<new_name>",f"{new_function_name}")
        

        return script


    def generate_control_flow_script(self, function_name):
        script = """from ghidra.program.model.symbol import RefType, SymbolType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address
from ghidra.program.model.block import BasicBlockModel, CodeBlockReferenceIterator
from ghidra.program.model.pcode import PcodeOp

def get_function_by_name(name):
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getSymbols(name)
    for symbol in symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            return getFunctionAt(symbol.getAddress())
    return None

def find_reachable_functions(function):
    monitor = ConsoleTaskMonitor()
    called_functions = set()
    to_process = [function]

    while to_process:
        current_function = to_process.pop()
        if current_function in called_functions:
            continue
        called_functions.add(current_function)
        
        # Get the instructions in the function
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(current_function.getBody(), True)
        
        for instruction in instructions:
            if instruction.getFlowType().isCall():
                called_func = getFunctionAt(instruction.getFlows()[0])
                if called_func and called_func not in called_functions:
                    to_process.append(called_func)
    
    return called_functions

def main():
    function_name = <name>
    function = get_function_by_name(function_name)
    if function is None:
        print("Function "+function_name+" not found.")
        return

    reachable_functions = find_reachable_functions(function)
    
    print("***")
    for func in reachable_functions:
        print(" "+func.getName())
    print("***")
if __name__ == "__main__":
    main()

""".replace("<name>",f"'{function_name}'")
        
        return script

    def generate_get_cross_references_to_function_name(self,name):
        script = """fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)
for func in funcs:
  if func.getName() == "<name>":
    print("Found '<name>' @ 0x{}".format(func.getEntryPoint()))
    entry_point = func.getEntryPoint()
    references = getReferencesTo(entry_point)
    for xref in references:
      print(xref)""".replace("<name>", name)
        
        return script

    def generate_decom_for_function(self, function_name):

        script = """from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)

# here we assume there is only one function named `main`
function = getGlobalFunctions('<name>')[0]

# decompile the function and print the pseudo C
results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
print(results.getDecompiledFunction().getC())""".replace("<name>", function_name)
        
        return script

    def generate_get_function_address_by_name(self, name):

        script = """# Note that multiple functions can share the same name, so Ghidra's API
# returns a list of `Function` types. Just keep this in mind.
name = "<name>"
funcs = getGlobalFunctions(name)
print("Found {} function(s) with the name '{}'".format(len(funcs), name))
for func in funcs:
	print("{} is located at 0x{}".format(func.getName(), func.getEntryPoint()))""".replace("<name>", name)

        return script
    
    def generate_get_function_names_and_address(self):
        script = """fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True) # True means 'forward'
for func in funcs: 
    print("Function: {} - Address: 0x{}".format(func.getName(), func.getEntryPoint()))"""
        
        return script

    def generate_get_a_function_name_by_address(self, address):

        script = """# helper function to get a Ghidra Address type
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# get a FunctionManager reference for the current program
functionManager = currentProgram.getFunctionManager()

# getFunctionAt() only works with function entryPoint addresses!
# returns `None` if address is not the address of the first
# instruction in a defined function. Consider using
# getFunctionContaining() method instead.
addr = getAddress(<address>)
funcName = functionManager.getFunctionAt(addr).getName()
print(funcName)""".replace("<address>",address)

        return script

    def generate_ghidra_decom_script(self, path_to_save_decoms_to, file_to_save_script_to):

        script = """# SaveFunctions.py
        
# Import necessary Ghidra modules
from ghidra.program.model.listing import Function
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface
import os
import time
import re

# Function to save the decompiled C code of a function to a file
def save_function_c_code(function, output_directory):
    function_name = function.getName()
    function_c_code = decompile_function_to_c_code(function)
    
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    
    # Save the C code to a file
    current_epoch_time = int(time.time())

    # Combine the elements to create the file path
    output_file_path = os.path.join(
        output_directory,
        re.sub(r'[^\w\-\.\\/]', '_', "{}__{}__{}.c".format(
            function.getProgram().getName(),
            function_name,
            int(time.time())
        ))
    )

    with open(output_file_path, 'w') as output_file:
        output_file.write(function_c_code)

# Function to decompile a function to C code
def decompile_function_to_c_code(function):
    decompiler = get_decompiler(function.getProgram())
    result = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY)
    try:
        return result.getDecompiledFunction().getC()
    except:
        return ""

# Function to get the decompiler for the current program
def get_decompiler(program):
    decompiler_options = program.getOptions("Decompiler")
    decompiler_id = decompiler_options.getString("decompiler", "ghidra")
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    return decompiler

# Main function to iterate through all functions and save their C code
def save_all_functions_to_files():
    current_program = getCurrentProgram()
    listing = current_program.getListing()
    
    # Specify the output directory
    output_directory = r"<PATH>"
    
    # Iterate through all functions
    for function in listing.getFunctions(True):
        function_name = function.getName()
        save_function_c_code(function, output_directory)

# Run the main function
save_all_functions_to_files()
        """.replace("<PATH>", path_to_save_decoms_to)

        with open(file_to_save_script_to, "w") as file:
            file.write(script)

    def _check_if_ghidra_project_exists(self, project_folder, project_name):

        project_folder_path = Path(project_folder, project_name + ".gpr")

        return project_folder_path.exists()

    def start_headless_with_script(self, path_to_binary, path_to_script):
        binary_hash = self._hash_binary(path_to_binary)

        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "decom_script.py").resolve()
            self._construct_ghidra_headless_command(path_to_binary, path_to_script, binary_hash)

    def _construct_ghidra_headless_command(self, binary_path, script_path, binary_hash):

        binary_name = "analyzeHeadless.bat"

        # Check if the binary is on the PATH
        headless = shutil.which(binary_name)

        temp_script_path = Path(script_path)
        temp_script_dir = temp_script_path.parent
        Path(temp_script_dir).resolve()
        if headless is not None:
            pass#print(f"{binary_name} found at: {headless}")
        else:
            binary_name = "analyzeHeadless"

            # Check if the binary is on the PATH
            headless = shutil.which(binary_name)

            if headless is None:

                # Binary not found, prompt user to provide the path
                user_provided_path = input(f"{binary_name} not found on the PATH. Please provide the full path: ")

                # Verify if the provided path is valid
                if shutil.which(user_provided_path) is not None:
                    headless = user_provided_path
                    print(f"{binary_name} found at: {headless}")

                    headless = user_provided_path
                else:
                    raise Exception(f"Error: {binary_name} not found at the provided path.")

        tmp_dir = None
        if not self.ghidra_project_dir:
            tmp_dir = tempfile.TemporaryDirectory()
            ghidra_project_dir = tmp_dir.name
        else:
            ghidra_project_dir = self.ghidra_project_dir


        if self._check_if_ghidra_project_exists(ghidra_project_dir, binary_hash):
            #print("Processing existing project")
            commandStr = [
                headless,
                ghidra_project_dir,
                binary_hash,
                "-process",
                "-scriptPath",
                temp_script_dir,
                "-postScript",
                temp_script_path.name
            ]

        else:
            #print("Importing new project")
            commandStr = [
                headless,
                ghidra_project_dir,
                binary_hash,
                "-import",
                binary_path,
                "-scriptPath",
                temp_script_dir,
                "-postScript",
                temp_script_path.name
            ]

        if self.cspec != None:
            commandStr = commandStr + [
                "-cspec",
                self.cspec
            ]

        if self.processor != None:
            commandStr = commandStr + [
                "-processor",
                self.processor
            ]


        resp = self._execute_blocking_command(commandStr)

        if not ghidra_project_dir:
            ghidra_project_dir.cleanup()

        # Run Ghidra headless command
        return resp

    def _hash_binary(self, binary_path):
        with open(binary_path, 'rb') as f:
            binary_hash = hashlib.sha256(f.read()).hexdigest()
        return binary_hash

    def run_string_script_on_binary(self, string_script, path_to_binary):
        binary_hash = self._hash_binary(path_to_binary)
        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "script.py").resolve()
            with open(script_path, "w") as file:
                # Write some content to the file
                file.write(string_script)
            
            return self._construct_ghidra_headless_command(path_to_binary, script_path, binary_hash)

    def get_all_function_names_and_addresses(self, path_to_binary):
        script_contents = self.generate_get_function_names_and_address()
        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "rename_script.py").resolve()
            with open(script_path, "w") as file:
                file.write(script_contents)

            binary_hash = self._hash_binary(path_to_binary)
            response = self._construct_ghidra_headless_command(path_to_binary, script_path, binary_hash)

            # Regular expression pattern to extract function names and addresses
            pattern = r'Function: (\w+) - Address: (0x[\da-f]+)'

            # Using re.findall to extract all matches
            matches = re.findall(pattern, str(response))

            # Create a dictionary to store the results
            functions_dict = {}

            # Populate the dictionary with extracted data
            for match in matches:
                function_name, address = match
                functions_dict[function_name] = address


            return functions_dict

    def get_registers_for_function(self, path_to_binary, function):
        script_contents = self.generate_script_for_getting_registers_for_function(function)
        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "rename_script.py").resolve()
            with open(script_path, "w") as file:
                file.write(script_contents)

            binary_hash = self._hash_binary(path_to_binary)
            response = str(self._construct_ghidra_headless_command(path_to_binary, script_path, binary_hash))


            if "registers" not in response:
                raise Exception("Script run uncuccessfully")

            
            resp = response[response.find("registers_start")+len("registers_start"):response.rfind("registers")]

            resp = resp.split(",")

            registers = []
            for register in resp:
                register = register.strip("\n").strip(r"[").replace("[","").replace("]","").strip(r"]").strip("\\n").strip("'").strip().strip(" ")
                registers.append(register)


            return registers

    def refactor_function_name(self, path_to_binary, old_function_name, new_function_name):
        script_contents = self.generate_function_rename_script(old_function_name, new_function_name)
        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "rename_script.py").resolve()
            with open(script_path, "w") as file:
                file.write(script_contents)

            binary_hash = self._hash_binary(path_to_binary)
            response = self._construct_ghidra_headless_command(path_to_binary, script_path, binary_hash)
            return response
        
    def decompile_binaries_functions(self, path_to_binary, decom_folder):
        binary_hash = self._hash_binary(path_to_binary)
        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "decom_script.py").resolve()
            self.generate_ghidra_decom_script(decom_folder, script_path)
            self._construct_ghidra_headless_command(path_to_binary, script_path, binary_hash)

    def get_list_of_reachable_functions(self, path_to_binary,  function_name):
        binary_hash = self._hash_binary(path_to_binary)
        with tempfile.TemporaryDirectory() as tmpdirname:
            script_path = Path(tmpdirname, "script.py").resolve()
            script_contents  = self.generate_control_flow_script(function_name)

            with open(script_path, "w") as file:
                file.write(script_contents)

            extracted_text = self._extract_text_between_delimiters(str(self._construct_ghidra_headless_command(path_to_binary, script_path, binary_hash)))
            list_of_functions = extracted_text[0].replace("\\n", "").strip("\\").strip(function_name).strip().split(" ")
            return list_of_functions

    def _extract_text_between_delimiters(self, text):
        # Define the regular expression pattern to match text between ***
        pattern = r'\*\*\*(.*?)\*\*\*'
        # Use re.findall to find all matches in the text
        matches = re.findall(pattern, text, re.DOTALL)
        return matches

    def decompile_all_binaries_in_folder(self, path_to_folder, decom_folder):
        # Create a list to store all the file paths
        files_to_process = [file_path for file_path in Path(path_to_folder).iterdir() if file_path.is_file()]

        # Use a ProcessPoolExecutor to execute the decompilation in parallel
        with ProcessPoolExecutor() as executor:
            # Create a list of futures
            futures = [executor.submit(self.decompile_binaries_functions, file_path, decom_folder) for file_path in
                       files_to_process]

            # Use tqdm to show progress
            for _ in tqdm(concurrent.futures.as_completed(futures), total=len(files_to_process),
                          desc="Decompiling functions in binaries from {}".format(path_to_folder)):
                pass


if __name__ == '__main__':
    raise Exception("This is not a program entrypoint!")

