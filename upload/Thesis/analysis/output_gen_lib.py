import pyhidra
from binascii import hexlify
import zipfile
import os
from upload.Thesis.analysis.utilities import uncompress

launcher = pyhidra.HeadlessPyhidraLauncher()
launcher.start()

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import Varnode, VarnodeAST

MAX_FILE_SIZE = 100000


def get_prog_start(path):
    with pyhidra.open_program(path, project_location="generated_test", project_name="Proj1") as flat_api:
        return flat_api.getCurrentProgram().getMinAddress().getOffset()


def analyze_program(path):
    with pyhidra.open_program(path, project_location="generated_test", project_name="Proj1") as flat_api:
        print(f"Scanning '{path}'")
        currentProgram = flat_api.getCurrentProgram()
        currentFunctionChecked = None
        currentLocalMap = None

        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(flat_api.getCurrentProgram())

        def get_stack_var_from_varnode(func, varnode):
            if type(varnode) not in [Varnode, VarnodeAST]:
                raise Exception("Invalid value. Expected `Varnode` or `VarnodeAST`, got {}.".format(type(varnode)))

            bitness_masks = {
                '16': 0xffff,
                '32': 0xffffffff,
                '64': 0xffffffffffffffff,
            }

            try:
                addr_size = currentProgram.getMetadata()['Address Size']
                bitmask = bitness_masks[addr_size]
            except KeyError:
                raise Exception("Unsupported bitness: {}. Add a bit mask for this target.".format(addr_size))

            local_variables = func.getAllVariables()
            vndef = varnode.getDef()
            if vndef:
                vndef_inputs = vndef.getInputs()
                for defop_input in vndef_inputs:
                    defop_input_offset = defop_input.getAddress().getOffset() & bitmask
                    for lv in local_variables:
                        unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
                        if unsigned_lv_offset == defop_input_offset:
                            return lv

                # If we get here, varnode is likely a "acStack##" variable.
                hf = flat_api.get_high_function(func)
                lsm = hf.getLocalSymbolMap()
                for vndef_input in vndef_inputs:
                    defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
                    for symbol in lsm.getSymbols():
                        if symbol.isParameter():
                            continue
                        if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                            return symbol

            # unable to resolve stack variable for given varnode
            return None

        def resolveVarnode(var):
            global currentFunctionChecked
            global currentLocalMap

            sym = get_stack_var_from_varnode(currentFunctionChecked, var)
            return currentLocalMap.getSymbol(sym.getSymbol().getID())

        def read_string_from_memory(memory, address):
            data = []
            while True:
                byte = memory.getByte(address)
                if byte == 0:
                    break
                data.append(byte)
                address = address.next()
            return bytes(data).decode('utf-8')

        allocs = {}
        frees = set()

        def readCallCheck(args, output):
            sym = args[2]
            availableSpace = 0
            if sym.isUnique():
                resolvedSym = resolveVarnode(sym)
                availableSpace = resolvedSym.getSize()
            elif sym.isRegister():
                resolvedSym = sym.getHigh()
                if resolvedSym.getName() == 'UNNAMED':
                    return True
                availableSpace = allocs[resolvedSym.getName()]

            if availableSpace < args[3].getOffset():
                # print("Detected buffer overflow from call!")
                return False
            return True

        def freeCheck(args, output):
            sym = args[1]
            if not sym.isRegister():
                return True
            resolvedSym = sym.getHigh()
            symName = resolvedSym.getName()
            if symName not in frees:
                frees.add(symName)
            else:
                # print("Detected double free from call!")
                return False
            return True

        def fgetsCheck(args, output):
            args = args[1:]
            new_args = [args[2], args[0], args[1]]
            return readCallCheck(new_args, output)

        def markMalloc(args, output):
            mallocSize = args[1].getOffset()
            varName = output.getHigh().getName()
            if varName in frees:
                frees.remove(varName)
            allocs[varName] = mallocSize

            return True

        def printfCheck(args, output):
            sym = args[1]
            if sym.isUnique() and len(args) == 2:
                # print("Detected format vuln")
                return False
            return True

        def scanfCheck(args, output):
            sym = args[1]
            if sym.isUnique():
                sym = sym.getDef().getInputs()[1]
                memory = currentProgram.getMemory()

                # Convert the address to an Address object
                address_factory = currentProgram.getAddressFactory()
                address = address_factory.getAddress(hex(sym.getOffset()))

                # Read and print the string from memory
                string_value = read_string_from_memory(memory, address)
                if string_value == "%s":
                    # print("Scanf Buffer overflow!")
                    return False
            return True

        vuln_functions = {"read": lambda x, y: readCallCheck(x, y), "scanf": lambda x, y: scanfCheck(x, y),
                          "free": lambda x, y: freeCheck(x, y), "malloc": lambda x, y: markMalloc(x, y),
                          "fgets": lambda x, y: fgetsCheck(x, y), "printf": lambda x, y: printfCheck(x, y),
                          "__isoc99_scanf": lambda x, y: scanfCheck(x, y)}

        def check_function(func_name):
            global currentLocalMap
            global currentFunctionChecked

            function = currentFunctionChecked = flat_api.getFunction(func_name)
            if function is None:
                return []
            call_address = function.getEntryPoint()

            res = ifc.decompileFunction(function, 60, monitor)
            high_func = res.getHighFunction()

            local_variables = high_func.getLocalSymbolMap().getSymbols()
            local_symbol_map = currentLocalMap = high_func.getLocalSymbolMap()
            high_variables = local_symbol_map.getSymbols()

            # print(f"Local variables in function '{func_name}':")
            # for var in local_variables:
            #     var_address = var.getStorage().getMinAddress()
            #     var_type = var.getDataType()
            #     print(f"Address: {var_address}, Type: {var_type}")
            # print("============================")

            # Get the instruction at the call address
            instruction = flat_api.getInstructionAt(call_address)

            vuln_function_body = function.getBody()
            instruction_iterator = currentProgram.getListing().getInstructions(vuln_function_body, True)

            # Iterate through all instructions in 'vuln'
            called_functions = set()
            vulnerabilities = []
            for instruction in instruction_iterator:
                if instruction.getMnemonicString() == "CALL":
                    # Check if the call instruction targets a function
                    for ref in instruction.getReferencesFrom():
                        if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                            target_address = ref.getToAddress()
                            target_function = flat_api.getFunctionAt(target_address)
                            if target_function is not None:
                                fname = target_function.getName()
                                called_functions.add(fname)
                                if fname in vuln_functions:
                                    pcodeops = high_func.getPcodeOps(instruction.getAddress())
                                    op = pcodeops.next()
                                    inputs = op.getInputs()
                                    args = [inp.getAddress() if inp.isAddress() else hex(inp.getOffset()) for inp in
                                            inputs[1:]]
                                    # print(f"Found '{fname}' with args: {args}")
                                    isSafeCall = vuln_functions[fname](inputs, op.getOutput())
                                    if not isSafeCall:
                                        start = instruction.getAddress().getOffset()
                                        end = instruction.getAddress().getOffset() + instruction.getLength()
                                        prog_start_addr = currentProgram.getMinAddress().getOffset()
                                        # print(f"Vulnerable call between 0x{start:x} - 0x{end:x}")
                                        vulnerabilities.append(((start - prog_start_addr) / MAX_FILE_SIZE,
                                                                (end - prog_start_addr) / MAX_FILE_SIZE,
                                                                1))

            return vulnerabilities

        function_manager = currentProgram.getFunctionManager()
        functions = function_manager.getFunctions(True)
        total_vulns = ""

        for function in functions:
            function_name = function.getName()

            output_data = [f"{s1:.7f},{e1:.7f},{c}" for s1, e1, c in check_function(function_name)]
            output_data = ",".join(output_data)
            if output_data != '':
                total_vulns += output_data + ","

        total_vulns = total_vulns.split(',')[:-1]
        print(f"Recorded {int(len(total_vulns) / 3)}/5 vulns")
        print("============================")
        total_vulns = total_vulns[:15]
        total_vulns = ",".join(total_vulns)
        return total_vulns


def uncompress_analyze(zip_path):
    file_path = uncompress(zip_path)
    # Read and print the content of the file
    res = analyze_program(file_path)

    # os.remove(file_path)

    return res
