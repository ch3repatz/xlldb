"""
XLLDB 1.0.0 pre-alpha (under active development)
by ch3repatz (ch3repatz@gmail.com)

Release history:
    1.0.0 pre-alpha  2016-08-20  Initial release (moved to GitHub at 2016-08-22)

XLLDB is a reverse engineering mini-framework written in pure Python. XLLDB covers some LLDB API
(http://lldb.llvm.org/cpp_reference/html/index.html) to make it more suitable for automating iOS
reverse engineering tasks.
"""

import sys
import os

# Try to add LLDB path to sys.path
XLLDB_LLDB_PATH = '/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/Python/'
if not os.path.exists(XLLDB_LLDB_PATH):
    raise ImportError('LLDB path "%s" is incorrect!' % XLLDB_LLDB_PATH)

# Add the XLLDB_LLDB_PATH path to sys.path
if XLLDB_LLDB_PATH not in sys.path:
    sys.path.insert(0, XLLDB_LLDB_PATH)

# Try to import LLDB
import lldb


class Debugger:
    """
    The class covers SBDebugger (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBDebugger.html)
    """

    def __init__(self, sb_debugger=None):
        """
        Init with SBDebugger class instance
        :param sb_debugger: SBDebugger class instance
        """
        self.sb_debugger = sb_debugger

    def command_interpreter(self):
        """
        An instance of CommandInterpreter class
        :return: an instance of CommandInterpreter class, the command interpreter for the debugger
        """
        return CommandInterpreter(self.sb_debugger.GetCommandInterpreter()) if self.valid() else None

    def targets_count(self):
        """
        Count of targets
        :return: count of targets or None (if self.valid() == False)
        """
        return self.sb_debugger.GetNumTargets() if self.valid() else None

    def targets(self):
        """
        Get a list [...] of targets
        :return: a list of Target class instances (may be empty if no targets of self.valid()==False)
        """
        return [Target(self.sb_debugger.GetTargetAtIndex(i)) for i in range(0, self.sb_debugger.GetNumTargets())] \
            if self.valid() else []

    def selected_target(self):
        """
        Get the selected target
        :return: the selected target or None (if no targets or self.valid() == False)
        """
        return Target(self.sb_debugger.GetSelectedTarget()) if self.valid() else None

    def valid(self):
        """
        Check if the debugger is valid
        :return: True if valid, false if is not valid or self.sb_debugger is None
        """
        return self.sb_debugger.IsValid() if self.sb_debugger else False


class Target:
    """
    The class covers SBTarget (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBTarget.html)
    """

    class TRIPLES:
        """
        The class contains arch-vendor-os triples
        """

        ARM64_IOS = 'arm64-apple-ios'

        # TODO: add the triple for ARMv7

    def __init__(self, sb_target=None):
        """
        Init with SBTarget class instance
        :param sb_target: SBTarget class instance
        """
        self.sb_target = sb_target

    def create_breakpoint_by_address(self, address, condition=None, thread=None, callback=None):
        """
        Create a breakpoint by an address
        :param address: the address
        :param condition: condition as a Python string
        :param thread: an instance of Thread class
        :param callback: a callback function or static method
        :return: True if succeeded, False otherwise
        """
        # Create a breakpoint
        return Breakpoint(
            self.sb_target.BreakpointCreateByAddress(address),
            condition=condition,
            thread=thread,
            callback=callback
        ).valid()

    def breakpoints(self):
        """
        A list of breakpoints
        :return: a list [...] of breakpoints
        """
        return [
            Breakpoint(self.sb_target.GetBreakpointAtIndex(i)) for i in range(0, self.sb_target.GetNumBreakpoints())
        ] if self.valid() else None

    def valid(self):
        """
        Check if the target is valid
        :return: True if valid, false if is not valid or self.sb_target is None
        """
        return self.sb_target.IsValid() if self.sb_target else False

    def debugger(self):
        """
        Get the debugger
        :return: Debugger instance or None
        """
        return Debugger(self.sb_target.GetDebugger()) if self.valid() else None

    def process(self):
        """
        Get the process
        :return: Process instance or None
        """
        return Process(self.sb_target.GetProcess()) if self.valid() else None

    def triple(self):
        """
        Get the arch-vendor-os triple
        :return: arch-vendor-os triple, see Target.TRIPLES
        """
        return self.sb_target.GetTriple() if self.valid() else None


class Process:
    """
    The class covers SBProcess (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBProcess.html)
    """

    def __init__(self, sb_process=None):
        """
        Init with SBProcess class instance
        :param sb_process: SBProcess class instance
        """
        self.sb_process = sb_process

    def valid(self):
        """
        Check if the process is valid
        :return: True if valid, false if is not valid or self.sb_process is None
        """
        return self.sb_process.IsValid() if self.sb_process else False

    def create_breakpoint_by_address(self, address, condition=None, thread=None, callback=None):
        """
        Create a breakpoint by an address
        :param address: the address
        :param condition: condition as a Python string
        :param thread: an instance of Thread class
        :param callback: a callback function or static method
        :return: True if succeeded, False otherwise
        """
        return self.target().create_breakpoint_by_address(
            address,
            condition=condition,
            thread=thread,
            callback=callback
        )

    def target(self):
        """
        Get the target
        :return: Target instance or None
        """
        return Target(self.sb_process.GetTarget()) if self.valid() else None

    def debugger(self):
        """
        Get the debugger
        :return: Debugger instance or None
        """
        return self.target().debugger()

    def threads(self):
        """
         A list [...] of threads
        :return: a list [...] of Thread instances (may be empty if no threads or the self.valid() == False)
        """
        return [Thread(self.sb_process.GetThreadAtIndex(i)) for i in range(0, self.sb_process.GetNumThreads())] \
            if self.valid() else []

    def selected_thread(self):
        """
        The selected thread
        :return: selected thread
        """
        return Thread(self.sb_process.GetSelectedThread()) if self.valid() else None

    def threads_count(self):
        """
        Count of threads
        :return: Count of threads or None (if the self.valid() is None)
        """
        return self.sb_process.GetNumThreads() if self.valid() else None

    def pid(self):
        """
        Process id
        :return: process id
        """
        return self.sb_process.GetProcessID() if self.valid() else None

    def breakpoints(self):
        """
        A list of breakpoints
        :return: a list [...] of breakpoints
        """
        return self.target().breakpoints() if self.valid() else None


class Thread:
    """
    The class covers SBThread (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBThread.html)
    """

    def __init__(self, sb_thread=None):
        """
        Init with SBThread class instance
        :param sb_thread: SBThread class instance
        """
        self.sb_thread = sb_thread

    def valid(self):
        """
        Check if the thread is valid
        :return: True if valid, false if is not valid or self.sb_thread is None
        """
        return self.sb_thread.IsValid() if self.sb_thread else False

    def create_thread_breakpoint_by_address(self, address, condition=None, callback=None):
        """
        Create a breakpoint by an address
        :param address: the address
        :param condition: condition as a Python string
        :param callback: a callback function or static method
        :return: True if succeeded, False otherwise
        """
        return self.target().create_breakpoint_by_address(
            address,
            condition=condition,
            thread=self,
            callback=callback
        )

    def id(self):
        """
        Thread ID
        :return: thread ID
        """
        return self.sb_thread.GetThreadID() if self.valid() else None

    def process(self):
        """
        Get the process
        :return: Process instance or None
        """
        return Process(self.sb_thread.GetProcess()) if self.valid() else None

    def target(self):
        """
        Get the target
        :return: Target instance or None
        """
        return self.process().target()

    def debugger(self):
        """
        Get the debugger
        :return: Debugger instance or None
        """
        return self.target().debugger()

    def frames(self):
        """
        A list [...] of frames
        :return: a list [...] of Frame instances (may be empty if no frames or the self.valid() == False)
        """
        return [Frame(self.sb_thread.GetFrameAtIndex(i)) for i in range(0, self.sb_thread.GetNumFrames())] \
            if self.valid() else []

    def frames_count(self):
        """
        The count of frames in the thread
        :return: frames count
        """
        return self.sb_thread.GetNumFrames() if self.valid() else 0

    def zero_frame(self):
        """
        Zero number frame
        :return: Frame instance or None if the thread is invalid or there is no zero frame
        """
        return Frame(self.sb_thread.GetFrameAtIndex(0)) if self.valid() else None

    def registers(self):
        """
        Thread (in fact, 0 frame) registers
        :return: thread registers
        """
        zero_frame = self.zero_frame()
        return zero_frame.registers() if zero_frame.valid() else None

    def pc(self):
        """
        Thread (in fact, 0 frame) pc register
        :return: thread pc register
        """
        zero_frame = self.zero_frame()
        return zero_frame.pc() if zero_frame.valid() else None

    def sp(self):
        """
        Thread (in fact, 0 frame) sp register
        :return: thread sp register
        """
        zero_frame = self.zero_frame()
        return zero_frame.sp() if zero_frame.valid() else None

    def fp(self):
        """
        Thread (in fact, 0 frame) fp register
        :return: thread fp register
        """
        zero_frame = self.zero_frame()
        return zero_frame.fp() if zero_frame.valid() else None


class Frame:
    """
    The class covers SBFrame (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBFrame.html)
    """

    def __init__(self, sb_frame=None):
        """
        Init with SBFrame class instance
        :param sb_frame: SBFrame class instance
        """
        self.sb_frame = sb_frame

    def valid(self):
        """
        Check if the frame is valid
        :return: True if valid, false if is not valid or self.sb_frame is None
        """
        return self.sb_frame.IsValid() if self.sb_frame else False

    def thread(self):
        """
        Get the thread
        :return: Thread instance or None
        """
        return Thread(self.sb_frame.GetThread()) if self.valid() else None

    def process(self):
        """
        Get the process
        :return: Process instance or None
        """
        return self.thread().process()

    def target(self):
        """
        Get the target
        :return: Target instance or None
        """
        return self.process().target()

    def debugger(self):
        """
        Get the debugger
        :return: Debugger instance or None
        """
        return self.target().debugger()

    def pc(self):
        """
        Get the pc register
        :return: pc register
        """
        return Register('pc', Register.ARM64_TYPES.UINT64, self.sb_frame.GetPC()) if self.valid() else None

    def sp(self):
        """
        Get the sp register
        :return: sp register
        """
        return Register('sp', Register.ARM64_TYPES.UINT64, self.sb_frame.GetSP()) if self.valid() else None

    def fp(self):
        """
        Get the fp register
        :return: fp register
        """
        if self.target().triple() == Target.TRIPLES.ARM64_IOS:
            return Register('fp', Register.ARM64_TYPES.UINT64, self.sb_frame.GetFP()) if self.valid() else None
        # TODO: FP (if any) for ARMv7
        else:
            return None

    def registers(self):
        """
        Get a dictionary <register name> = <an instance of Register class>
        :return: the dictionary <register name> = <an instance of Register class>
        """
        register_list = None
        if self.valid():
            if self.target().triple() == Target.TRIPLES.ARM64_IOS:
                # Get the actual register list
                registers = self.sb_frame.GetRegisters()
                # Init the resulting dict
                register_list = {}
                # Run through register groups
                for register_group in registers:
                    # Run through registers in the group
                    for register in register_group:
                        # Create an empty error object
                        sb_error = lldb.SBError()
                        # Get a type of the register
                        register_type = register.GetType().GetName()
                        # Get register name
                        register_name = register.GetName()
                        # Get register data
                        register_data = register.GetData()
                        # Cast the data to something readable, depending on the type
                        if register_type == Register.ARM64_TYPES.UINT64:
                            register_value = register_data.GetUnsignedInt64(sb_error, 0)
                        elif register_type == Register.ARM64_TYPES.UINT32:
                            register_value = register_data.GetUnsignedInt32(sb_error, 0)
                        elif register_type == Register.ARM64_TYPES.FLOAT:
                            register_value = register_data.GetFloat(sb_error, 0)
                        elif register_type == Register.ARM64_TYPES.DOUBLE:
                            register_value = register_data.GetDouble(sb_error, 0)
                        elif register_type == Register.ARM64_TYPES.VECTOR:
                            register_value = [register_data.GetUnsignedInt8(sb_error, i) for i in range(0, 16)]
                        else:
                            # Unknown reg type, ignore it: return register_list unchanged
                            return register_list
                        # Add the register to register list
                        register_list[register_name] = Register(register_name, register_type, register_value)
                # Add x29 to the list (duplicate fp)
                if 'fp' in register_list.keys():
                    register_list['x29'] = register_list['fp']
                # Add x30 to the list (duplicate lr)
                if 'lr' in register_list.keys():
                    register_list['x30'] = register_list['lr']
                # Add pc to the list
                pc = self.pc()
                if 'pc' not in register_list.keys() and pc:
                    register_list['pc'] = pc
                # Add sp to the list
                sp = self.sp()
                if sp:
                    register_list['sp'] = sp
                # Add flags
                if 'fpsr' in register_list.keys():
                    fprs = register_list['cpsr'].value()
                    register_list['nf'] = Register('nf', Register.ARM64_TYPES.BOOL, (fprs & 0x80000000) > 0)
                    register_list['zf'] = Register('zf', Register.ARM64_TYPES.BOOL, (fprs & 0x40000000) > 0)
                    register_list['cf'] = Register('cf', Register.ARM64_TYPES.BOOL, (fprs & 0x20000000) > 0)
                    register_list['vf'] = Register('vf', Register.ARM64_TYPES.BOOL, (fprs & 0x10000000) > 0)
        # TODO: ARMv7 support for registers mining :)
        return register_list


class Register:
    """
    The class contains info (name/type/value) about a register
    """

    class ARM64_TYPES:
        """
        The class contains a list of register types for ARM64
        """

        UINT64 = 'unsigned long'
        UINT32 = 'unsigned int'
        FLOAT  = 'float'
        DOUBLE = 'double'
        VECTOR = 'unsigned char __attribute__((ext_vector_type(16)))'
        BOOL   = 'bool'

    # TODO: Add register types class for ARMv7

    def __init__(self, register_name, register_type, register_value):
        """
        Initialization
        :param register_name: register name
        :param register_type: register rtype
        :param register_value: register value
        """
        self._name = register_name
        self._type = register_type
        self._value = register_value

    def name(self):
        """
        Get register name
        :return: register name
        """
        return self._name

    def type(self):
        """
        Get register type
        :return: register type (see Register.*_TYPES)
        """
        return self._type

    def value(self):
        """
        Get register value
        :return: register value
        """
        return self._value


class CommandReturn:
    """
    The class contains an OOP-friendly result of
    SBCommandInterpreter.HandleCommand("<some command>", SBReturnObject())
    """

    def __init__(self, output, error=None, succeeded=True):
        """
        Initialisation
        :param output: the command's output
        :param error: error message
        :param succeeded: True if the command run without errors
        :return:
        """
        self._succeeded = succeeded
        self._output = output
        self._error = error

    def succeeded(self):
        """
        Success or not
        :return: True if success, False otherwise
        """
        return self._succeeded

    def output(self):
        """
        Command's output
        :return: command's output
        """
        return self._output

    def error(self):
        """
        Error message
        :return: error message
        """
        return self._error


class CommandInterpreter:

    def __init__(self, command_interpreter=None):
        """
        Initialization
        :param command_interpreter: a command interpreter or None
        """
        self.sb_command_interpreter = command_interpreter

    def valid(self):
        """
        Check if the command interpreter is valid
        :return: True if valid, false if is not valid or self.sb_command_interpreter is None
        """
        return self.sb_command_interpreter.IsValid() if self.sb_command_interpreter else False

    def execute_command(self, command):
        """
        Execute LLDB command with LLDB command interpreter
        :param command: a command to execute
        :return: an instance of CommandReturn class containing the results of execution
        """
        # A return object
        return_object = lldb.SBCommandReturnObject()
        # If the command interpreter is valid, do the job
        if self.valid():
            # Handle command
            self.sb_command_interpreter.HandleCommand(command, return_object)
            # If the return object is not valid, return an error
            if not return_object.IsValid():
                return CommandReturn(output=None, error='The SBReturnObject instance is not valid', succeeded=False)
            # If If the return object is valid, analyze the results:
            succeeded = return_object.Succeeded()       # finished succeeded?
            # Return the result
            return CommandReturn(
                output=return_object.GetOutput() if succeeded else None,
                error=return_object.GetError(False) if not succeeded else None,
                succeeded=succeeded
            )
        # If the command interpreter is not valid, return an error
        else:
            return CommandReturn(output=None, error='The CommandInterpreter instance is not valid', succeeded=False)


class Breakpoint:
    """
    The class covers SBBreakpoint (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBBreakpoint.html)
    """

    def __init__(self, sb_breakpoint=None, condition=None, thread=None, callback=None):
        """
        Init the object
        :param sb_breakpoint: an instance of SBBreakpoint class
        :param condition: breakpoint condition
        :param thread: an instance of Thread class
        :param callback: a callback function or static method
        """
        if sb_breakpoint and sb_breakpoint.IsValid():
            self.sb_breakpoint = sb_breakpoint
            if condition:
                self.sb_breakpoint.SetCondition(condition)
            if thread and thread.valid():
                self.sb_breakpoint.SetThreadID(thread.id())
            if callback:
                self.sb_breakpoint.SetScriptCallbackFunction(callback)

    def valid(self):
        """
        Check if the breakpoint is valid
        :return: True if valid, false if is not valid or self.sb_breakpoint is None
        """
        return self.sb_breakpoint.IsValid() if self.sb_breakpoint else False

    def condition(self):
        """
        Breakpoint's condition if any
        :return: breakpoint's condition as Python string
        """
        return self.sb_breakpoint.GetCondition() if self.valid() else None

    def locations(self):
        """
        A list [...] of breakpoint's locations
        :return: list [...] of breakpoint's locations
        """
        return [
            BreakpointLocation(self.sb_breakpoint.GetLocationAtIndex(i))
            for i in range(0, self.sb_breakpoint.GetNumLocations())
        ] if self.valid() else None


class BreakpointLocation:
    """
    The class covers SBBreakpointLocation
    (http://lldb.llvm.org/cpp_reference/html/classlldb_1_1SBBreakpointLocation.html)
    """

    def __init__(self, sb_breakpoint_location=None):
        """
        Initialisation
        :param sb_breakpoint_location: an instance of SBBreakpointLocation class
        :return:
        """
        self.sb_breakpoint_location = sb_breakpoint_location

    def valid(self):
        """
        Check if the breakpoint is valid
        :return: True if valid, false if is not valid or self.sb_breakpoint is None
        """
        return self.sb_breakpoint_location.IsValid() if self.sb_breakpoint_location else False

    def load_address(self):
        """
        Getting location load address
        :return: location load address
        """
        return self.sb_breakpoint_location.GetLoadAddress() if self.valid() else None

    def condition(self):
        """
        Breakpoint location condition if any
        :return: breakpoint location condition as Python string
        """
        return self.sb_breakpoint_location.GetCondition() if self.valid() else None


def xlldb_test_function(debugger, command, result, internal_dict):
    """
    Just a test LLDB command xlldbtest
    """
    # TODO: THIS FUNCTION WILL BE REMOVED IN A FINAL VERSION!
    dbg = Debugger(debugger)
    print dbg.selected_target().create_breakpoint_by_address(
        0x195ecc0a0,
        thread=dbg.selected_target().process().selected_thread(),
        condition='$x0==1',
        callback='xlldb.callbackfunct'
    )

def __lldb_init_module(debugger, internal_dict):
    """
    Adding the test command xlldbtest
    """
    # TODO: THIS FUNCTION WILL BE REMOVED IN A FINAL VERSION!
    debugger.HandleCommand('command script add -f xlldb.xlldb_test_function xlldbtest')
