from unicorn import *
from unicorn.x86_const import *
import capstone
import pefile
import traceback
from capstone.x86 import *
import sys
import string
import itertools
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

mu = None
image_base = None
pw = ''
stop = False
correct_cnt=0
VM_MEMORY = 0x5F00000
VM_PROG = 0x5F27418
PW_MEMORY = 0x5F50398
PE_LOAD_ADDR = 0x5CB5000
TEXT_LOAD_ADDR = 0x5CB52C0
VERIFY_BLOCK_RVA = 0x5ce64c6-PE_LOAD_ADDR
VERIFY_BLOCK_ADDR = 0x5ce64c6
PREP_BUFFER_RVA = 0x5CE6F78-PE_LOAD_ADDR # Address where the password is mangled into
AFTER_VERIFIED_RVA = 0x5CE6FEC-PE_LOAD_ADDR # Address after the verifier returned
VERIFIER_START_RVA = 0x5CE6274-PE_LOAD_ADDR # First op within verifier 
VERIFIER_END_RVA = 0x5CE6933-PE_LOAD_ADDR # Last op within verifier

def load_pe_to_unicorn(pe_path):
    global image_base
    # Load the PE file
    pe = pefile.PE(pe_path)

    # Initialize Unicorn
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    # Get the base address of the module
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
    # Get virtual alignment 
    memory_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    memory_alignment = 4096
    # Load PE into emulator
    add_data_sections(uc, pe, image_base, memory_alignment)

        # Get lower bounds of allocated memory from emulator
    memory_base = get_memory_lower_bound(uc)

        # Get upper bounds of allocated memory from emulator
    memory_top = get_memory_upper_bound(uc, memory_alignment)
        
        # Get the stack base
    stack_base = memory_align(0x1000, memory_alignment)
        
        # Get the stack size
    
    stack_size = memory_align(0x5000, memory_alignment)
        
        # Adjust the stack base and size if needed
    if stack_base +  stack_size > memory_base and stack_base < memory_top:
        stack_base = memory_align(memory_top + 0x1000, memory_alignment)

    # Map the stack
    uc.mem_map(stack_base, stack_size)
    tmp_RSP = stack_base + stack_size // 2
    uc.reg_write(UC_X86_REG_RSP, tmp_RSP)
    uc.reg_write(UC_X86_REG_RBP, tmp_RSP)
    print(f"Stack set to 0x{tmp_RSP:x}, memory from 0x{memory_base:x}-0x{memory_top:x}")        
    
    return (uc, tmp_RSP)

def get_memory_lower_bound(uc) -> int:
    """
        Returns the lower bound of the allocated memory.
    """
    memory_segments = list(uc.mem_regions())
    memory_segments.sort(key=lambda x: x[0])
    memory_base = 0
    if len(memory_segments) > 0:
        memory_base = memory_segments[0][0]
    return memory_base
    
def get_memory_upper_bound(uc, memory_alignment) -> int:
    """
        Returns the upper bound of the allocated memory.
    """
    memory_segments = list(uc.mem_regions())
    memory_segments.sort(key=lambda x: x[1], reverse=True)
    memory_top = 0
    if len(memory_segments) > 0:
        memory_top = memory_align(memory_segments[0][1], memory_alignment)
    return memory_top

def memory_align(address: int, memory_alignment: int) -> int:
    """
        Aligns the given address to the nearest multiple of alignment.
        """
    
    return ((address + memory_alignment - 1) // memory_alignment) * memory_alignment

def add_data_sections(uc,pe, image_base,memory_alignment) -> None:
    """
        Adds sections to emulator
    """
    # For each section in the PE file add it to the emulator
    for section in pe.sections:
        # Get the section data
        data = section.get_data()
        # Get the section size
        size = section.Misc_VirtualSize
        # Align the section size
        size_aligned = memory_align(size, memory_alignment)
        # Get the section address
        address = image_base + section.VirtualAddress
        permissions = 0
        # Check if the section is readable
        if section.Characteristics & 0x40000000:
            permissions |= UC_PROT_READ
        # Check if the section is writable
        if section.Characteristics & 0x80000000:
            permissions |= UC_PROT_WRITE
        # Check if the section is executable
        if section.Characteristics & 0x20000000:
            permissions |= UC_PROT_EXEC

        if b".text" in section.Name:
            address = 0x5CB52C0 #PE_LOAD_ADDR#-0x5000
            print(f"Mapping section {section.Name.decode()} at 0x{address:x} with size 0x{size_aligned:x} (until {(address+size_aligned):x}) and permissions {permissions}")
            uc.mem_map(address-0x52c0, size_aligned+0x6000, permissions)
            #print(f"Now writing data from {address:x} - {address+0x5000+len(data):x}")        
            uc.mem_write(address, data)
            
        else:
            pass
            # Map the memory with the combined permissions
            #print(f"Mapping section {section.Name.decode()} at 0x{address:x} with size 0x{size_aligned:x} and permissions {permissions}")
            #err = uc.mem_map(address, size_aligned, permissions)        
        
            #uc.mem_write(address, data)

    return 

def hexdump(data, length=16):
    """Generate a hex dump from a specific starting address.

    Args:
        data (bytes): The data to dump.
        start_address (int): The starting address (byte offset) for the dump.
        length (int): The number of bytes to dump.

    Returns:
        None: Prints the hex dump to the console.
    """

    end_address = data + length  # Ensure we don't go out of bounds
    print(80*'*')
    for i in range(data, end_address, 16):  # Display 16 bytes per line
        # Get the slice of the data
        chunk = mu.mem_read(i,16)
        # Create a hex representation
        hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
        # Create a string representation for ASCII characters
        ascii_part = ''.join((chr(byte) if 32 <= byte < 127 else '.') for byte in chunk)
        # Print the formatted output
        print(f'{i:04x}  {hex_part:<{16 * 3}}  {ascii_part}')
    print(80*'*')

op = {
    1 : 'READ_CONST',
    2 : '?',
    3 : '?',
    4 : '?',
    5 : '?',
    6 : '?',
    7 : '?',
    8 : '?',
    9 : '?',
    10 : '?',
    11 : '?',
    12 : '?',
    13 : '?',
    14 : '?',
    15 : '?',
    16 : '?',
    17 : '?',
    18 : '?',
    19 : '?',
    20 : '?',
    21 : '?',
    22 : '?',
    23 : '?',
    24 : '?',
    25 : '?',
    26 : '?',
    27 : '?',
    28 : '?',
    29 : '?',
    30 : '?',
    31 : '?',
}
# Example usage
LAST_VM_OP = None
def hook_code(uc, address, size, user_data):
    global g_LAST_VM_OP
    global stop
    global correct_cnt
            
    bf = int.from_bytes(uc.mem_read(0x5D9D6D0, 8), byteorder='little')
    should = int.from_bytes(uc.mem_read(0x5D9D6C8, 8), byteorder='little')
    #if (bf & 0xffff0000) == (should & 0xffff0000): # 1st char
    #if (bf & 0xffffff00) == (should & 0xffffff00): # 2nd char
    if (bf) == (should): # 3nd char
        #print("Got it")
        #print(f"0x{bf:x}<->0x{should:x}")
        #print(f"{pw.decode('utf-16le')}")
        correct_cnt+=1                                
    
def generate_random_string(length=32):
    import string
    import random
    # Define the character set: digits and letters (uppercase and lowercase)
    characters = string.ascii_letters + string.digits
    # Generate a random string of the specified length
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def print_regs(uc):
    registers = {
        'RAX': uc.reg_read(UC_X86_REG_RAX),
        'RBX': uc.reg_read(UC_X86_REG_RBX),
        'RCX': uc.reg_read(UC_X86_REG_RCX),
        'RDX': uc.reg_read(UC_X86_REG_RDX),
        'RSI': uc.reg_read(UC_X86_REG_RSI),
        'RDI': uc.reg_read(UC_X86_REG_RDI),
        'RSP': uc.reg_read(UC_X86_REG_RSP),
        'RBP': uc.reg_read(UC_X86_REG_RBP),
        'RIP': uc.reg_read(UC_X86_REG_RIP),
        'R8':  uc.reg_read(UC_X86_REG_R8),
        'R9':  uc.reg_read(UC_X86_REG_R9),
        'R10': uc.reg_read(UC_X86_REG_R10),
        'R11': uc.reg_read(UC_X86_REG_R11),
        'R12': uc.reg_read(UC_X86_REG_R12),
        'R13': uc.reg_read(UC_X86_REG_R13),
        'R14': uc.reg_read(UC_X86_REG_R14),
        'R15': uc.reg_read(UC_X86_REG_R15),
    }

def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        # map this memory in with 2MB in size
        uc.mem_map(0xaaaa0000, 2 * 1024*1024)
        # return True to indicate we want to continue emulation
        return True
    else:
        print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        
        print_regs(uc)
        
        # return False to indicate we want to stop emulation
        return False

def newmain():
    global mu
    global pw
    global stop
    global correct_cnt
    # Main loop    
    try:
        mu, rsp = load_pe_to_unicorn("Section_PE32_image_FullShell_Shell_body.exe")
        ori_rsp = rsp

        vm_prog = None
        with open("program3.bin", "rb") as f:
            vm_prog = f.read()

        

        mu.mem_map(0x5d1f000,20 * 1024 * 1024)
        #mu.mem_map(VM_MEMORY, 2 * 1024 * 1024)
        mu.mem_write(VM_MEMORY, vm_prog)

        ADDR_OF_PW = VM_MEMORY+(PW_MEMORY-VM_MEMORY)
        ADDR_OF_VM = 0x5d9d5a8
        mu.mem_write(ADDR_OF_VM,b'\x00\x00\xf0\x05') # Set pointer to point to our VM at 0x05 F0 00 00
        image_base = PE_LOAD_ADDR#-0x52c0

        
        
        #hook_id = mu.hook_add(UC_HOOK_CODE, hook_code, None, image_base+VERIFIER_START_RVA, image_base+AFTER_VERIFIED_RVA)
        #hook_id = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)           

        # Start and monitor right from the beginning of the verifier
        #hook_id = mu.hook_add(UC_HOOK_CODE, hook_code, None, image_base+VERIFIER_START_RVA, image_base+VERIFIER_END_RVA)
        #hook_id = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)           
        #print(f"Starting execution at: 0x{image_base+VERIFIER_START_RVA:x}")
        #mu.emu_start(image_base+VERIFIER_START_RVA, image_base+VERIFIER_END_RVA)

        # Start and monitor right from the beginning of the prep
        # We need to write addr of our pw (unicode!) to R8 and RCX to the *VM
        
        alphabet = string.ascii_letters+string.digits+'$_@'
        i = 0
        start_point = '@@3y'
        start_yielding = start_point is None

        hook_id = mu.hook_add(UC_HOOK_CODE, hook_code, None, image_base+VERIFY_BLOCK_RVA, image_base+VERIFY_BLOCK_RVA)
        for combination in itertools.product(alphabet, repeat=4):
            correct_cnt=0
            i+=1
            # Join the tuple into a string
            if not start_yielding:
                if ''.join(combination) == start_point:
                    start_yielding = True
                continue
            
            
            # Preset with 1st possible solution for block 1
            pw = bytes('Veqz'+''.join(combination)+8*'A', 'utf-16le')
            #pw = bytes(generate_random_string(16), 'utf-16le')
            # Print or process the result
            if i % 10000 == 0:
                print(f"{i}: {pw.decode('utf-16le')}")
            # pw = bytes('AAAABBBBCCCCDDDD', 'utf-16le')
            mu.mem_write(ADDR_OF_PW, pw)        
            mu.reg_write(UC_X86_REG_RSP, ori_rsp)        
            mu.reg_write(UC_X86_REG_RBP, ori_rsp)
            
            mu.reg_write(UC_X86_REG_RCX, 0x5f00000)
            mu.reg_write(UC_X86_REG_R8, ADDR_OF_PW)
            
            # print(f"Starting execution at: 0x{image_base+PREP_BUFFER_RVA:x}")
            #mu.emu_start(image_base+PREP_BUFFER_RVA, image_base+AFTER_VERIFIED_RVA)
            

            mu.emu_start(image_base+PREP_BUFFER_RVA, image_base+AFTER_VERIFIED_RVA)
            if correct_cnt==2:
                print(f"PW = {pw.decode('utf-16le')}")                                 
       
            #else:
            #    print(f"0x{bf:x}<->0x{should:x}")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()        

def main():
    global mu
    global pw
    global stop
    # Main loop    
    try:
        mu, rsp = load_pe_to_unicorn("Section_PE32_image_FullShell_Shell_body.exe")
        ori_rsp = rsp

        vm_prog = None
        with open("program3.bin", "rb") as f:
            vm_prog = f.read()

        

        mu.mem_map(0x5d1f000,20 * 1024 * 1024)
        #mu.mem_map(VM_MEMORY, 2 * 1024 * 1024)
        mu.mem_write(VM_MEMORY, vm_prog)

        ADDR_OF_PW = VM_MEMORY+(PW_MEMORY-VM_MEMORY)
        ADDR_OF_VM = 0x5d9d5a8
        mu.mem_write(ADDR_OF_VM,b'\x00\x00\xf0\x05') # Set pointer to point to our VM at 0x05 F0 00 00
        image_base = PE_LOAD_ADDR#-0x52c0

        
        
        #hook_id = mu.hook_add(UC_HOOK_CODE, hook_code, None, image_base+VERIFIER_START_RVA, image_base+AFTER_VERIFIED_RVA)
        #hook_id = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)           

        # Start and monitor right from the beginning of the verifier
        #hook_id = mu.hook_add(UC_HOOK_CODE, hook_code, None, image_base+VERIFIER_START_RVA, image_base+VERIFIER_END_RVA)
        #hook_id = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)           
        #print(f"Starting execution at: 0x{image_base+VERIFIER_START_RVA:x}")
        #mu.emu_start(image_base+VERIFIER_START_RVA, image_base+VERIFIER_END_RVA)

        # Start and monitor right from the beginning of the prep
        # We need to write addr of our pw (unicode!) to R8 and RCX to the *VM
        
        alphabet = string.ascii_letters+string.digits+'$_'
        i = 0
        start_point = 'adlh'
        start_yielding = start_point is None
        for combination in itertools.product(alphabet, repeat=4):
            i+=1
            # Join the tuple into a string
            if not start_yielding:
                if ''.join(combination) == start_point:
                    start_yielding = True
                continue
            if stop:
                print(f"PW = {pw.decode('utf-16le')}")
                stop = False
            # Preset with 1st possible solution for block 1
            pw = bytes('Veqz'+''.join(combination)+8*'A', 'utf-16le')
            #pw = bytes(generate_random_string(16), 'utf-16le')
            # Print or process the result
            if i % 1000 == 0:
                print(f"{i}: {pw.decode('utf-16le')}")
            # pw = bytes('AAAABBBBCCCCDDDD', 'utf-16le')
            mu.mem_write(ADDR_OF_PW, pw)        
            mu.reg_write(UC_X86_REG_RSP, ori_rsp)        
            mu.reg_write(UC_X86_REG_RBP, ori_rsp)
            
            mu.reg_write(UC_X86_REG_RCX, 0x5f00000)
            mu.reg_write(UC_X86_REG_R8, ADDR_OF_PW)
            
            # print(f"Starting execution at: 0x{image_base+PREP_BUFFER_RVA:x}")
            #mu.emu_start(image_base+PREP_BUFFER_RVA, image_base+AFTER_VERIFIED_RVA)
            mu.emu_start(image_base+PREP_BUFFER_RVA, image_base+VERIFY_BLOCK_RVA)
            
            # Here we detected part 1 but we already have it now
            """
            rip = mu.reg_read(UC_X86_REG_RIP)
            bf = int.from_bytes(mu.mem_read(0x5D9D6D0, 8), byteorder='little')
            should = int.from_bytes(mu.mem_read(0x5D9D6C8, 8), byteorder='little')
            if (bf) == (should):
                print("Got part 1")
                print(f"0x{bf:x}<->0x{should:x}")
                print(f"{pw.decode('utf-16le')}")
                #stop = True
            """
            rip = mu.reg_read(UC_X86_REG_RIP)
            code_bytes = mu.mem_read(rip, 16)
            insn_size = 0
            for insn in md.disasm(code_bytes, rip):
                insn_size = insn.size
                break
            mu.emu_start(image_base+VERIFY_BLOCK_RVA,image_base+VERIFY_BLOCK_RVA+insn_size,0,1)
            rip = mu.reg_read(UC_X86_REG_RIP)
            # Do a single step (one cmp instruction = 4 byte)
            #mu.emu_start(image_base+VERIFY_BLOCK_RVA,image_base+VERIFY_BLOCK_RVA+4,0,1)
            #rip = mu.reg_read(UC_X86_REG_RIP)
            # print(f"Recomencing at rip: 0x{rip:x} (previous run to 0x{image_base+VERIFY_BLOCK_RVA:x})")
            mu.emu_start(rip, image_base+VERIFY_BLOCK_RVA)
            # 2nd stop
            bf = int.from_bytes(mu.mem_read(0x5D9D6D0, 8), byteorder='little')
            should = int.from_bytes(mu.mem_read(0x5D9D6C8, 8), byteorder='little')
            if (bf) == (should): 
                print("Got part 2")
                print(f"0x{bf:x}<->0x{should:x}")
                print(f"{pw.decode('utf-16le')}")
                stop = True      
       
            #else:
            #    print(f"0x{bf:x}<->0x{should:x}")
            
            
                
                
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    
newmain()

"""
Block 1
VeqzAAAAAAAAAAAA
VerYAAAAAAAAAAAA
Ves8AAAAAAAAAAAA
VfPzAAAAAAAAAAAA
VfQYAAAAAAAAAAAA
VfR8AAAAAAAAAAAA
Vg0YAAAAAAAAAAAA
Vg18AAAAAAAAAAAA
WDqzAAAAAAAAAAAA
WDrYAAAAAAAAAAAA
WDs8AAAAAAAAAAAA
WEPzAAAAAAAAAAAA
WEQYAAAAAAAAAAAA
WER8AAAAAAAAAAAA
WF0YAAAAAAAAAAAA
WF18AAAAAAAAAAAA
X$PzAAAAAAAAAAAA
X$QYAAAAAAAAAAAA
X$R8AAAAAAAAAAAA

Block 2
VeqzDumBAAAAAAAA
"""