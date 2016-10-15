
import os
import sys

def printf(format, *args):
    sys.stdout.write(format % args)

#
#nt!_KPROCESS
#    +0x000 Header           : _DISPATCHER_HEADER
#    +0x018 ProfileListHead  : _LIST_ENTRY
#    +0x028 DirectoryTableBase : Uint8B
#    +0x030 ThreadListHead   : _LIST_ENTRY
#    +0x040 ProcessLock      : Uint4B
#    +0x044 Spare0           : Uint4B
#    +0x048 DeepFreezeStartTime : Uint8B
#    +0x050 Affinity         : _KAFFINITY_EX
#    +0x0f8 ReadyListHead    : _LIST_ENTRY
#    +0x108 SwapListEntry    : _SINGLE_LIST_ENTRY
#    +0x110 ActiveProcessors : _KAFFINITY_EX
#    +0x1b8 AutoAlignment    : Pos 0, 1 Bit
#    +0x1b8 DisableBoost     : Pos 1, 1 Bit
#    +0x1b8 DisableQuantum   : Pos 2, 1 Bit
#    +0x1b8 DeepFreeze       : Pos 3, 1 Bit
#    +0x1b8 TimerVirtualization : Pos 4, 1 Bit
#    +0x1b8 CheckStackExtents : Pos 5, 1 Bit
#    +0x1b8 SpareFlags0      : Pos 6, 2 Bits
#    +0x1b8 ActiveGroupsMask : Pos 8, 20 Bits
#    +0x1b8 ReservedFlags    : Pos 28, 4 Bits
#    +0x1b8 ProcessFlags     : Int4B
#    +0x1bc BasePriority     : Char
#    +0x1bd QuantumReset     : Char
#    +0x1be Visited          : UChar
#    +0x1bf Flags            : _KEXECUTE_OPTIONS
#    +0x1c0 ThreadSeed       : [20] Uint4B
#    +0x210 IdealNode        : [20] Uint2B
#    +0x238 IdealGlobalNode  : Uint2B
#    +0x23a Spare1           : Uint2B
#    +0x23c StackCount       : _KSTACK_COUNT
#    +0x240 ProcessListEntry : _LIST_ENTRY
#    +0x250 CycleTime        : Uint8B
#    +0x258 ContextSwitches  : Uint8B
#    +0x260 SchedulingGroup  : Ptr64 _KSCHEDULING_GROUP
#    +0x268 FreezeCount      : Uint4B
#    +0x26c KernelTime       : Uint4B
#    +0x270 UserTime         : Uint4B
#    +0x274 LdtFreeSelectorHint : Uint2B
#    +0x276 LdtTableLength   : Uint2B
#    +0x278 LdtSystemDescriptor : _KGDTENTRY64
#    +0x288 LdtBaseAddress   : Ptr64 Void
#    +0x290 LdtProcessLock   : _FAST_MUTEX
#    +0x2c8 InstrumentationCallback : Ptr64 Void
#    +0x2d0 SecurePid        : Uint8B


key_types = {
    'UChar': "UCHAR", 
    'Char': "CHAR", 
    'Uint2B': "USHORT", 
    'Uint4B': "ULONG", 
    'Uint8B': "ULONG64", 
    'Int2B': "SHORT", 
    'Int4B': "LONG", 
    'Int8B': "LONG64", 
    'Void': "VOID"
}

def get_input(prompt):
    print prompt,
    lines = []
    line = raw_input()
    while line != "":
        line = line.replace("\t", "")
        lines.append(line)
        line = raw_input()
    lines = ''.join(lines)
    return lines

def get_struct_name(dt_dump):
    exclamation_idx = dt_dump.index('!');
    first_addition_idx =  dt_dump.index('+');
    structname = dt_dump[ exclamation_idx + 1 : first_addition_idx ];
    return structname.strip()

def get_fields(dt_dump):
    ''' Returns generated field list '''
    field_list = []
    
    first_addition_idx = dt_dump.index('+')
    s = dt_dump[first_addition_idx + 1 :]
    s = s.split('+')
    
    for field in s: 
        current_field = { 'name': "", 'type': "", 'pointer': False, 'offset': -1, 'size': 0, 'array_size': -1, 'union': False, 'bit_pos': -1 }
    
        offset_end_idx = field.index(' ')
        current_field['offset'] = int(field[:offset_end_idx], 16)
    
        field = field[offset_end_idx + 1:]
        name, dtype = field.split(':')
        # strip leading and trailing whitespace
        name = name.strip()
        dtype = dtype.strip()
    
        current_field['name'] = name       
    
        # Bitfield type
        if "Pos " in dtype:
            dtype = dtype.strip(' ')
            pos, bit = dtype.split(',')
            current_field['bit_pos'] = int(pos[3:])
            current_field['size'] = int(bit[:bit.index('B')])
        # Pointer field type
        elif ("Ptr64" in dtype):
            ptr, dt = dtype.split(' ')
            current_field['pointer'] = True
            current_field['type'] = dt
            current_field['size'] = 8
        elif ("Ptr32" in dtype):
            ptr, dt = dtype.split(' ')
            current_field['pointer'] = True
            current_field['type'] = dt
            current_field['size'] = 4                
        # Array field type 
        elif '[' in dtype:
            arr, dt = dtype.split(' ')
            arr = arr.strip("[]") # drop the brackets
            current_field['array_size'] = int(arr)
            current_field['type'] = dt;
        # Regular field type  
        else:
            current_field['type'] = dtype
    
        # Finalize data for the previous field
        if len(field_list) > 0:
            if field_list[-1]['bit_pos'] == -1 and current_field['bit_pos'] == -1:
                # Calculate the previous field's size by subtracting the 
                # current offset from the previous offset 
                field_list[-1]['size'] = current_field['offset'] - field_list[-1]['offset']
                #print(field_list[-1]['size'])
            # check if the previous or current field is a union
            elif field_list[-1]['bit_pos'] != -1 and current_field['bit_pos'] == -1 and field_list[-1]['offset'] == current_field['offset']:
                current_field['union'] = True;                
            elif field_list[-1]['bit_pos'] == -1 and field_list[-1]['offset'] == current_field['offset']:
                field_list[-1]['union'] = True;      
    
        # Append the field to the list
        field_list.append(current_field)
        
    return field_list

def union_size(union_field):
    total = 0;
    for field in fields:
        if field['union'] == False and field['offset'] == union_field['offset']:
            total = total + field['size']
    return total

def print_bitfield(bit_field):
    if bit_field['size'] > 32:
        bit_field['type'] = "ULONGLONG";
    elif bit_field['size'] > 16:
        bit_field['type'] = "ULONG";
    elif bit_field['size'] > 8:
        bit_field['type'] = "USHORT";
    else:
        bit_field['type'] = "UCHAR";
    printf("\t%s %s : %d; // 0x%X\n", bit_field['type'], bit_field['name'], bit_field['size'], bit_field['offset'])    

def print_union(fields, union_field):
    printf("\tstruct\n\t{\n")
    if union_field['type'] in key_types:
        printf("\t\t%s %s; // 0x%X\n", key_types[union_field['type']], union_field['name'], union_field['offset'])
    else:
        printf("\t\t%s %s; // 0x%X\n", union_field['type'], union_field['name'], union_field['offset'])
    printf("\t\tunion\n\t\t{\n")
    for field in fields:
        if field['union'] == False and field['bit_pos'] != -1 and field['offset'] == union_field['offset']:
            printf("\t\t")
            print_bitfield(field)
    printf("\t\t};\n")
    printf("\t};\n")

def main():
    
    dt_dump = get_input("Enter dumped WinDbg data-type: ")
    if (dt_dump):
        
        struct_name = get_struct_name(dt_dump)
        fields = get_fields(dt_dump)
            
        printf("typedef struct %s\n{\n", struct_name)
        
        union_struct = []
        
        previous_field = None
        for field in fields:    
            # print out the type
            if field['bit_pos'] != -1:
                # skip printing bitfields as they are printed in print_union
                continue
            elif field['union'] == True:
                # Print entire union including the bitfields
                print_union(fields, field)
            else:
                if field['type'] in key_types:
                    if field['pointer'] == True:
                        printf("\tP%s ", key_types[field['type']])
                    else:
                        printf("\t%s ", key_types[field['type']])
                else:
                    if field['type'][0] == '_':
                        printf("\tstruct %s", field['type'])
                    else:
                        printf("\t%s", field['type'])
                    if field['pointer'] == True:
                        printf("* ")
                    else:
                        printf(" ")
                printf("%s", field['name'])
                if field['array_size'] != -1:
                    printf("[%d]; // ", field['array_size'])
                else:
                    printf("; // ")
                printf("0x%X\n", field['offset'])
                
            previous_field = field
        
        struct_name = struct_name[1:]
        printf("} %s, *P%s;\n", struct_name, struct_name) 
        
    else:
        print("Error: invalid input")    
    
    return




if __name__ == "__main__":
    main()