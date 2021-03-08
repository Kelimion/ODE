package ode_file_format

/*
	PE support headers, flags and constants
*/

PE_File :: struct {
	dos_header: DOS_Header,
	real_mode_stub: []byte,
	pe_header: PE_Header,
	coff_header: COFF_Header,
	optional_header: union {
		PE32_Optional_Header,
		PE64_Optional_Header,
	},
	// If .Fill_Raw_Buffer is passed on open, this will contain the entire file for further inspection.
	raw: []byte,
}

PE_Option_Flags :: enum {
	Fill_Real_Mode_Stub,
	Fill_Raw_Buffer,	
}
PE_Options :: distinct bit_set[PE_Option_Flags];

PE_Errors :: enum {
	OK = 0,

	Could_Not_Open_File  = 1,
	File_Too_Short,

	Malformed_DOS_Signature,
	Malformed_DOS_Header,
	Malformed_PE_Signature,
	    // Subset of PE signature error
		Image_Is_OS2_File,
		Image_Is_OS2_LE_File,
	Malformed_Optional_Header,
}

// DOS .EXE header, ported from WINNT.h
// Values are Little Endian
DOS_Header :: struct {
    signature: Signature,
    bytes_on_last_page_of_file: u16le,
    pages_in_file: u16le,
    relocations: u16le,
    size_of_header_in_paragraphs: u16le,
    minimum_extra_paragraphs_needed: u16le,
    maximum_extra_paragraphs_needed: u16le,
    initial_relative_stack_segment: u16le,
    initial_stack_pointer: u16le,
    checksum: u16le,
    initial_instruction_pointer: u16le,
    initial_relative_code_segment: u16le,
    relocation_table_offet: u16le,
    overlay_number: u16le,
    reserved: [4]u16le,
    oem_id: u16le,
    oem_info: u16le,
    reserved2: [10]u16le,
    pe_header_offset: u32le,
}
DOS_HEADER_SIZE :: size_of(DOS_Header);
#assert(DOS_HEADER_SIZE == 64);

PE_Header :: struct {
	signature: Signature,
	sig_zeroes: u16le,      // \0\0 after PE
}
PE_HEADER_SIZE :: size_of(PE_Header);
#assert(PE_HEADER_SIZE == 4);

Signature :: enum u16le {
	DOS    = 0x5a4d, // MZ
	NT     = 0x4550, // PE\0\0
	OS2    = 0x454e, // NE
	OS2_LE = 0x454c, // LE

	PE32   =  0x10b, // 32 bit
	PE64   =  0x20b, // 64 bit
}

// Microsoft recommends aligning the header on an 8-byte boundary
// http://msdn.microsoft.com/en-us/gg463119.aspx
COFF_Header :: struct {
	machine_type: Machine_Type,
	number_of_sections: u16le,
	time_date_stamp: u32le,	// Lower 32 bits of seconds since 1 Jan 1970, 00:00
	pointer_to_symbol_table: u32le,
	number_of_symbols: u32le,
	optional_header_size: u16le,
	characteristics: COFF_Characteristics,
};
COFF_HEADER_SIZE :: size_of(COFF_Header);
#assert(COFF_HEADER_SIZE == 20);

Machine_Type :: enum u16le {
	Unknown   = 0x0,
	AM33      = 0x1d3,
	AMD64     = 0x8664,
	ARM       = 0x1c0,
	ARM64     = 0xaa64,
	ARMNT     = 0x1c4,
	EBC       = 0xebc,
	I386      = 0x14c,
	IA64      = 0x200,
	M32R      = 0x9041,
	MIPS16    = 0x266,
	MIPSFPU   = 0x366,
	MIPSFPU16 = 0x466,
	POWERPC   = 0x1f0,
	POWERPCFP = 0x1f1,
	R4000     = 0x166,
	RISCV32   = 0x5032,
	RISCV64   = 0x5064,
	RISCV128  = 0x5128,
	SH3       = 0x1a2,
	SH3DSP    = 0x1a3,
	SH4       = 0x1a6,
	SH5       = 0x1a8,
	THUMB     = 0x1c2,
	WCEMIPSV2 = 0x169,
}

COFF_Characteristics_Flags :: enum u16le {
    Relocs_Stripped             = 0,
    Executable_Image            = 1,
    Line_Nums_Stripped          = 2,
    Local_Symbolss_Stripped     = 3,
    Aggressive_Working_Set_Trim = 4,
    Large_Address_Aware         = 5,
    Reserved                    = 6,
    Bytes_Reversed_LO           = 7,
    Architecture_32_bit         = 8,
    Debug_Stripped              = 9,
    Removable_Run_From_Swap     = 10,
    Net_Run_From_Swap           = 11,
    System_File                 = 12,
    DLL                         = 13,
    Uniprocessor_System_Only    = 14,
    Bytes_Reversed_HI           = 15,
}

COFF_Characteristics :: distinct bit_set[COFF_Characteristics_Flags; u16le];

PE32_Optional_Header :: struct {
	// Standard Fields
	signature: Signature,
	major_linker_version: u8,
	minor_linker_version: u8,
	size_of_code: u32le,
	size_of_initialized_data: u32le,
	size_of_unitialized_data: u32le,
	address_of_entry_point: u32le,
	base_of_code: u32le,
	// NT Specific Fields
	base_of_data: u32le,
	image_base: u32le,
	section_alignment: u32le,
	file_alignment: u32le,
	major_os_version: u16le,
	minor_os_version: u16le,
	major_image_version: u16le,
	minor_image_version: u16le,
	major_subsystem_version: u16le,
	minor_subsystem_version: u16le,
	win32_version_value: u32le,
	size_of_image: u32le,
	size_of_headers: u32le,
	checksum: u32le,
	subsystem: Windows_Subsystem,
	dll_characteristics: DLL_Characteristics,
	size_of_stack_reserve: u32le,
	size_of_stack_commit: u32le,
	size_of_heap_reserve: u32le,
	size_of_heap_commit: u32le,
	loader_flags: u32le,
	number_of_rva_and_size: u32le,
}
PE32_OPTIONAL_HEADER_SIZE :: size_of(PE32_Optional_Header);
#assert(PE32_OPTIONAL_HEADER_SIZE == 96);

PE64_Optional_Header :: struct {
	// Standard Fields
	signature: Signature,
	major_linker_version: u8,
	minor_linker_version: u8,
	size_of_code: u32le,
	size_of_initialized_data: u32le,
	size_of_unitialized_data: u32le,
	address_of_entry_point: u32le,
	base_of_code: u32le,
	// NT Specific Fields
	image_base: u64le,
	section_alignment: u32le,
	file_alignment: u32le,
	major_os_version: u16le,
	minor_os_version: u16le,
	major_image_version: u16le,
	minor_image_version: u16le,
	major_subsystem_version: u16le,
	minor_subsystem_version: u16le,
	win32_version_value: u32le,
	size_of_image: u32le,
	size_of_headers: u32le,
	checksum: u32le,
	subsystem: Windows_Subsystem,
	dll_characteristics: DLL_Characteristics,
	size_of_stack_reserve: u64le,
	size_of_stack_commit: u64le,
	size_of_heap_reserve: u64le,
	size_of_heap_commit: u64le,
	loader_flags: u32le,
	number_of_rva_and_size: u32le,
}
PE64_OPTIONAL_HEADER_SIZE :: size_of(PE64_Optional_Header);
#assert(PE64_OPTIONAL_HEADER_SIZE == 112);

Windows_Subsystem :: enum u16le {
	Unknown                  = 0,
	Native                   = 1,
	Windows_GUI              = 2,
	Windows_CUI              = 3,
	OS2_CUI                  = 5,
	POSIX_CUI                = 7,
	Native_Window            = 8,
	Windows_CE_GUI           = 9,
	EFI_Application          = 10,
	EFI_Boot_Service_Driver  = 11,
	EFI_Runtime_Driver       = 12,
	EFI_ROM                  = 13,
	XBOX                     = 14,
	Windows_Boot_Application = 15,
}

DLL_Characteristics_Flags :: enum u16le {
	Reserved1             =  0,
	Reserved2             =  1,
	Reserved3             =  2,
	Reserved4             =  3,
	Unknown               =  4,
	High_Entropy_VA       =  5,
	Dynamic_Base          =  6,
	Force_Integrity       =  7,
	NX_Compatible         =  8,
	Isolation_Aware       =  9,
	No_SEH                = 10,
	No_Bind               = 11,
	App_Container         = 12,
	WDM_Driver            = 13,
	Control_Flow_Guard    = 14,
	Terminal_Server_Aware = 15,
}

DLL_Characteristics :: distinct bit_set[DLL_Characteristics_Flags; u16le];
