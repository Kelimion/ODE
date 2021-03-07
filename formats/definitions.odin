package ode_file_format

/*
	PE support headers, flags and constants
*/

PE_File :: struct {
	dos_header: Image_DOS_Header,
	real_mode_stub: []byte,
	pe_header: PE_Header,


	raw: []byte,
}

PE_Option_Flags :: enum {
	Fill_Real_Mode_Stub = 1,
	Fill_Raw_Buffer,	
}
PE_Options :: distinct bit_set[PE_Option_Flags];

PE_Errors :: enum {
	OK = 0,

	Could_Not_Open_File  = 1,
	File_Too_Short,


	Malformed_DOS_Signature,
	Malformed_PE_Signature,
	    // Subset of PE signature error
		Image_Is_OS2_File,
		Image_Is_OS2_LE_File,

}

// DOS .EXE header, ported from WINNT.h
// Values are Little Endian
Image_DOS_Header :: struct {
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
DOS_HEADER_SIZE :: size_of(Image_DOS_Header);
#assert(DOS_HEADER_SIZE == 64);

Signature :: enum u16le {
	DOS    = 0x5a4d, // MZ
	NT     = 0x4550, // PE\0\0
	OS2    = 0x454e, // NE
	OS2_LE = 0x454c, // LE
}

// Microsoft recommends aligning the header on an 8-byte boundary
// http://msdn.microsoft.com/en-us/gg463119.aspx
PE_Header :: struct {
	signature: Signature,
	sig_zeroes: u16le,      // \0\0 after PE
	machine_type: Machine_Type,
	number_of_sections: u16le,
	time_date_stamp: u32le,	// Lower 32 bits of seconds since 1 Jan 1970, 00:00
	pointer_to_symbol_table: u32le,
	number_of_symbols: u32le,
	optional_header_size: u16le,
	characteristics: u16le,
};
PE_HEADER_SIZE :: size_of(PE_Header);
#assert(PE_HEADER_SIZE == 24);

Machine_Type :: enum u16le {
	Image_File_Machine_Unknown   = 0x0,
	Image_File_Machine_AM33      = 0x1d3,
	Image_File_Machine_AMD64     = 0x8664,
	Image_File_Machine_ARM       = 0x1c0,
	Image_File_Machine_ARM64     = 0xaa64,
	Image_File_Machine_ARMNT     = 0x1c4,
	Image_File_Machine_EBC       = 0xebc,
	Image_File_Machine_I386      = 0x14c,
	Image_File_Machine_IA64      = 0x200,
	Image_File_Machine_M32R      = 0x9041,
	Image_File_Machine_MIPS16    = 0x266,
	Image_File_Machine_MIPSFPU   = 0x366,
	Image_File_Machine_MIPSFPU16 = 0x466,
	Image_File_Machine_POWERPC   = 0x1f0,
	Image_File_Machine_POWERPCFP = 0x1f1,
	Image_File_Machine_R4000     = 0x166,
	Image_File_Machine_RISCV32   = 0x5032,
	Image_File_Machine_RISCV64   = 0x5064,
	Image_File_Machine_RISCV128  = 0x5128,
	Image_File_Machine_SH3       = 0x1a2,
	Image_File_Machine_SH3DSP    = 0x1a3,
	Image_File_Machine_SH4       = 0x1a6,
	Image_File_Machine_SH5       = 0x1a8,
	Image_File_Machine_THUMB     = 0x1c2,
	Image_File_Machine_WCEMIPSV2 = 0x169,
}