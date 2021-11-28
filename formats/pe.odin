package ode_file_format

/*
	PE format support
*/

import "core:os"
import "core:fmt"
import "core:mem"
import "core:time"
import "core:strings"
import "core:io"

parse_pe :: proc {
	parse_pe_from_file,
	parse_pe_from_byte_array,
}
parse_coff :: proc {
	parse_coff_from_file,
	parse_coff_from_byte_array,
}

peek_bytes :: #force_inline proc(buffer: []byte, offset: int, length: int) -> (ok: bool, bytes: []byte) {
	new_offset := offset + length
	if new_offset >= len(buffer) {
		ok = false
		return
	}

	ok = true
	bytes = buffer[offset:new_offset]
	return
}

get_bytes :: #force_inline proc(buffer: []byte, offset: int, length: int) -> (ok: bool, bytes: []byte, new_offset: int) {
	ok, bytes = peek_bytes(buffer, offset, length)
	new_offset = offset
	if ok do new_offset += length
	return
}

parse_pe_from_file :: proc(path: string, options:=PE_Options{}) -> (PE_File, PE_Errors) {

	read_start := time.tick_now()
	if buffer, ok := os.read_entire_file(path); ok {
		read_end := time.tick_now()
		fmt.printf("PE file read in %s.\n", fmt.tprint(time.tick_diff(read_start, read_end)))

		parse_start := time.tick_now()
		pe_file, errors := parse_pe_from_byte_array(buffer, options)
		parse_end := time.tick_now()
		fmt.printf("PE file parsed in %s.\n", fmt.tprint(time.tick_diff(parse_start, parse_end)))
		return pe_file, errors
	} else {
		return PE_File{}, .Could_Not_Open_File
	}
}

parse_coff_from_file :: proc(path: string, options:=PE_Options{}) -> (Coff_File, PE_Errors) {

	read_start := time.tick_now()
	if buffer, ok := os.read_entire_file(path); ok {
		read_end := time.tick_now()
		fmt.printf("OBJ file read in %s.\n", fmt.tprint(time.tick_diff(read_start, read_end)))

		parse_start := time.tick_now()
		pe_file, errors := parse_coff_from_byte_array(buffer, 0)
		parse_end := time.tick_now()
		fmt.printf("OBJ file parsed in %s.\n", fmt.tprint(time.tick_diff(parse_start, parse_end)))
		return pe_file, errors
	} else {
		return Coff_File{}, .Could_Not_Open_File
	}
}

parse_coff_from_byte_array :: proc(buffer: []byte, i_offset: int) -> (Coff_File, PE_Errors) {

	ok := false
	offset := i_offset
	coff_file: Coff_File
	using coff_file

	coff_header_bytes: []byte
	// Interpret the 4 bytes at pe_header_offset as a PE header.
	ok, coff_header_bytes, offset = get_bytes(buffer, offset, COFF_HEADER_SIZE)
	if ok == false do return coff_file, .File_Too_Short
	header = mem.slice_data_cast([]COFF_Header, coff_header_bytes)[0]

	if header.optional_header_size > 0 {
		// Now based on the next u16le, we either read the 32 or 64 bit optional header version.
		// We already accounted for the minimum file size to include the shorter 32 bit version.
		optional_magic_bytes: []byte
		ok, optional_magic_bytes = peek_bytes(buffer, offset, 2)
		optional_magic := mem.slice_data_cast([]Signature, optional_magic_bytes)[0]

		data_directory_entries := 0
		data_directory_size    := 0
		if optional_magic == Signature.PE32 {

			optional_header_bytes: []byte
			ok, optional_header_bytes, offset = get_bytes(buffer, offset, PE32_OPTIONAL_HEADER_SIZE)
			if ok == false do return coff_file, .File_Too_Short
			optional_header = mem.slice_data_cast([]PE32_Optional_Header, optional_header_bytes)[0]

			data_directory_entries = int(optional_header.(PE32_Optional_Header).number_of_rva_and_size)

			if int(data_directory_entries * DATA_DIRECTORY_SIZE + PE32_OPTIONAL_HEADER_SIZE) != int(header.optional_header_size) {
				return coff_file, .Malformed_Optional_Header		
			}
		} else if optional_magic == Signature.PE64 {

			optional_header_bytes: []byte
			ok, optional_header_bytes, offset = get_bytes(buffer, offset, PE64_OPTIONAL_HEADER_SIZE)
			if ok == false do return coff_file, .File_Too_Short
			optional_header = mem.slice_data_cast([]PE64_Optional_Header, optional_header_bytes)[0]

			data_directory_entries = int(optional_header.(PE64_Optional_Header).number_of_rva_and_size)
			if int(data_directory_entries * DATA_DIRECTORY_SIZE + PE64_OPTIONAL_HEADER_SIZE) != int(header.optional_header_size) {
				return coff_file, .Malformed_Optional_Header		
			}
		} else {
			return coff_file, .Malformed_Optional_Header
		}

		data_directory_size = data_directory_entries * DATA_DIRECTORY_SIZE
		data_directory_bytes: []byte

		ok, data_directory_bytes, offset = get_bytes(buffer, offset, data_directory_size)
		if ok == false do return coff_file, .File_Too_Short
		data_directory = mem.slice_data_cast([]Data_Directory_Entry, data_directory_bytes)
	}

	section_header_size := int(header.sections_count) * SECTION_HEADER_SIZE
	section_header_bytes: []byte

	ok, section_header_bytes, offset = get_bytes(buffer, offset, section_header_size)
	if ok == false do return coff_file, .File_Too_Short
	section_headers = mem.slice_data_cast([]Section_Header, section_header_bytes)	

	relocations = make([][]Relocation_Entry, header.sections_count)

	relocation_bytes: []byte
	rel_offset := offset
	for section, i in section_headers {
		using section
		if relocations_count > 0 {
			relocation_size := int(relocations_count) * RELOCATION_ENTRY_SIZE
			if ok, relocation_bytes, rel_offset = get_bytes(buffer, int(relocations_ptr), relocation_size); ok {
				relocations[i] = mem.slice_data_cast([]Relocation_Entry, relocation_bytes)
			} else {
				return coff_file, .File_Too_Short
			}
		}
	}

	symbol_table_bytes: []byte
	if header.symbol_count > 0 {
		sym_offset: = offset
		symbol_table_size := int(header.symbol_count) * SYMBOL_SIZE
		if ok, symbol_table_bytes, sym_offset = get_bytes(buffer, int(header.symbol_table_ptr), symbol_table_size); ok {
			symbol_table = mem.slice_data_cast([]Symbol, symbol_table_bytes)
		} else {
			return coff_file, .File_Too_Short			
		}
	}

	return coff_file, .OK

}

parse_pe_from_byte_array :: proc(buffer: []byte, options:=PE_Options{}) -> (PE_File, PE_Errors) {

	pe_file := PE_File{}
	using pe_file

	file_len := len(buffer)

	minimum_file_size := DOS_HEADER_SIZE + PE_HEADER_SIZE + COFF_HEADER_SIZE + PE32_OPTIONAL_HEADER_SIZE

	if file_len < minimum_file_size {
		return pe_file, .File_Too_Short	
	}

	if .Fill_Raw_Buffer in options {
		raw = buffer
	}

	// Interpret the first 64 bytes as a DOS header.
	ok, dos_header_bytes, offset := get_bytes(buffer, 0, DOS_HEADER_SIZE)
	if ok == false do return pe_file, .File_Too_Short
	dos_header = mem.slice_data_cast([]DOS_Header, dos_header_bytes)[0]

	// Check that the magic is 0x5a4d ("MZ")
	if dos_header.signature != .DOS {
		return pe_file, .Malformed_DOS_Signature
	}

	if dos_header.pe_header_offset <= DOS_HEADER_SIZE {
		// DOS Header says the PE header starts inside of the PE header
		return pe_file, .Malformed_DOS_Header
	}

	pe_header_bytes: []byte
	// Interpret the 4 bytes at pe_header_offset as a PE header.
	ok, pe_header_bytes, offset = get_bytes(buffer, int(dos_header.pe_header_offset), PE_HEADER_SIZE)
	if ok == false do return pe_file, .File_Too_Short
	pe_header = mem.slice_data_cast([]PE_Header, pe_header_bytes)[0]

	// Now we've read past the real mode stub, we can fill it in if requested.
	if .Fill_Real_Mode_Stub in options {
		real_mode_stub = buffer[DOS_HEADER_SIZE:dos_header.pe_header_offset]
	}

	if pe_header.signature != .NT {
		if pe_header.signature == .OS2 {
			return pe_file, .Image_Is_OS2_File
		} else if pe_header.signature == .OS2_LE {
			return pe_file, .Image_Is_OS2_LE_File
		}
	}
	if pe_header.sig_zeroes != 0 {
		return pe_file, .Malformed_PE_Signature
	}

	error: PE_Errors
	coff, error = parse_coff_from_byte_array(buffer, offset)

	return pe_file, .OK
}

isc_alignment_size :: proc(isc: Image_Section_Characteristics) -> (size: int) {

	bits  := (transmute(u32le)isc & 0x00F00000) >> 20
	sizes := []int{
		0, 1, 2,
		4, 8, 16,
		32, 64, 128,
		256, 512, 1024,
		2048, 4096, 8192,
	}
	return sizes[bits]
}

section_header_formatter :: proc(fi: ^fmt.Info, arg: any, verb: rune) -> bool {

	using strings
	assert(arg.id == Section_Header)
	sh: ^Section_Header
	sh = cast(^Section_Header)arg.data

	name := trim_right_null(string_from_ptr(&sh.name[0], 8))
	io.write_string(fi.writer, "{name = ")
	io.write_string(fi.writer, name)
	io.write_string(fi.writer, ", virtual_size = ")
	fmt.fmt_int(fi, u64(sh.virtual_size), false, 32, 'v')
	io.write_string(fi.writer, ", virtual_address = ")
	fmt.fmt_int(fi, u64(sh.virtual_address), false, 32, 'v')
	io.write_string(fi.writer, ", raw_data_size = ")
	fmt.fmt_int(fi, u64(sh.raw_data_size), false, 32, 'v')
	io.write_string(fi.writer, ", raw_data_ptr = ")
	fmt.fmt_int(fi, u64(sh.raw_data_ptr), false, 32, 'v')
	io.write_string(fi.writer, ", relocations_ptr = ")
	fmt.fmt_int(fi, u64(sh.relocations_ptr), false, 32, 'v')
	io.write_string(fi.writer, ", line_numbers_ptr = ")
	fmt.fmt_int(fi, u64(sh.relocations_ptr), false, 32, 'v')
	io.write_string(fi.writer, ", relocations_count = ")
	fmt.fmt_int(fi, u64(sh.relocations_count), false, 32, 'v')
	io.write_string(fi.writer, ", line_numbers_count = ")
	fmt.fmt_int(fi, u64(sh.line_numbers_count), false, 32, 'v')
	io.write_string(fi.writer, ", characteristics = ")
	fmt.fmt_bit_set(fi, sh.characteristics)
	io.write_string(fi.writer, "}")
	return true
}

print_coff_file :: proc(filename: string, coff_file: Coff_File) {
	using coff_file
	using fmt

	rel: []Relocation_Entry
	total_relocation_count := 0

	println()
	println("Machine Type:", header.machine_type)
	build_date := time.Time{_nsec = i64(header.time_date_stamp) * 1e9}
	printf ("Timestamp   : %v\n\n", build_date)
	printf ("Symbol Table:\n\tOffset: %v\n", header.symbol_table_ptr)
	printf ("\tCount : %v\n\n", header.symbol_count)
	println("# Sections:", header.sections_count)
	for section, i in section_headers {
		name := strings.trim_right_null(string(section_headers[i].name[:]))
		printf("\t%2d: %v\n", i+1, name)
		if section.virtual_size > 0 {
			printf("\t\tVirtual Size      : %v\n", section.virtual_size)
		}
		if section.virtual_address > 0 {
			printf("\t\tVirtual Addr      : 0x%08d\n", section.virtual_address)
		}
		printf("\t\tRaw Data Offset   : %v\n", section.raw_data_ptr)
		printf("\t\tRaw Data Size     : %v\n", section.raw_data_size)
		if section.relocations_ptr > 0 {
			printf("\t\tRelocations Offset: %v\n", section.relocations_ptr)
		}
		if section.relocations_count > 0 {
			printf("\t\tRelocations Count : %v\n", section.relocations_count)
			total_relocation_count += int(section.relocations_count)
		}
		printf("\t\tChracteristics    : \n")

		ch := transmute(u32le)section.characteristics &~ 0x00F00000

		delim := false
		printf("\t\t\tFlags    : ")
		for i in 0..=31 {
			if ch & (1 << u32(i)) > 0 {
				if delim do printf(" | ")
				printf(Image_Section_Flag_Names[i])
				delim = true
			}
		}
		printf("\n\t\t\tAlignment: %v\n", isc_alignment_size(section.characteristics))

		if name == ".data" do rel = relocations[i]
	}

	println(rel)

	println("\n# Relocations Total:", total_relocation_count)

	for i in 0..=9 {
		sym := symbol_table[i]
		if sym.storage_class != .null {
			name := strings.trim_right_null(string(sym.name.short_name[:]))
			printf("Symbol #%v: %v -> %v\n", i, name, sym)
		}
	}
}

main :: proc() {

	if false {
		user_formatters: map[typeid]fmt.User_Formatter
		fmt.set_user_formatters(&user_formatters)

		err: fmt.Register_User_Formatter_Error
		err = fmt.register_user_formatter(Section_Header, section_header_formatter)
	}

	if false {
		filename := "../test/test.exe"
		if pe_file, errors := parse_pe(filename); errors == .OK {

			using pe_file.coff
			build_date := time.Time{_nsec = i64(header.time_date_stamp) * 1e9}
			fmt.printf("\n%v was built on %v\n", filename, build_date)
			fmt.println()
			for section, i in section_headers {
				name := strings.trim_right_null(string(section_headers[i].name[:]))

				fmt.println("Section: ", i, name)
			}

			fmt.println(pe_file)
		} else {
			fmt.println("Couldn't open", filename, errors)
		}
	}

	if true {
		filename := "../test/test.obj"
		if coff_file, errors := parse_coff(filename); errors == .OK {

			print_coff_file(filename, coff_file)

		} else {
			fmt.println("Couldn't open", filename, errors)
		}
	}
}