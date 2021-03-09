package ode_file_format

/*
	PE format support
*/

import "core:os"
import "core:math/bits"
import "core:fmt"
import "core:mem"
import "core:time"
import "core:strings"

parse_pe :: proc {
	parse_pe_from_file,
	parse_pe_from_byte_array,
};
parse_coff :: proc {
	parse_coff_from_file,
	parse_coff_from_byte_array,
};

peek_bytes :: #force_inline proc(buffer: []byte, offset: int, length: int) -> (ok: bool, bytes: []byte) {
	new_offset := offset + length;
	if new_offset >= len(buffer) {
		ok = false;
		return;
	}

	ok = true;
	bytes = buffer[offset:new_offset];
	return;
}

get_bytes :: #force_inline proc(buffer: []byte, offset: int, length: int) -> (ok: bool, bytes: []byte, new_offset: int) {
	ok, bytes = peek_bytes(buffer, offset, length);
	new_offset = offset;
	if ok do new_offset += length;
	return;
}

parse_pe_from_file :: proc(path: string, options:=PE_Options{}) -> (PE_File, PE_Errors) {

	read_start := time.tick_now();
	if buffer, ok := os.read_entire_file(path); ok {
		read_end := time.tick_now();
		fmt.printf("PE file read in %s.\n", fmt.tprint(time.tick_diff(read_start, read_end)));

		parse_start := time.tick_now();
		pe_file, errors := parse_pe_from_byte_array(buffer, options);
		parse_end := time.tick_now();
		fmt.printf("PE file parsed in %s.\n", fmt.tprint(time.tick_diff(parse_start, parse_end)));
		return pe_file, errors;
	} else {
		return PE_File{}, .Could_Not_Open_File;
	}
}

parse_coff_from_file :: proc(path: string, options:=PE_Options{}) -> (Coff_File, PE_Errors) {

	read_start := time.tick_now();
	if buffer, ok := os.read_entire_file(path); ok {
		read_end := time.tick_now();
		fmt.printf("OBJ file read in %s.\n", fmt.tprint(time.tick_diff(read_start, read_end)));

		parse_start := time.tick_now();
		pe_file, errors := parse_coff_from_byte_array(buffer, 0);
		parse_end := time.tick_now();
		fmt.printf("OBJ file parsed in %s.\n", fmt.tprint(time.tick_diff(parse_start, parse_end)));
		return pe_file, errors;
	} else {
		return Coff_File{}, .Could_Not_Open_File;
	}
}

parse_coff_from_byte_array :: proc(buffer: []byte, i_offset: int) -> (Coff_File, PE_Errors) {

	ok := false;
	offset := i_offset;
	coff_file: Coff_File;
	using coff_file;

	coff_header_bytes: []byte;
	// Interpret the 4 bytes at pe_header_offset as a PE header.
	ok, coff_header_bytes, offset = get_bytes(buffer, offset, COFF_HEADER_SIZE);
	if ok == false do return coff_file, .File_Too_Short;
	header = mem.slice_data_cast([]COFF_Header, coff_header_bytes)[0];

	if header.optional_header_size > 0 {
		// Now based on the next u16le, we either read the 32 or 64 bit optional header version.
		// We already accounted for the minimum file size to include the shorter 32 bit version.
		optional_magic_bytes: []byte;
		ok, optional_magic_bytes = peek_bytes(buffer, offset, 2);
		optional_magic := mem.slice_data_cast([]Signature, optional_magic_bytes)[0];

		fmt.println(header);
		fmt.println(optional_magic);

		data_directory_entries := 0;
		data_directory_size    := 0;
		if optional_magic == Signature.PE32 {

			optional_header_bytes: []byte;
			ok, optional_header_bytes, offset = get_bytes(buffer, offset, PE32_OPTIONAL_HEADER_SIZE);
			if ok == false do return coff_file, .File_Too_Short;
			optional_header = mem.slice_data_cast([]PE32_Optional_Header, optional_header_bytes)[0];

			data_directory_entries = int(optional_header.(PE32_Optional_Header).number_of_rva_and_size);

			if int(data_directory_entries * DATA_DIRECTORY_SIZE + PE32_OPTIONAL_HEADER_SIZE) != int(header.optional_header_size) {
				return coff_file, .Malformed_Optional_Header;		
			}
		} else if optional_magic == Signature.PE64 {

			optional_header_bytes: []byte;
			ok, optional_header_bytes, offset = get_bytes(buffer, offset, PE64_OPTIONAL_HEADER_SIZE);
			if ok == false do return coff_file, .File_Too_Short;
			optional_header = mem.slice_data_cast([]PE64_Optional_Header, optional_header_bytes)[0];

			data_directory_entries = int(optional_header.(PE64_Optional_Header).number_of_rva_and_size);
			if int(data_directory_entries * DATA_DIRECTORY_SIZE + PE64_OPTIONAL_HEADER_SIZE) != int(header.optional_header_size) {
				return coff_file, .Malformed_Optional_Header;		
			}
		} else {
			return coff_file, .Malformed_Optional_Header;
		}

		data_directory_size = data_directory_entries * DATA_DIRECTORY_SIZE;
		data_directory_bytes: []byte;

		ok, data_directory_bytes, offset = get_bytes(buffer, offset, data_directory_size);
		if ok == false do return coff_file, .File_Too_Short;
		data_directory = mem.slice_data_cast([]Data_Directory_Entry, data_directory_bytes);
	}

	section_header_size := int(header.number_of_sections) * SECTION_HEADER_SIZE;
	section_header_bytes: []byte;

	ok, section_header_bytes, offset = get_bytes(buffer, offset, section_header_size);
	if ok == false do return coff_file, .File_Too_Short;
	section_headers = mem.slice_data_cast([]Section_Header, section_header_bytes);	

	return coff_file, .OK;

}

parse_pe_from_byte_array :: proc(buffer: []byte, options:=PE_Options{}) -> (PE_File, PE_Errors) {

	pe_file := PE_File{};
	using pe_file;

	file_len := len(buffer);

	minimum_file_size := DOS_HEADER_SIZE + PE_HEADER_SIZE + COFF_HEADER_SIZE + PE32_OPTIONAL_HEADER_SIZE;

	if file_len < minimum_file_size {
		return pe_file, .File_Too_Short;	
	}

	if .Fill_Raw_Buffer in options {
		raw = buffer;
	}

	// Interpret the first 64 bytes as a DOS header.
	ok, dos_header_bytes, offset := get_bytes(buffer, 0, DOS_HEADER_SIZE);
	if ok == false do return pe_file, .File_Too_Short;
	dos_header = mem.slice_data_cast([]DOS_Header, dos_header_bytes)[0];

	// Check that the magic is 0x5a4d ("MZ")
	if dos_header.signature != .DOS {
		return pe_file, .Malformed_DOS_Signature;
	}

	if dos_header.pe_header_offset <= DOS_HEADER_SIZE {
		// DOS Header says the PE header starts inside of the PE header
		return pe_file, .Malformed_DOS_Header;
	}

	pe_header_bytes: []byte;
	// Interpret the 4 bytes at pe_header_offset as a PE header.
	ok, pe_header_bytes, offset = get_bytes(buffer, int(dos_header.pe_header_offset), PE_HEADER_SIZE);
	if ok == false do return pe_file, .File_Too_Short;
	pe_header = mem.slice_data_cast([]PE_Header, pe_header_bytes)[0];

	// Now we've read past the real mode stub, we can fill it in if requested.
	if .Fill_Real_Mode_Stub in options {
		real_mode_stub = buffer[DOS_HEADER_SIZE:dos_header.pe_header_offset];
	}

	if pe_header.signature != .NT {
		if pe_header.signature == .OS2 {
			return pe_file, .Image_Is_OS2_File;
		} else if pe_header.signature == .OS2_LE {
			return pe_file, .Image_Is_OS2_LE_File;
		}
	}
	if pe_header.sig_zeroes != 0 {
		return pe_file, .Malformed_PE_Signature;
	}

	error: PE_Errors;
	coff, error = parse_coff_from_byte_array(buffer, offset);

	return pe_file, .OK;
}


main :: proc() {

	if false {
		filename := "../test/test.exe";
		if pe_file, errors := parse_pe(filename); errors == .OK {

			using pe_file.coff;
			build_date := time.Time{_nsec = i64(header.time_date_stamp) * 1e9};
			fmt.printf("\n%v was built on %v\n", filename, build_date);
			fmt.println();
			// for section, i in pe_file.section_headers {
			// 	name_ptr := &pe_file.section_headers[i].name[0];
			// 	name := transmute(string)mem.Raw_String{name_ptr, 8};

			// fmt.println("Section: ", i, name);
			// }

			fmt.println(pe_file);
		} else {
			fmt.println("Couldn't open", filename, errors);
		}
	}

	if true {
		filename := "../test/test.obj";
		if coff_file, errors := parse_coff(filename); errors == .OK {

			using coff_file;
			build_date := time.Time{_nsec = i64(header.time_date_stamp) * 1e9};
			fmt.printf("\n%v was built on %v\n", filename, build_date);
			fmt.println();
			for section, i in section_headers {
				name_ptr := &section_headers[i].name[0];
				name := transmute(string)mem.Raw_String{name_ptr, 8};

				fmt.println("Section: ", i, name);
			}
			fmt.println();
			fmt.println(coff_file);
		} else {
			fmt.println("Couldn't open", filename, errors);
		}
	}


}