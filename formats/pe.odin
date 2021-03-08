package ode_file_format

/*
	PE format support
*/

import "core:os"
import "core:math/bits"
import "core:fmt"
import "core:mem"
import "core:time"

open :: proc {
	open_from_file,
	open_from_byte_array,
};

open_from_file :: proc(path: string, options:=PE_Options{}) -> (PE_File, PE_Errors) {

	if contents, ok := os.read_entire_file(path); ok {
		return open_from_byte_array(contents, options);
	} else {
		return PE_File{}, .Could_Not_Open_File;
	}
}

open_from_byte_array :: proc(contents: []byte, options: PE_Options) -> (PE_File, PE_Errors) {

	pe_file := PE_File{};
	using pe_file;

	file_len := len(contents);

	minimum_file_size := DOS_HEADER_SIZE + PE_HEADER_SIZE + COFF_HEADER_SIZE + PE32_OPTIONAL_HEADER_SIZE;

	if file_len < minimum_file_size {
		return pe_file, .File_Too_Short;	
	}

	if .Fill_Raw_Buffer in options {
		raw = contents;
	}

	// Interpret the first 64 bytes as a DOS header.
	dos_header_bytes := contents[:DOS_HEADER_SIZE];
	dos_header = mem.slice_data_cast([]DOS_Header, dos_header_bytes)[0];

	// Check that the magic is 0x5a4d ("MZ")
	if dos_header.signature != .DOS {
		return pe_file, .Malformed_DOS_Signature;
	}

	if dos_header.pe_header_offset <= DOS_HEADER_SIZE {
		// DOS Header says the PE header starts inside of the PE header
		return pe_file, .Malformed_DOS_Header;
	}

	if .Fill_Real_Mode_Stub in options {
		real_mode_stub = contents[DOS_HEADER_SIZE:dos_header.pe_header_offset];
	}

	// Check the file is long enough to contain all headers and such
	minimum_file_size += int(dos_header.pe_header_offset);
	if file_len < minimum_file_size {
		return pe_file, .File_Too_Short;
	}

	// Interpret the 4 bytes at pe_header_offset as a PE header.
	pe_header_end := int(dos_header.pe_header_offset) + PE_HEADER_SIZE;
	pe_header_bytes := contents[dos_header.pe_header_offset:pe_header_end];
	pe_header = mem.slice_data_cast([]PE_Header, pe_header_bytes)[0];

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

	// TODO(Jeroen): Factor out COFF parsing to its own function.
	// It'll be reused in object file parsing.

	coff_header_end := pe_header_end + COFF_HEADER_SIZE;
	// Interpret the 4 bytes at pe_header_offset as a PE header.
	coff_header_bytes := contents[pe_header_end:coff_header_end];
	coff_header = mem.slice_data_cast([]COFF_Header, coff_header_bytes)[0];

	// Now based on the next u16le, we either read the 32 or 64 bit optional header version.
	// We already accounted for the minimum file size to include the shorter 32 bit version.

	optional_magic_bytes := contents[coff_header_end:coff_header_end+2];
	optional_magic := mem.slice_data_cast([]Signature, optional_magic_bytes)[0];

	if optional_magic == Signature.PE32 {

		optional_header_end := coff_header_end + PE32_OPTIONAL_HEADER_SIZE;
		optional_header_bytes := contents[coff_header_end:optional_header_end];
		optional_header = mem.slice_data_cast([]PE32_Optional_Header, optional_header_bytes)[0];
	} else if optional_magic == Signature.PE64 {

		minimum_file_size += (PE64_OPTIONAL_HEADER_SIZE - PE32_OPTIONAL_HEADER_SIZE);
		if file_len < minimum_file_size {
			return pe_file, .File_Too_Short;
		}

		optional_header_end := coff_header_end + PE64_OPTIONAL_HEADER_SIZE;
		optional_header_bytes := contents[coff_header_end:optional_header_end];
		optional_header = mem.slice_data_cast([]PE64_Optional_Header, optional_header_bytes)[0];
	} else {
		return pe_file, .Malformed_Optional_Header;
	}

	return pe_file, .OK;
}


main :: proc() {

	parse_start := time.tick_now();
	filename := "../test/test.exe";
	if pe_file, errors := open(filename); errors == .OK {
		parse_time := time.tick_diff(parse_start, time.tick_now());

		fmt.printf("PE file read and parsed in %s.\n", fmt.tprint(parse_time));

		build_date := time.Time{_nsec = i64(pe_file.coff_header.time_date_stamp) * 1e9};
		fmt.printf("\n%v was built on %v\n", filename, build_date);
		fmt.println();
		fmt.println(pe_file);
	} else {
		fmt.println("Couldn't open", filename, errors);
	}

}