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

	if file_len < DOS_HEADER_SIZE {
		return pe_file, .File_Too_Short;	
	}

	if .Fill_Raw_Buffer in options {
		raw = contents;
	}

	// Interpret the first 64 bytes as a DOS header.
	dos_header_bytes := contents[:DOS_HEADER_SIZE];
	dos_header = mem.slice_data_cast([]Image_DOS_Header, dos_header_bytes)[0];

	// Check that the magic is 0x5a4d ("MZ")
	if dos_header.signature != .DOS {
		return pe_file, .Malformed_DOS_Signature;
	}

	if .Fill_Real_Mode_Stub in options {
		real_mode_stub = contents[DOS_HEADER_SIZE:dos_header.pe_header_offset];
	}

	// Check the file is long enough to contain a PE header.
	pe_header_end := int(dos_header.pe_header_offset) + PE_HEADER_SIZE;
	if file_len < pe_header_end {
		return pe_file, .File_Too_Short;
	}

	// Interpret the 24 bytes at pe_header_offset as a PE header.
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

	return pe_file, .OK;
}



main :: proc() {

	s := time.tick_now();

	filename := "../test/test.exe";
	if pe_file, errors := open(filename); errors == .OK {
		build_date := time.Time{_nsec = i64(pe_file.pe_header.time_date_stamp) * 1e9};
		fmt.printf("%v was built on %v\n", filename, build_date);
		fmt.println();
		fmt.println(pe_file);
	} else {
		fmt.println("Couldn't open", filename, errors);
	}

	e := time.tick_diff(s, time.tick_now());
	fmt.printf("\n\nFinished in %s.\n", fmt.tprint(e));
}