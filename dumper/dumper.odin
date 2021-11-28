package ode_dumper

import "core:fmt"
import "core:strings"
import "core:time"

import pe "../formats"

main :: proc() {

	if true {
		user_formatters: map[typeid]fmt.User_Formatter
		fmt.set_user_formatters(&user_formatters)

		err: fmt.Register_User_Formatter_Error
		err = fmt.register_user_formatter(pe.Section_Header, pe.section_header_formatter)
	}

	if true {
		filename := "../test/test.exe"
		if pe_file, errors := pe.parse_pe(filename); errors == .OK {

			using pe_file.coff
			build_date := time.Time{_nsec = i64(header.time_date_stamp) * 1e9}
			fmt.printf("\n%v was built on %v\n", filename, build_date)
			fmt.println()
			for section, i in section_headers {
				name := strings.trim_right_null(string(section_headers[i].name[:]))

				fmt.println("Section: ", i, name)
			}

			fmt.printf("PE File:\n%#v\n", pe_file)
		} else {
			fmt.println("Couldn't open", filename, errors)
		}
	}

	if true {
		filename := "../test/test.obj"
		if coff_file, errors := pe.parse_coff(filename); errors == .OK {

			pe.print_coff_file(filename, coff_file)

		} else {
			fmt.println("Couldn't open", filename, errors)
		}
	}
}