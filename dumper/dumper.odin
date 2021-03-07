package ode_dumper

import "core:math/bits"
import "core:fmt"
import "core:mem"
import "core:time"
import "core:os"

import pe "../formats"

main :: proc() {

	s := time.tick_now();

	filename := "../test/test.exe";
	if pe_file, errors := pe.open(filename); errors == .OK {
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