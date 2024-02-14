import "vt"

rule new_file_rules {
	condition:
		vt.metadata.new_file
}