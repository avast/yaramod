import "pe"

include "test_rla.yar"

rule rule_pedia
{
	condition:
		for any rsrc in pe.resources : (
			int8(rsrc.offset + 0x2) == 0x14
		)
}
