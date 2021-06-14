import "pe"

rule rule_rla {
	condition:
		for any resource in pe.resources : (resource.language == 1000)
}
