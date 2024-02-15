/*
Collection of rules from the VirusTotal documentation (https://docs.virustotal.com/docs/writing-yara-rules-for-livehunt) for testing purposes. If yaramod does not raise an exception based on this file, the JSON definition should be correct.
*/
import "vt"

rule new_file_rules {
  condition:
    vt.metadata.new_file
}

rule infected_pe {  
  condition:  
    vt.metadata.analysis_stats.malicious > 1 and vt.metadata.file_type == vt.FileType.PE_EXE  
}

rule new_file_from_china {  
  condition:  
    vt.metadata.new_file and vt.metadata.submitter.country == "CN"  
}

rule zbot {  
  condition:  
    for any engine, signature in vt.metadata.signatures : (  
      signature contains "zbot"  
    )  
}

rule drops_foo_exe {  
  condition:  
    for any file_dropped in vt.behaviour.files_dropped : (  
      file_dropped.path contains "foo.exe"  
    )  
}
  
rule mutex_hgl345 {  
  condition:  
    for any mutex in vt.behaviour.mutexes_created : (  
       mutex == "HGL345"  
    )  
}
  
rule persistence_and_self_deletion {  
  condition:  
    for any trait in vt.behaviour.traits : ( trait == vt.BehaviourTrait.PERSISTENCE ) and  
    for any trait in vt.behaviour.traits : ( trait == vt.BehaviourTrait.SELF_DELETE )  
}

rule urls_in_asn {
meta:
  description = "New URLs whos domain resolve to certain ASN"
  author = "virustotal"
  target_entity = "url"
condition:
  vt.net.url.new_url and
  vt.net.ip.ip_asn == 74838
}

rule urls_in_iprange {
meta:
  description = "New URLs whos domain resolve to my IP range"
  author = "virustotal"
  target_entity = "url"
condition:
  vt.net.url.new_url and
  vt.net.ip.ip_as_int >= 3941835776 and vt.net.ip.ip_as_int < 3941836800 // 234.243.166.33/22
}

rule urls_with_dhash {
meta:
  description = "Domains with similar favicons"
  author = "virustotal"
  target_entity = "domain"
condition:
  vt.net.url.favicon.dhash == "f0cc929ab296cc71" or
  vt.net.url.favicon.raw_md5 == "30e26a059b7b858731e172c431d55bb4"
}

rule selfsigned_certificate_domains {
meta:
  description = "Domains with self signed certificates"
  author = "virustotal"
  target_entity = "domain"
condition:
  for any tag in vt.net.domain.tags: (
    tag == "self-signed"
  )
}

rule ip_resolutions_for_domain {
meta:
  description = "IP resolutions for a certain domain"
  author = "virustotal"
  target_entity = "ip_address"
condition:
  vt.net.ip.reverse_lookup == "somedomain.com"
}

rule NewFileDownloadedFromUrlMatchingExpression {
meta:
  description = "New Files downloaded from URLs with a pattern"
  author = "virustotal"
  target_entity = "file"
condition:
  vt.metadata.new_file and
  vt.metadata.itw.url.raw matches /example[.]com\/foo\/.*/
}

rule NewExesDownloadedFromSomeURLPattern {
meta:
  description = "New PE files downloaded from URLs with a pattern"
  author = "virustotal"
  target_entity = "file"
condition:
  vt.metadata.new_file and
  vt.metadata.itw.url.raw matches /example.com\/foo\/.*/ and
  vt.metadata.file_type == vt.FileType.PE_EXE
}

rule UrlsMatchingExpressionDownloadingNewFiles {
meta:
  description = "URLs matching a pattern that downloads a PE file for first time"
  author = "virustotal"
  target_entity = "url"
condition:
  vt.net.url.downloaded_file.new_for_url and
  vt.net.url.raw matches /example[.]com\/foo\/.*/ and
  vt.net.url.downloaded_file.file_type == vt.FileType.PE_EXE
}

rule NewURLsServingThisFile {
meta:
  description = "New URLs serving certain hash"
  author = "virustotal"
  target_entity = "url"
condition:
  vt.net.url.new_url and
  vt.net.url.downloaded_file.sha256 == "<sha256>"
}

rule NewURLsServingANewFile {
meta:
  description = "New URL with a pattern serving a new file"
  author = "virustotal"
  target_entity = "url"
condition:
  vt.net.url.new_url and
  vt.net.url.downloaded_file.new_for_vt and  // For VT
  vt.net.url.raw icontains "example.com/foo/"
}

rule URLsMatchingContent {
meta:
  description = "URLs matching a string in its content and served for first time"
  author = "virustotal"
  target_entity = "url"
strings:
  $cmdlet_str = "CmdletBinding" nocase
condition:
  vt.net.url.downloaded_file.new_for_url and
  $cmdlet_str
}

rule NewURLsServingFileContentMatchingConditions {
meta:
  description = "New URLs matching certain strings in its content"
  author = "virustotal"
  target_entity = "url"
strings:
  $foo = "foo"
  $bar = "bar"
condition:
  vt.net.url.new_url and
  all of them
}

rule NewCommunicatingDomainForDetectedFiles {
meta:
  description = "New Domains having communicating files detected"
  author = "virustotal"
  target_entity = "domain"
condition:
  vt.net.domain.new_domain and
  // communicating_file.* refers to a File behavioural analysis that reported this Domain (or URL domain).
  vt.net.domain.communicating_file.analysis_stats.malicious > 2
}

rule IPJarmMatching {
meta:
  description = "IP addresses with SSL/TLS serving with a specific JARM"
  author = "virustotal"
  target_entity = "ip_address"
condition:
  vt.net.ip.jarm == "00112233445566778899AABBCCDDEEFF"
}


rule cookieWithName {
meta:
  description = "URLs with a certain cookie name"
  author = "virustotal"
  target_entity = "url"
condition:
  for any name, value in vt.net.url.cookies : (
    name == "SuspiciousCookie"
  )
}