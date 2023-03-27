import yaramod

def test_modules_that_are_readonly(tmp_path):
    modules_directory = tmp_path
    my_cuckoo_module = modules_directory / "my_cuckoo.json"
    my_cuckoo_module.write_text('''{
  "kind": "struct",
  "name": "cuckoo",
  "attributes": [
    {
      "kind": "function",
      "name": "my_func",
      "return_type": "i",
      "overloads": [
        {
          "arguments": [
            {
              "type": "r",
              "name": "data"
            }
          ],
          "documentation": "Test"
        }
      ]
    }
  ]
}
''')
    my_cuckoo_module.chmod(0o444)
    ymod = yaramod.Yaramod(modules_directory=str(modules_directory))
    yfile = ymod.parse_string(r'''import "cuckoo"
rule test {
    condition:
        cuckoo.my_func(/.*/)
}
''')
    assert yfile is not None
