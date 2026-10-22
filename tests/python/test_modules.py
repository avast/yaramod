import pytest
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


def _write_time_module(path):
    path.write_text('''{
  "kind": "struct",
  "name": "time",
  "attributes": [
    {
      "kind": "function",
      "name": "now",
      "return_type": "i",
      "overloads": [
        {
          "arguments": [],
          "documentation": "Returns current time as epoch"
        }
      ]
    }
  ]
}
''')
    return path


def test_exclusive_module_paths_loads_only_specified_modules(tmp_path):
    module_file = _write_time_module(tmp_path / "my_time.json")
    ymod = yaramod.Yaramod(yaramod.Features.AllCurrent, module_paths=[str(module_file)])

    assert "time" in ymod.modules
    assert "pe" not in ymod.modules
    assert "hash" not in ymod.modules


def test_exclusive_module_paths_can_parse_rules_with_specified_module(tmp_path):
    module_file = _write_time_module(tmp_path / "my_time.json")
    ymod = yaramod.Yaramod(yaramod.Features.AllCurrent, module_paths=[str(module_file)])

    yfile = ymod.parse_string('''import "time"
rule test {
    condition:
        time.now() > 0
}
''')
    assert yfile is not None
    assert len(yfile.rules) == 1


def test_exclusive_module_paths_rejects_unloaded_builtin_module(tmp_path):
    module_file = _write_time_module(tmp_path / "my_time.json")
    ymod = yaramod.Yaramod(yaramod.Features.AllCurrent, module_paths=[str(module_file)])

    with pytest.raises(yaramod.ParserError):
        ymod.parse_string('''import "pe"
rule test {
    condition:
        pe.is_dll()
}
''')


def test_exclusive_module_paths_empty_list_loads_no_modules():
    ymod = yaramod.Yaramod(yaramod.Features.AllCurrent, module_paths=[])
    assert len(ymod.modules) == 0


def test_exclusive_module_paths_multiple_modules(tmp_path):
    time_file = _write_time_module(tmp_path / "my_time.json")

    math_file = tmp_path / "my_math.json"
    math_file.write_text('''{
  "kind": "struct",
  "name": "math",
  "attributes": [
    {
      "kind": "function",
      "name": "entropy",
      "return_type": "f",
      "overloads": [
        {
          "arguments": [
            {"type": "i", "name": "offset"},
            {"type": "i", "name": "size"}
          ],
          "documentation": "Returns entropy"
        }
      ]
    }
  ]
}
''')

    ymod = yaramod.Yaramod(
        yaramod.Features.AllCurrent,
        module_paths=[str(time_file), str(math_file)],
    )

    assert set(ymod.modules.keys()) == {"time", "math"}


def test_yara_file_builder_exclusive_module_paths(tmp_path):
    module_file = _write_time_module(tmp_path / "my_time.json")
    builder = yaramod.YaraFileBuilder(
        yaramod.Features.AllCurrent,
        module_paths=[str(module_file)],
    )

    cond = yaramod.bool_val(True)
    rule = yaramod.YaraRuleBuilder() \
        .with_name("test") \
        .with_plain_string("$a", "hello") \
        .with_condition(cond.get()) \
        .get()

    file = builder \
        .with_module("time") \
        .with_rule(rule) \
        .get(recheck=True)

    assert file is not None
    assert len(file.rules) == 1


def test_yara_file_builder_exclusive_module_paths_ignores_unloaded(tmp_path):
    """When using exclusive module_paths, adding a module that isn't loaded
    silently drops it — the import does not appear in the output."""
    module_file = _write_time_module(tmp_path / "my_time.json")
    builder = yaramod.YaraFileBuilder(
        yaramod.Features.AllCurrent,
        module_paths=[str(module_file)],
    )

    cond = yaramod.bool_val(True)
    rule = yaramod.YaraRuleBuilder() \
        .with_name("test") \
        .with_plain_string("$a", "hello") \
        .with_condition(cond.get()) \
        .get()

    file = builder \
        .with_module("pe") \
        .with_rule(rule) \
        .get(recheck=True)

    assert file is not None
    assert 'import "pe"' not in file.text
