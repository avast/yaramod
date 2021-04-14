import json
import getopt
import os
import sys


def main(argv):
    input_directory = ""
    output_directory = ""
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print("ERROR: Bad arguments for json_to_array.py: -i <input_directory> -o <output_directory>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print("json_to_array.py -i <input_directory> -o <output_directory>")
            sys.exit()
        elif opt in ("-i", "--ifile"):
            input_directory = arg
        elif opt in ("-o", "--ofile"):
            output_directory = arg

    list_file = os.path.join(output_directory, 'module_list' + '.h')
    with open(list_file, 'w') as f:
        f.write('''/**
* @file modules/generated/module_list.h
* @brief File containing includes of generated module files. Generated by json_to_array.py
* @copyright (c) 2021 Avast Software, licensed under the MIT license
*/
#pragma once

''')
    module_names = []

    for file in os.listdir(input_directory):
        filename, extension = os.path.splitext(file)
        if extension != ".json":
            continue
        source_path = os.path.join(input_directory, file)
        output_file = os.path.join(output_directory, filename + "_generated.h")

        with open(source_path, "r") as f:
            data = json.load(f)
        if "name" not in data:
            continue
        name = data["name"]
        module_names.append(filename)

        with open(source_path, "r") as f:
            module_content = f.read()

        with open(output_file, "w") as f:
            f.write('''/**
 * @file modules/generated/module_''' + name + '''_generated.h
 * @brief Definition of ''' + filename + ''' written in array. Generated by json_to_array.py
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */
 #pragma once

 #include "yaramod/types/modules/module_content.h"

 namespace yaramod {

 namespace modules {

 class G''' + filename + " : public ModuleContent\n"
 + '{\npublic:\n\tG' + filename + '() : ModuleContent("' + name + '", {')
            for c in module_content:
                if c == "\"":
                    f.write("'\\\"', ")
                elif c == "\'":
                    f.write("'\\'', ")
                elif c == "\n":
                    f.write("'\\n', ")
                elif c == "\\":
                    f.write("'\\\\', ")
                else:
                    f.write("\'" + c + "\', ")
            f.write('\'\\n\'})\n\t{\n\t}\n};\n\n} // namespace modules\n\n} // namespace yaramod\n')

        print("Created ModuleContent", output_file, "from", filename)

    with open(list_file, "a") as f:
        for n in module_names:
            f.write('#include "' + n + '_generated.h"\n')
        f.write("\n#include <vector>\n\nnamespace yaramod {\n\nnamespace modules {\n\n"
            + "class ModuleList {\npublic:\n\tstd::vector<ModuleContent> list = {")
        ms = ""
        for n in module_names:
            ms +="G" + n + "{}, "
        if module_names:
            f.write(ms[:-2])
        f.write("};\n};\n\n} //namespace modules\n\n} // namespace yaramod\n")


if __name__ == "__main__":
    main(sys.argv[1:])
