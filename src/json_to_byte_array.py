# import json
import os
# import pathlib

PUBLIC_MODULES_DIRECTORY = '/home/ts/dev/yaramod/src/modules/public'
PUBLIC_MODULES_AS_CPP_DIRECTORY = '/home/ts/dev/yaramod/src/modules'


print('Welcome json_to_byte_array.py')

def main():
    for file in os.listdir(PUBLIC_MODULES_DIRECTORY):
        filename, extension = os.path.splitext(file)
        if extension == ".json":
            source_path = os.path.join(PUBLIC_MODULES_DIRECTORY, file)
            output_file = os.path.join(PUBLIC_MODULES_AS_CPP_DIRECTORY, filename + '.cpp')
            print(source_path)
            with open(source_path, 'r') as f:
                module_content = f.read()
            array = bytearray(module_content.encode('utf-8'))

            with open(output_file, 'wb') as f:
                print('Written to', output_file)
                f.write(array)
        else:
            continue


if __name__ == "__main__":
    main()
