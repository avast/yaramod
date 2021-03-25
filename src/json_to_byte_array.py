import pickle
import getopt
import os
import sys


def main(argv):
    input_directory = ''
    output_directory = ''
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print('ERROR: Bad arguments for json_to_byte_array.py: -i <input_directory> -o <output_directory>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('json_to_byte_array.py -i <input_directory> -o <output_directory>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            input_directory = arg
        elif opt in ("-o", "--ofile"):
            output_directory = arg

    for file in os.listdir(input_directory):
        filename, extension = os.path.splitext(file)
        if extension != ".json":
            continue
        source_path = os.path.join(input_directory, file)
        output_file = os.path.join(output_directory, filename + '.cpp')
        with open(source_path, 'r') as f:
            module_content = f.read()

        with open(output_file, 'wb') as f:
            pickle.dump(module_content.encode('utf-8'), f)
            print('################################################', 'Created module', output_file, 'from', filename)

        with open(output_file, 'rb') as f:
            content = pickle.load(f)
            # print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>', content)


if __name__ == "__main__":
    main(sys.argv[1:])
