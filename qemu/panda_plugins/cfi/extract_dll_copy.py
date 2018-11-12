import pefile
import sys
import r2pipe
import pandas as pd
import logging
from itertools import repeat
from multiprocessing import Pool, current_process
from os.path import exists

SOURCE = None
DEST = None
LOGGER = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s')
LOGGER.setLevel(logging.INFO)


def r2_analysis(sample_file_path):
    r2 = r2pipe.open(sample_file_path,["-2"])
    base = int(r2.cmd("?v $B"),16)
    LOGGER.info(sample_file_path + " - aaa")
    r2.cmd("aaa")
    LOGGER.info(sample_file_path + " - aap")
    r2.cmd("aap")
    LOGGER.info(sample_file_path + " - aab")
    r2.cmd("aab")
    functions_df = pd.DataFrame(r2.cmdj("aflj"))
    r2.quit()
    return list(functions_df["offset"].subtract(base))

def load_from_file(file_source=None, file_dest=None):
    if file_source is None:
        file_source = SOURCE
    LOGGER.info(str(current_process()) + ": Reading file " + file_source)
    try:
        result = r2_analysis(file_source)
    except Exception as e:
        LOGGER.info("File to open " + file_source)
        pass
    if file_dest is None:
        output_file = open(DEST,"w")
    else:
        output_file = open(file_dest,"w")
    for element in result:
        to_print = str(element)+"\n"
        output_file.write(to_print)
    output_file.close()
    LOGGER.info(str(current_process()) + ": Complete file "+ file_source)

def load_from_folder():
    print("Loading each file in folder " + SOURCE)

def parallel_load_from_file(base_folder, current_element):
        current_file = (current_element[(len(base_folder)+1):]).strip()
        # print(current_file)
        current_dest = (DEST + current_file.replace("/", "_")+".wl").lower()
        # print(current_dest)
        if not exists(current_dest):
            load_from_file(file_source=current_element.strip(), file_dest=current_dest) 

def load_from_list(base_folder):
    print("Reading list of file from: " + SOURCE + " with " + base_folder + " as base folder")
    with open(SOURCE) as f:
        file_list = f.readlines()
    for i in file_list:
        current_file = (i[(len(base_folder)+1):]).strip()
        print(current_file)
        current_dest = (DEST + current_file.replace("/", "_")+".wl").lower()
        print(current_dest)
        load_from_file(file_source=i.strip(), file_dest=current_dest)

def parallel_load_from_list(base_folder):
    print("Reading list of file from: " + SOURCE + " with " + base_folder + " as base folder")
    with open(SOURCE) as f:
        file_list = f.readlines()
    pool = Pool(5)
    pool.starmap(parallel_load_from_file, zip(repeat(base_folder), file_list))
    

def main():
    argument_list = sys.argv
    global SOURCE
    global DEST
    if(len(argument_list) < 3 ):
        print("Missing arguments")
        print("USAGE")
        print("file/folder/list source destination [other args]")
        # SOURCE = "/home/giuseppe/qcow_copy/windows/system32/zipfldr.dll"
        # DEST = "/home/giuseppe/zipfldr.dll.out"
        SOURCE = "/home/giuseppe/dll_list"
        DEST = "/home/giuseppe/file_wl/"
        base_folder = "qcow_copy"
        # load_from_list(base_folder)
        parallel_load_from_list(base_folder)
        # SOURCE="/Users/giuseppe/GitHub/panda/qemu/panda_plugins/cfi/kernelbase.dll"
        # DEST="/Users/giuseppe/GitHub/panda/qemu/panda_plugins/cfi/kernelbase.dll.wl"
        # SOURCE="/Users/giuseppe/esent.dll"

        # load_from_file(SOURCE,DEST)
        # r2_analysis(SOURCE)
    else:
        function_type = sys.argv[1]
        SOURCE = sys.argv[2]
        DEST = sys.argv[3]
        if("folder" in function_type):
            load_from_folder()
        elif("function" in function_type):
            load_from_file()
        elif("list" in function_type):
            load_from_list(sys.argv[4])
        else:
            print("Unrecognized command: " + function_type)
main()