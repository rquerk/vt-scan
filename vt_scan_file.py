import vt
import time
import os
import logging
import subprocess
import shutil
from datetime import datetime

BASE_PATH = "/usr/local/src/virus-total/scan/"
full_file_paths = []

def scan_file(file_path:str):
        with open(file_path, "rb") as potential_virus:
                analysis = client.scan_file(potential_virus)

        # asking for the analysis object until it's status is completed
        Finished = False
        while not Finished:
                result = client.get_object("/analyses/{}", analysis.id)
                logging.info(str(datetime.now()) + " " + result.status)
                if result.status == "completed":
                        Finished = True
                        with open("/usr/local/src/virus-total/report/scan_statistics.txt", "a") as stats_file:
                                stats_file.write(f"{str(datetime.now())} Scan results from {file_path}\n")
                                stats_file.write(str(result.stats)+"\n")
                        break
                time.sleep(30)


def is_valid_path(path) -> bool:
        return os.path.exists(path)

def error_not_a_valid_path():
        logging.error(str(datetime.now()) + " not a valid path")
        exit(1)

def check_if_path_exists(path):
        if not is_valid_path(path):
                error_not_a_valid_path()

def get_all_files(directory:str) -> []:
        """returns list of filenames in given directory"""
        check_if_path_exists(directory)
        ls_output = subprocess.run(["ls", directory], capture_output=True)
        filenames = ls_output.stdout.splitlines()
        files = [ entry.decode("utf-8") for entry in filenames ]
        return files


def get_full_paths(files:list,  base_path:str):
        """filles list of full file paths of given directory"""
        for entry in files:
                full_file_path = os.path.join(base_path, entry)
                full_file_paths.append(full_file_path)
                if os.path.isdir(base_path+entry):
                        new_base_path = base_path+entry+"/"
                        child_dir_files = get_all_files(new_base_path)
                        get_full_paths(child_dir_files, new_base_path)

def delete_files_and_dirs_in_list(paths):
        for path in paths:
                if os.path.isdir(path):
                        shutil.rmtree(path)
                elif os.path.isfile(path):
                        os.remove(path)


if __name__ == "__main__":
	#removing encoding arg, since ubuntu uses too old lib
        logging.basicConfig(filename="/usr/local/src/virus-total/vt_scan.log", level=logging.DEBUG)
	#somewhow open does not create if file does not exist so we crete the report file
        with open("/usr/local/src/virus-total/report/scan_statistics.txt", "w") as scan_stats:
                scan_stats.write("Satrting new scanner instance\n")

        while True:
                files = get_all_files(BASE_PATH)
                if files != [] and files != None:
                        get_full_paths(files, BASE_PATH)
                        client = vt.Client(os.environ["VT_API_KEY"])
                        for path in full_file_paths:
                                if os.path.isfile(path):
                                        logging.info(str(datetime.now()) + " Scanning: " + path)
                                        try:
                                                scan_file(path)
                                        except Exception as Ex_scan:
                                                logging.warning(str(datetime.now()) + " Exception while scanning")
                                                logging.warning(f"Reason: {Ex_scan}")
                        client.close()
                        try:
                                delete_files_and_dirs_in_list(full_file_paths)
                        except Exception as Ex_del:
                                logging.warning(str(datetime.now()) + " Exception while deleting scanned files")
                                logging.warning(f"Reason: {Ex_del}")
                        del full_file_paths[:]
                        del files
                time.sleep(1)

