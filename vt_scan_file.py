import vt
import time
import os
import logging
import subprocess
import shutil
from datetime import datetime

from pdb import set_trace as bp

SCAN_PATH = "/usr/local/src/virus-total/scan/"
REPORT_PATH = "/usr/local/src/virus-total/report/"
full_file_paths = []
URLs_filename = "URLs.txt"
URLs_file_header = "Paste URLs below this line\n"

def create_url_file():
        with open(SCAN_PATH + URLs_filename, "w") as url_file:
                url_file.write(URLs_file_header)

def create_scan_result_file():
        #somewhow open does not create if file does not exist so we crete the report file
        with open(REPORT_PATH + "scan_statistics.txt", "w") as scan_stats:
                scan_stats.write("Satrting new scanner instance\n")

def scan_file(file_path:str):
        logging.info(f"{str(datetime.now())} Scanning File: {file_path}")
        with open(file_path, "rb") as potential_virus:
                analysis = client.scan_file(potential_virus)  # client is the variable from main "function"
        wait_for_result(analysis, file_path)

def scan_url(url:str):
        logging.info(f"{str(datetime.now())} Scanning URL: {url}")
        analysis = client.scan_url(url)
        wait_for_result(analysis, url)

def wait_for_result(analysis, scanned):
        # asking for the analysis object until it's status is completed
        Finished = False
        while not Finished:
                result = client.get_object("/analyses/{}", analysis.id)
                logging.info(str(datetime.now()) + " " + result.status)
                if result.status == "completed":
                        Finished = True
                        with open(REPORT_PATH + "scan_statistics.txt", "a") as stats_file:
                                stats_file.write(f"{str(datetime.now())} Scan results from {scanned}:\n")
                                stats_file.write(str(result.stats).strip("{}").replace("'","")+"\n")
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
        files = [ entry.decode("utf-8", errors="replace") for entry in filenames ]  # could use errors="surrogateescape"
        try:
                files.remove(URLs_filename)
        except ValueError:
                create_url_file()
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

def scan_URLs():
        with open(SCAN_PATH + URLs_filename, "r") as urls_file:
                url_list = urls_file.readlines()
        # recreateing the empty url file after we read all the urls
        create_url_file()
        try:
                url_list.remove(URLs_file_header)
        except ValueError:
                logging.warning(str(datetime.now()) + "URLs file misses header")
        for url in url_list:
                scan_url(url.strip("\n"))


if __name__ == "__main__":
        #removing encoding arg, since ubuntu uses too old lib
        logging.basicConfig(filename="/usr/local/src/virus-total/vt_scan.log", level=logging.DEBUG)

        create_scan_result_file()
        create_url_file()

        with vt.Client(os.environ["VT_API_KEY"]) as client:

                while True:
                        scan_URLs()
                        files = get_all_files(SCAN_PATH)
                        if files != [] and files != None:
                                get_full_paths(files, SCAN_PATH)
                                for path in full_file_paths:
                                        if os.path.isfile(path):
                                                try:
                                                        scan_file(path)
                                                except Exception as Ex_scan:
                                                        logging.warning(str(datetime.now()) + " Exception while scanning")
                                                        logging.warning(f"Reason: {Ex_scan}")
                                try:
                                        delete_files_and_dirs_in_list(full_file_paths)
                                except Exception as Ex_del:
                                        logging.warning(str(datetime.now()) + " Exception while deleting scanned files")
                                        logging.warning(f"Reason: {Ex_del}")
                                del full_file_paths[:]
                                del files
                        time.sleep(1)

