import vt
import time
import os
import logging
import subprocess
import shutil
from os import stat
from pwd import getpwuid
from datetime import datetime

SCAN_PATH = "/usr/local/src/virus-total/scan/"
URLs_FILENAME = "URLs.txt"
URLs_FILE_HEADER = "Paste URLs below this line\n"

class URLFile:

    def create:
        with open(SCAN_PATH + URLs_FILENAME, "w") as url_file:
            url_file.write(URLs_FILE_HEADER)

class ScanResult:
"""Object to hold file names and their scan results, as well as the files owner.
VT Supports Files and URLs"""

    name = ""
    owner = ""
    scan_result = None

    def get_file_owner():
        if os.path.isfile(name):
            self.owner = getpwuid(stat(self.name).st_uid).pw_name
        return self.owner

    def split_owner_suffix():
        """Get rid of everything after @-sign to change the domain later."""
        return self.owner.split("@")[0]


class GetFilenames:

    files = []

    def check_if_path_exists(os_path: str):
        if not os.path.exists(os_path):
            raise NotAValidPath("given path does not exist in the system")

    def get_filenames_in_directory(directory: str):
        """Makes an ls to given directory and returns the values as list."""
        ls_output = subprocess.run(["ls", directory], capture_output=True)
        ls_files = ls_output.stdout.splitlines()
        filenames = [ entry.decode("utf-8", errors="replace") for entry in ls_files ]
        return filenames

    def remove_URLs_file_from_list_of_files()
        try:
            self.files.remove(URLs_FILENAME)
        except ValueError:
            URLFile.create()
        return self.files

    def get_full_path_of_every_file(filenames: list, base_path: str)
        """Recursive function to get all filenames in a given directory and its subdirectoies.
        Function saves the results in self.files"""
        for entry in filenames:
            path = os.path.join(base_path, entry)
            if os.path.isfile(path):
                self.files.append(path)
            if os.path.isdir(base_path+entry):
                new_base_path = base_path+entry+"/"
                child_dir_files = get_filenames_in_directory(new_base_path)
                get_full_path_of_every_file(child_dir_files, new_base_path)

class Scanner:

    vt_client = None
    scan_result = None

    def scan_file():
        try:
            vt_scan_file(path)
        except Exception as Ex_scan:
            logging.warning(str(datetime.now()) + " Exception while scanning")
            logging.warning(f"Reason: {Ex_scan}")

    def vt_scan_file(file_path:str):
        logging.info(f"{str(datetime.now())} Scanning File: {file_path}")
        with open(file_path, "rb") as potential_virus:
            analysis = self.vt_client.scan_file(potential_virus)
        wait_for_result(analysis, file_path)

    def wait_for_result(analysis, scanned_obj: str):
        # asking for the analysis object until it's status is completed
        Finished = False
        while not Finished:
            result = self.vt_client.get_object("/analyses/{}", analysis.id)
            logging.info(str(datetime.now()) + " " + result.status)
            if result.status == "completed":
                Finished = True
                self.scan_result = ScanResult()
                self.scan_result.name = scanned_obj
                self.scan_result.owner = self.scan_result.get_file_owner()
                self.scan_result.scan_result = result
                break
            time.sleep(30)

    def scan_URLs():
        with open(SCAN_PATH + URLs_filename, "r") as urls_file:
            url_list = urls_file.readlines()
        try:
            url_list.remove(URLs_file_header)
        except ValueError:
            logging.warning(f"{str(datetime.now())} URLs file misses header")
        if url_list:
            for url in url_list:
                vt_scan_url(url.strip("\n"))
            URLFile.create()

    def vt_scan_url(url:str):
        logging.info(f"{str(datetime.now())} Scanning URL: {url}")
        analysis = self.client.scan_url(url)
        wait_for_result(analysis, url)

class MailReport:

    def write_report(scan_results):
        for entry in objects:


def _delete_files_and_dirs_in_list(paths):
    for path in paths:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.isfile(path):
            os.remove(path)


def write_result(result, filename):
    with open(REPORT_PATH + "scan_statistics.txt", "a") as stats_file:
        stats_file.write(f"{str(datetime.now())} Scan results from {scanned_file}:\n")
        stats_file.write(str(result.stats).strip("{}").replace("'","")+"\n")














