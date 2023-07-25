# digital_forensic_investigation.py
import os
import hashlib
import logging
import datetime
import shutil
import subprocess
import threading
import volatility.plugins.common as common
import volatility.framework.interfaces.plugins as plugins
import volatility.framework.interfaces.renderers as renderers
from volatility import framework
from volatility.framework.renderers import format_hints
from volatility.plugins.registry.registryapi import RegistryApi
from volatility.plugins.registry import printkey
from volatility.plugins.registry.lsadump import HashDump
from volatility.plugins.netscan import netscan
from volatility.plugins.malware import malfind
from volatility.plugins.imageinfo import imageinfo
from volatility.plugins.filescan import filescan
from volatility.plugins.dumpfiles import dumpfiles

class UtilsError(Exception):
    """Custom exception class for errors in the utils module."""
    pass

def calculate_checksum(file_path, algorithm="sha256", block_size=65536):
    # Calculate the checksum of a file using the specified algorithm
    supported_algorithms = ["md5", "sha1", "sha256", "sha512"]

    if algorithm not in supported_algorithms:
        raise UtilsError(f"Unsupported algorithm. Supported algorithms: {', '.join(supported_algorithms)}")

    try:
        hash_algorithm = getattr(hashlib, algorithm)()
    except AttributeError:
        raise UtilsError(f"Invalid algorithm. Supported algorithms: {', '.join(supported_algorithms)}")

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(block_size), b""):
            hash_algorithm.update(block)

    return hash_algorithm.hexdigest()

def create_directory(directory_path):
    # Create a directory if it does not exist
    if not os.path.exists(directory_path):
        try:
            os.makedirs(directory_path)
        except OSError as e:
            raise UtilsError(f"Error creating directory: {str(e)}")

def copy_file(source_path, destination_path, overwrite=False):
    # Copy a file from the source path to the destination path
    if not os.path.isfile(source_path):
        raise UtilsError(f"Source path is not a file: {source_path}")

    if not os.path.exists(os.path.dirname(destination_path)):
        create_directory(os.path.dirname(destination_path))

    if os.path.exists(destination_path) and not overwrite:
        raise UtilsError(f"Destination file already exists: {destination_path}")

    try:
        shutil.copy2(source_path, destination_path)
    except Exception as e:
        raise UtilsError(f"Error copying file: {str(e)}")

def setup_logging(log_file_path="digital_forensic_investigation.log", log_level=logging.INFO):
    # Set up logging to a file and console
    logger = logging.getLogger("digital_forensic_investigation")
    logger.setLevel(log_level)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler(log_file_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def log_info(message):
    # Log an info-level message
    logging.getLogger("digital_forensic_investigation").info(message)

def log_error(message):
    # Log an error-level message
    logging.getLogger("digital_forensic_investigation").error(message)

def run_volatility_plugin(image_path, plugin_name, plugin_args=None):
    # Run a Volatility plugin with the provided arguments on the given memory image
    framework.require_interface_version(1, 0, 0)
    ctx = framework.Context()
    ctx.config["IMAGE_PATH"] = image_path

    try:
        plugin = framework.class_subclasses(plugins.PluginInterface, lowercase=True)[plugin_name](ctx, config=ctx.config)
    except KeyError:
        raise UtilsError(f"Invalid plugin name: {plugin_name}")

    if plugin_args is not None:
        plugin_args = plugin_args.split()
        ctx.config.update(plugin_args)

    renderers = []
    for plugin in ctx.plugins.list:
        if plugin.__class__.__name__ == plugin_name:
            plugin.renderers = [volatility.framework.renderers.format_hints.RichTextHintRenderer]
            plugin.run()

            for r in plugin.renderers:
                if issubclass(r, renderers.TreeGrid):
                    result = plugin.build_tree()
                    renderers.append(result)

    return renderers

def collect_memory_dump(target_directory, memory_dump_file):
    # Collect a memory dump of the target system using LiME
    lime_module = "lime.ko"  # Path to the LiME kernel module
    memory_dump_path = os.path.join(target_directory, memory_dump_file)

    # Check if the LiME kernel module is available
    if not os.path.exists(lime_module):
        raise UtilsError("LiME kernel module not found. Make sure the module is available on the target system.")

    # Check if the target directory exists
    if not os.path.exists(target_directory):
        create_directory(target_directory)

    # Run the LiME memory acquisition command
    cmd = ["insmod", lime_module, "path=" + memory_dump_path]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise UtilsError(f"Error loading LiME kernel module: {str(e)}")

    # Check if the memory dump file was created
    if not os.path.isfile(memory_dump_path):
        raise UtilsError("Memory dump file not found. LiME memory acquisition may have failed.")

    # Unload the LiME kernel module to avoid interfering with the target system
    try:
        subprocess.run(["rmmod", "lime"], check=True)
    except subprocess.CalledProcessError as e:
        raise UtilsError(f"Error unloading LiME kernel module: {str(e)}")

    return memory_dump_path


def analyze_memory_dump(memory_dump_file):
    # Analyze the memory dump using Volatility plugins
    log_info("Analyzing memory dump...")
    plugin_args = "--profile=Win7SP1x64 pslist psscan pstree malfind"
    result = run_volatility_plugin(memory_dump_file, "windows", plugin_args=plugin_args)
    for r in result:
        print(r)
    log_info("Memory dump analysis completed.")

def analyze_network_traffic(pcap_file):
    # Analyze network traffic using Zeek (formerly Bro) tool
    log_info("Analyzing network traffic...")
    cmd = ["zeek", "-r", pcap_file]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise UtilsError(f"Error analyzing network traffic: {str(e)}")
    log_info("Network traffic analysis completed.")

def perform_data_carving(image_path, output_directory):
    # Perform data carving on the memory image to recover deleted files
    log_info("Performing data carving...")
    cmd = ["foremost", "-t", "all", "-o", output_directory, image_path]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise UtilsError(f"Error performing data carving: {str(e)}")
    log_info("Data carving completed.")

def generate_forensic_report(report_file):
    # Generate a digital forensic investigation report
    log_info("Generating forensic report...")
    report_content = "Digital Forensic Investigation Report\n\n"

    # Add investigation findings and analysis results
    # Replace this section with your custom analysis and findings

    with open(report_file, "w") as report:
        report.write(report_content)

    log_info(f"Forensic report generated: {report_file}")

def main():
    # Replace these variables with the target directory and evidence directory
    target_directory = "path/to/target_directory"
    memory_dump_file = "memory_dump.bin"
    pcap_file = "network_traffic.pcap"
    data_carving_output_directory = "recovered_files"
    report_file = "digital_forensic_investigation_report.txt"

    # Perform evidence collection
    collect_memory_dump(target_directory, memory_dump_file)
    # Add other evidence collection methods if required

    # Analyze the memory dump
    analyze_memory_dump(memory_dump_file)

    # Analyze network traffic (if network traffic capture is available)
    if os.path.isfile(pcap_file):
        analyze_network_traffic(pcap_file)

    # Perform data carving on the memory dump
    perform_data_carving(memory_dump_file, data_carving_output_directory)

    # Generate the forensic investigation report
    generate_forensic_report(report_file)

if __name__ == "__main__":
    setup_logging()
    main()
