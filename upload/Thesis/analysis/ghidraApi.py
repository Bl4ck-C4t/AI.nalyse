import os
import shutil
import pyhidra
from pyhidra import HeadlessPyhidra

launcher = pyhidra.HeadlessPyhidraLauncher()
launcher.start()

from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType


def print_function_names(program):
    # Get the listing object from the program
    listing = program.getListing()

    # Iterate through all functions and print their names
    functions = listing.getFunctions(True)
    for func in functions:
        print(f"Function: {func.getName()}")


def delete_leftover_files(project_directory):
    # Delete all files in the project directory
    shutil.rmtree(project_directory)
    print(f"Deleted project directory: {project_directory}")


def main():
    # Paths to the two files (replace with your actual file paths)
    file_path_1 = "../generated/generated_test/vuln2"
    file_path_2 = "../generated/generated_test/a.out"

    # Create a new project
    project_name = "MyGhidraProject"
    project_location = "generated/generated_test/"  # Adjust this path
    project_path = os.path.join(project_location, project_name)

    # Ensure the project directory exists
    os.makedirs(project_path, exist_ok=True)

    with HeadlessPyhidra() as pyhidra:
        # Open the first file
        with pyhidra.open_program(file_path_1) as program_1:
            print("Functions in the first file:")
            print_function_names(program_1)

        # Open the second file
        with pyhidra.open_program(file_path_2) as program_2:
            print("Functions in the second file:")
            print_function_names(program_2)

    # Delete leftover files
    delete_leftover_files(project_path)


if __name__ == "__main__":
    main()
