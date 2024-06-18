import os
import zipfile


def uncompress(zip_path):
    if not os.path.exists(zip_path):
        print(f"ZIP file '{zip_path}' does not exist.")
        return

    with zipfile.ZipFile(zip_path, 'r') as zipf:
        # Get the list of files in the zip
        file_list = zipf.namelist()

        # Ensure there's exactly one file in the zip
        if len(file_list) != 1:
            print(f"ZIP file '{zip_path}' does not contain exactly one file.")
            return

        # Extract the file
        file_name = file_list[0]
        file_path_dir = "../generated/generated_elfs"
        zipf.extract(file_name, file_path_dir)
        file_path = os.path.join(file_path_dir, file_name)
        return file_path


def zip_file(file_path, zip_dir):
    if not zip_dir.endswith('/'):
        zip_dir += '/'

        # Get the file name from the file_path and create a zip file name
    file_name = os.path.basename(file_path)
    zip_file_name = f"{file_name}.zip"
    zip_path = os.path.join(zip_dir, zip_file_name)

    # Create a ZipFile object in write mode
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        # Write the file to the zip archive
        zipf.write(file_path, arcname=file_name)

    return zip_path
