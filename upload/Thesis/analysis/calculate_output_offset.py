import os

filename = input("Enter filename: ")
start_byte = int(input("Enter start byte: "), 16)
end_byte = int(input("Enter end byte: "), 16)

path = "D:/Pycharm projects/Thesis/pwn files/" + filename
f = open(path, "rb")
content = f.read()
filesize = os.stat(path).st_size

print(f"Opening '{path}'")
print(f"Size {filesize} bytes")

slice = content[start_byte:end_byte].hex()
slice = ' '.join(slice[i:i+2] for i in range(0, len(slice), 2))

rel_start = float(start_byte) / 100000
rel_end = float(end_byte) / 100000
print("=======================")
print(f"Content at location [{slice}]")
print("=======================")

print(f"Relative start {rel_start:.7f}")
print(f"Relative end {rel_end:.7f}")
print("Confirm bytes are correct before adding to dataset")


