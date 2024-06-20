from upload.Thesis.classes.Exceptions import FileTypeException
from upload.Thesis.classes.MainExecutor import CompleteScanner

scanner = CompleteScanner()
# path = input("Enter filepath: ")
# path = "upload/Thesis/pwn files/bof"
path = "D:/Pycharm Projects/ThesisBackend/uploads/bof"
print(scanner.prettyScan(path))
