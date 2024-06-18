import random
import string
import re
import os


class FunctionGenerator:
    def __init__(self, vulns, safe):
        self.vulns = vulns
        self.safe = safe

    @staticmethod
    def gen_string(length):
        return ''.join([random.choice(string.ascii_lowercase)] +
                       random.choices(string.ascii_lowercase + "_" + string.digits, k=length))

    @staticmethod
    def gen_print():
        text = FunctionGenerator.gen_string(15)

        return f"puts(\"{text}\");"

    def extract_pure_routine(self, function):
        function = function.strip()
        # set args to 0, since it's a routine
        function = function[function.index("{") + 1:-1]

        return re.sub(r"return .+?;", "", function)

    def extract_pure_routine_args(self, function):
        function = function.strip()

        args = function[function.index("(") + 1:function.index(")")].split(",")
        if args[0] != '':
            args = "\n".join([arg[4:] + f"= {random.randint(0, 200)};" for arg in args])
        else:
            args = ""

        pure = args + self.extract_pure_routine(function)
        return pure

    def gen_safe_routines(self):
        routines = ""
        routine_num = random.randint(2, 4)
        for i in range(routine_num):
            if random.random() < 0.6:
                routines += FunctionGenerator.gen_print() + "\n"
            else:
                routine = random.choice(self.safe)
                routine = self.extract_pure_routine_args(routine)
                routines += routine + "\n"
        return routines

    def prepare_vuln(self, procedure):
        before = self.gen_safe_routines()
        after = self.gen_safe_routines()
        procedure = "\nint n;\nint a;\nint b;\n" + procedure
        return procedure.format(before=before, after=after, size=random.randint(5, 9000),
                                to_read=random.randint(5, 9000))

    def prepare_safe(self):
        return self.prepare_vuln("{before}\n{after}\n")

    def gen_function(self):
        func_name = FunctionGenerator.gen_string(random.randint(8, 30))
        procedure = None
        if random.random() < 0.3:  # 30% chance
            procedure = random.choice(self.vulns)
            procedure = self.prepare_vuln(procedure)
        else:
            procedure = random.choice(self.safe)
            procedure = self.prepare_safe()

        return f"""

int {func_name}() {{
	{procedure}
	return 0;
}}

"""

    def gen_functions(self):
        functions = []
        num_routines = random.randint(2, 8)
        for i in range(num_routines):
            function = self.gen_function()

            if function in functions:
                continue

            functions.append(function)

        return "\n".join(functions)

    def generate_files(self, path, count):
        f3 = open("../template.c", "r")
        template_file = f3.read()

        for i in range(count):
            functions_code = generator.gen_functions()
            generated_file = template_file.format(functions_code)

            filename = self.gen_string(15) + ".c"
            filepath = os.path.join(path, filename)
            with open(filepath, "w") as f:
                f.write(generated_file)


f = open("../vulnFunctions.c", "r")
f2 = open("../safeFunc.c", "r")

vulns = f.read().split("// [END]")
safe = f2.read().split("// [END]")

# functions_num = random.randint(3, 10)
generator = FunctionGenerator(vulns, safe)

# print(generator.gen_print())
# for i in range(functions_num):
generator.generate_files("generated/generated_sources", count=400)

# print(generated_file)
