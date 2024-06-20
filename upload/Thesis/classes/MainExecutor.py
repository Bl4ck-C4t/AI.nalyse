from upload.Thesis.machine_learning_analysis import VulnerabilityScanner
from upload.Thesis.analysis.output_gen_lib import *
from upload.Thesis.analysis.utilities import *
from upload.Thesis.classes.Exceptions import FileTypeException
import magic

SCALE = 100000


class CompleteScanner():
    def __init__(self):
        self.scanner = VulnerabilityScanner()
        pass

    def convert_static_output(self, output):
        output = [float(x) for x in output.split(",")]
        output = list(zip(*[iter(output)] * 3))
        return [(s1 * SCALE, e1 * SCALE, 0.5) for s1, e1, c in output]

    def check_between(self, ranges1, ranges2):
        for r in ranges1:
            if ranges2[0] <= r <= ranges2[1]:
                return True
        return False

    def convert_vuln(self, vuln, prog_start):
        return int(vuln[0]) + prog_start, int(vuln[1]) + prog_start, vuln[2] * 100

    def convert_to_address(self, vulns, prog_start):
        return [self.convert_vuln(vuln, prog_start) for vuln in vulns]

    def range_intersection(self, ranges1, ranges2):  # (r1, e1), (r2, e2)
        return self.check_between(ranges1, ranges2) or self.check_between(ranges2, ranges1)

    def confirm_file_type(self, path):
        file_magic = magic.Magic()

        # Use the magic object to identify the file type
        file_type = file_magic.from_file(path)
        if "ELF" not in file_type:
            raise FileTypeException(f"Expected 'ELF' file type but got: {file_type}")

    def scanFile(self, path, verbose='auto'):
        self.confirm_file_type(path)


        zip_path = zip_file(path, "upload/Thesis/processing")
        prog_start = get_prog_start(path)

        predictions = self.scanner.get_vulns(zip_path, verbose)
        static_analysis = self.convert_static_output(analyze_program(path))
        static_analysis = self.convert_to_address(static_analysis, prog_start)
        vulns = []
        total_predictions = len(predictions)

        for s1, e1, c in static_analysis:
            score = 50

            found = False
            for p_s1, p_e1, p_c in predictions:
                if self.range_intersection((s1, e1), (p_s1, p_e1)):
                    score += (50 / total_predictions) * p_c
                    start = min(p_s1, s1)
                    end = max(p_e1, e1)
                    vulns.append(self.convert_to_address((start, end, score), prog_start))
                    found = True

            if not found:
                vulns.append((s1, e1, score))

        predictions = self.convert_to_address(predictions, prog_start)
        # vulns = self.convert_to_address(vulns, prog_start)
        return vulns, static_analysis, predictions

    def vuln_to_str(self, vuln):
        return f"Between 0x{vuln[0]:x} - 0x{vuln[1]:x} | Confidence {vuln[2]:.2f}%\n"

    def pretty_scan(self, path, verbose='auto'):
        output = ""
        vulns, static_analysis, predictions = self.scanFile(path, verbose)
        output += "Static vulnerabilities: \n"
        for vuln in static_analysis:
            output += self.vuln_to_str(vuln)

        output += "AI vulnerabilities: \n"
        for vuln in predictions:
            output += self.vuln_to_str(vuln)

        output += "Combined vulnerabilities: \n"
        for vuln in vulns:
            output += self.vuln_to_str(vuln)

        return output
