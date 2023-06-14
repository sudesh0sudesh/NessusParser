# Nessus Parser

The Nessus Parser is a Python script that parses Nessus files and generates CSV files of affected hosts based on specific vulnerabilities.

## Prerequisites

- Python 3.x
- The following Python packages are required (install using `pip` or any other package manager):
    - `argparse`
    - `csv`
    - `re`
    - `xml.etree.ElementTree`

## Usage

1. Download or clone the repository to your local machine.

2. Open a terminal or command prompt and navigate to the directory containing the `nessus_parser.py` script.

3. Run the script using the following command:

```
python nessus_parser.py nessus_file_path

```

Replace `nessus_file_path` with the path to your Nessus file.

4. The script will generate a separate CSV file for each unique vulnerability found in the Nessus file. The CSV files will be named based on the vulnerability name, with special characters removed.

5. Additionally, an `output.csv` file will be created, which consolidates all affected hosts from different vulnerabilities into a single CSV file.
