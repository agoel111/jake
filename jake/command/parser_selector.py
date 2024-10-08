#
# Copyright 2019-Present Sonatype Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# encoding: utf-8

import sys
from argparse import ArgumentParser
from argparse import FileType
from typing import Optional
from typing import TextIO

from cyclonedx.parser import BaseParser
from cyclonedx_py.parser.conda import CondaListExplicitParser
from cyclonedx_py.parser.conda import CondaListJsonParser
from cyclonedx_py.parser.environment import EnvironmentParser
from cyclonedx_py.parser.pipenv import PipEnvFileParser
from cyclonedx_py.parser.pipenv import PipEnvParser
from cyclonedx_py.parser.poetry import PoetryFileParser
from cyclonedx_py.parser.poetry import PoetryParser
from cyclonedx_py.parser.requirements import RequirementsFileParser
from cyclonedx_py.parser.requirements import RequirementsParser
from jake.Utils.swiftpacakge import PackageFileParser
from jake.Utils.swiftpacakge import PackageParser

def get_parser(input_type: str, input_data_fh: Optional[TextIO]) -> BaseParser:
    if input_type == 'ENV':
        return EnvironmentParser()

    # All other input types require INPUT - let's grab it now if provided via STDIN or supplied FILE
    if input_data_fh:
        with input_data_fh:
            input_data = input_data_fh.read()
            input_data_fh.close()

        if input_type == 'CONDA':
            return CondaListExplicitParser(conda_data=input_data)

        if input_type == 'CONDA_JSON':
            return CondaListJsonParser(conda_data=input_data)

        if input_type == 'PIP':
            return RequirementsParser(requirements_content=input_data)
        
        if input_type == 'SWIFT':
            return PackageParser(package_content=input_data)

        if input_type == 'PIPENV':
            return PipEnvParser(pipenv_contents=input_data)

        if input_type == 'POETRY':
            return PoetryParser(poetry_lock_contents=input_data)

    else:
        # No data available on STDIN or the supplied FILE, so we'll try standard filenames in the current directory
        if input_type == 'PIP':
            return RequirementsFileParser(requirements_file='requirements.txt')
        
        if input_type == 'SWIFT':
            return PackageFileParser(package_content='Package.resolved')
        
        if input_type == 'PIPENV':
            return PipEnvFileParser(pipenv_lock_filename='Pipfile.lock')

        if input_type == 'POETRY':
            return PoetryFileParser(poetry_lock_filename='poetry.lock')

    raise NotImplementedError


def add_parser_selector_arguments(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        '-f',
        '--input-file',
        action='store',
        metavar='FILE_PATH',
        type=FileType('r'),
        default=(None if sys.stdin.isatty() else sys.stdin),
        help='Where to get input data from. If a path to a file is not specified directly here,'
             'then we will attempt to read data from STDIN. If there is no data on STDIN, we '
             'will then fall back to looking for standard files in the current directory that '
             'relate to the type of input indicated by the -t flag.',
        dest='sbom_input_source',
        required=False
    )
    arg_parser.add_argument(
        '-t',
        '-it',
        '--type',
        '--input-type',
        help='how jake should find the packages from which to generate your SBOM.'
             'ENV = Read from the current Python Environment; '
             'CONDA = Read output from `conda list --explicit`; '
             'CONDA_JSON = Read output from `conda list --json`; '
             'PIP = read from a requirements.txt; '
             'PIPENV = read from Pipfile.lock; '
             'POETRY = read from a poetry.lock. '
             '(Default = ENV)',
        metavar='TYPE',
        choices={'CONDA', 'CONDA_JSON', 'ENV', 'PIP', 'PIPENV', 'POETRY', 'SWIFT'},
        default='ENV',
        dest='sbom_input_type'
    )
