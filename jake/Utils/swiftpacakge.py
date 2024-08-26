# encoding: utf-8

# This file is part of CycloneDX Python Lib
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
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from cyclonedx.model.component import Component
from cyclonedx.parser import BaseParser, ParserWarning
# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore
import json


class PackageParser(BaseParser):

    def __init__(self, package_content: str) -> None:
        super().__init__()
        
        # Parse the JSON content of the Package.resolved file
        package_data = json.loads(package_content)
        
        # Iterate over each pin in the pins list
        for pin in package_data['pins']:
            identity = pin['identity']
            version = pin['state']['version']
            location = pin['location']
            
            # Extract the part of the location URL starting from 'github.com' to the end
            name_index = location.find('github.com')
            if name_index != -1:
                name = location[name_index:]  # This includes 'github.com' and the rest of the URL
            else:
                name = identity  # Fallback to identity if 'github.com' is not found

            # Construct a PackageURL using 'github' as the type since the location is a git URL
            purl = PackageURL(type='swift', name=name, version=version)
            print(purl.to_string())
            # Append the constructed component to the components list
            self._components.append(Component(
                name=identity, version=version, purl=purl
            ))

            self.comp = self._components

class PackageFileParser(PackageParser):

    def __init__(self, package_file: str) -> None:
        with open(package_file) as r:
            super(PackageFileParser, self).__init__(package_content=r.read())
            r.close()


# print(PackageFileParser("/workspaces/jake/jake/Utils/Package.resolved").comp)