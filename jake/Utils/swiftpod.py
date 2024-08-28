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
import re


class PodParser(BaseParser):

    def __init__(self, pod_content: str) -> None:
        super().__init__()
        
        pod_data = self.parse_podfile_lock(pod_content)
        
        # Iterate over each pin in the pins list
        for pod in pod_data:
            name = pod['name']
            identity = pod['identity']
            version = pod['version']
            
            # Construct a PackageURL using 'github' as the type since the location is a git URL
            purl = PackageURL(type='cocoapods', name=name, version=version)
            print(purl.to_string())
            # Append the constructed component to the components list
            self._components.append(Component(
                name=identity, version=version, purl=purl
            ))

            self.comp = self._components
    
    def parse_podfile_lock(self, content):
        pod_dicts = []
        pod_regex = re.compile(r"^\s*-\s(?P<name>[^\s(]+)(?:\s\/[^\s(]+)?\s\((?P<version>\d+(\.\d+)*)\):?$", re.MULTILINE)
        
        matches = pod_regex.finditer(content)
        seen_pods = set()

        for match in matches:
            pod_name = match.group('name')
            pod_version = match.group('version')
            
            if pod_name not in seen_pods:
                pod_dicts.append({
                    "name": pod_name,
                    "identity": pod_name,
                    "version": pod_version
                })
                seen_pods.add(pod_name)

        return pod_dicts
    
class PodFileParser(PodParser):

    def __init__(self, pod_file: str) -> None:
        with open(pod_file) as r:
            super(PodFileParser, self).__init__(pod_content=r.read())
            r.close()


# print(PodFileParser("/workspaces/jake/iOS-SalesDemoApp/Podfile.lock").comp)