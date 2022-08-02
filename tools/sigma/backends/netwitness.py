# NetWitness output backend for sigmac
# Copyright 2018 John Tuckner (@tuckner)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class NetWitnessBackend(SingleTextQueryBackend):
    """Converts Sigma rule into NetWitness saved search. Contributed by @tuckner"""
    identifier = "netwitness"
    config_required = False
    default_config = ["sysmon", "netwitness"]
    active = True
    reEscape = re.compile('(")')
    reClear = None
    andToken = " && "
    orToken = " || "
    notToken = "NOT"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\'%s\'"
    keyExpression = "%s"
    nullExpression = "%s !exists"
    notNullExpression = "%s exists"
    mapExpression = "(%s=%s)"
    mapListsSpecialHandling = True

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value[1:-1]:
                value = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', value)
                value = re.sub('\\*', '.*', value)
                value = re.sub('\\?', '.', value)
                return f"({key} regex {self.generateValueNode(value)})"
            elif type(value) == str and "*" in value:
                value = re.sub("(\*\\\\)|(\*)", "", value)
                return f"({key} contains {self.generateValueNode(value)})"
            elif type(value) in (str, int):
                return self.mapExpression % (key, self.generateValueNode(value))
            else:
                return self.mapExpression % (key, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        elif value is None:
            return self.nullExpression % (key, )
        else:
            raise TypeError(
                f"Backend does not support map values of type {str(type(value))}"
            )

    def generateMapItemListNode(self, key, value):
        equallist = []
        containlist = []
        regexlist = []
        for item in value:
            if type(item) == str and "*" in item[1:-1]:
                item = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', item)
                item = re.sub('\\*', '.*', item)
                item = re.sub('\\?', '.', item)
                regexlist.append(self.generateValueNode(item))
            elif type(item) == str and (item.endswith("*") or item.startswith("*")):
                item = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', item)
                item = re.sub("(\*\\\\)|(\*)", "", item)
                containlist.append(self.generateValueNode(item))
            else:
                equallist.append(self.generateValueNode(item))
        fmtitems = []
        if equallist:
            fmtitems.append(f'{key} = {", ".join(equallist)}')
        if containlist:
            fmtitems.append(f'{key} contains {", ".join(containlist)}')
        if regexlist:
            fmtitems.append(f'{key} regex {", ".join(regexlist)}')
        return "("+" || ".join(filter(None, fmtitems))+")"

    def generateValueNode(self, node):
        return self.valueExpression % (str(node))

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for k in sigmaparser.parsedyaml["detection"].keys():
            if k.startswith('keyword'):
                raise NotImplementedError("Backend does not support keywords")
        for parsed in sigmaparser.condparsed:
            return self.generateQuery(parsed, sigmaparser)

    def generateQuery(self, parsed, sigmaparser):
        return self.generateNode(parsed.parsedSearch)
