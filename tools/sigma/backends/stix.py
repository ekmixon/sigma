import sigma
from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend


class STIXBackend(SingleTextQueryBackend):
    """Converts Sigma rule into STIX pattern."""
    identifier = "stix"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    valueExpression = "\'%s\'"
    mapExpression = "%s = %s"
    notMapExpression = "%s != %s"
    mapListsSpecialHandling = True
    sort_condition_lists = True

    def cleanKey(self, key):
        if key is None:
            raise TypeError(f"Backend does not support empty key {str(key)}")
        else:
            return key

    def cleanValue(self, value):
        return value

    def generateANDNode(self, node, currently_within_NOT_node=False):
        generated = [self.generateNode(val, currently_within_NOT_node) for val in node]
        if filtered := [g for g in generated if g is not None]:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node, currently_within_NOT_node=False):
        generated = [self.generateNode(val, currently_within_NOT_node) for val in node]
        if filtered := [g for g in generated if g is not None]:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node, currently_within_NOT_node=False):
        currently_within_NOT_node = not(currently_within_NOT_node)
        generated = self.generateNode(node.item, currently_within_NOT_node)
        return generated if generated is not None else None

    def generateSubexpressionNode(self, node, currently_within_NOT_node=False):
        if generated := self.generateNode(node.items, currently_within_NOT_node):
            return self.subExpression % generated
        else:
            return None

    def generateMapItemNode(self, node, currently_within_NOT_node=False):
        fieldname, value = node

        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if currently_within_NOT_node:
                return self.notMapExpression % (transformed_fieldname, self.generateNode(value))
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value, currently_within_NOT_node)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError(
                f"Backend does not support map values of type {str(type(value))}"
            )

    def generateMapItemListNode(self, key, value, currently_within_NOT_node=False):
        items_list = []
        for item in value:
            if type(item) == str and "*" in item:
                item = item.replace("*", "%")
                if currently_within_NOT_node:
                    items_list.append(
                        f'{self.cleanKey(key)} NOT LIKE {self.generateValueNode(item)}'
                    )

                else:
                    items_list.append(f'{self.cleanKey(key)} LIKE {self.generateValueNode(item)}')
            elif currently_within_NOT_node:
                items_list.append(f'{self.cleanKey(key)} != {self.generateValueNode(item)}')
            else:
                items_list.append(f'{self.cleanKey(key)} = {self.generateValueNode(item)}')
        if currently_within_NOT_node:
            return '(' + " AND ".join(items_list) + ')'
        else:
            return '('+" OR ".join(items_list)+')'

    def generateMapItemTypedNode(self, key, value):
        if type(value) != SigmaRegularExpressionModifier:
            raise NotImplementedError(
                f"Type modifier '{value.identifier}' is not supported by backend"
            )

        regex = str(value)
            # Regular Expressions have to match the full value in QRadar
        if not regex.startswith('^') and not regex.startswith('.*'):
            regex = f'.*{regex}'
        if not regex.endswith('$') and not regex.endswith('.*'):
            regex += '.*'
        return f"{self.cleanKey(key)} MATCHES {self.generateValueNode(regex)}"

    def generateMapItemNode(self, node, currently_within_NOT_node=False):
        key, value = node
        if ":" not in key:
            # key wasn't mapped
            return None
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                value = value.replace("*", "%")
                if currently_within_NOT_node:
                    return f"{self.cleanKey(key)} NOT LIKE {self.generateValueNode(value)}"
                return f"{self.cleanKey(key)} LIKE {self.generateValueNode(value)}"
            elif type(value) in (str, int):
                if currently_within_NOT_node:
                    return self.notMapExpression % (self.cleanKey(key), self.generateValueNode(value))
                return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value, currently_within_NOT_node)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(key, value)
        else:
            raise TypeError(
                f"Backend does not support map values of type {str(type(value))}"
            )

    def generateValueNode(self, node, keypresent=True):
        if keypresent != False:
            return self.valueExpression % (self.cleanValue(str(node)))
        if type(node) == str and "*" in node:
            node = node.replace("*", "%")
        return "artifact:payload_bin LIKE \'{0}\'".format(self.cleanValue(str(node)))

    def generateNode(self, node, currently_within_NOT_node=False):
        if type(node) == sigma.parser.condition.ConditionAND:
            if currently_within_NOT_node:
                return self.generateORNode(node, currently_within_NOT_node)
            return self.generateANDNode(node, currently_within_NOT_node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            if currently_within_NOT_node:
                return self.generateANDNode(node, currently_within_NOT_node)
            return self.generateORNode(node, currently_within_NOT_node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node, currently_within_NOT_node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node, currently_within_NOT_node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node, currently_within_NOT_node)
        elif type(node) in (str, int):
            return self.generateValueNode(node, keypresent=False)
        else:
            raise TypeError(
                f"Node type {str(type(node))} was not expected in Sigma parse tree"
            )

    def generate(self, sigmaparser):
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            return f"[{query}]"

    def generateQuery(self, parsed, sigmaparser):
        return self.generateNode(parsed.parsedSearch)
