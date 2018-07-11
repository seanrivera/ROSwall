from typing import List

from textx import metamodel_from_file


class Port(object):
    name = ''

    def __init__(self, parent, name):
        self.parent = parent
        self.name = name

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other):
        return self.name == other.name


class Rule(object):
    src = ''
    dst = ''
    min_bw = 0
    max_bw = 0
    encryption = False
    action = ''
    action_target = ''

    def __init__(self, parent: object, src: Port, dst: Port, min_bw: int, max_bw: int,
                 encryption: bool, action: str, action_target: Port = ''):
        self.parent = parent
        self.src = src
        self.dst = dst
        self.min_bw = min_bw
        self.max_bw = max_bw
        self.encryption = encryption
        self.action = action
        # TODO: This prints none when there is non. Change to ''
        self.action_target = action_target

    def __str__(self):
        return str(self.src) + ", " + str(self.dst) + ", " + str(self.min_bw) + ", " + str(self.max_bw) + ", " + \
               str(self.encryption) + ', ' + str(self.action) + " " + str(self.action_target) + ";"

    def attribute_compare(self, name, value):
        # TODO This throws an attribute error, and shouldn't?
        if getattr(self, name) == value:
            return True
        return False

    def match_check(self, args_dict: dict):
        if args_dict is not None:
            check = {k: self.attribute_compare(k, v) for k, v in args_dict.items()}
            # print(check)
            return all(check.values())
        return False


class Firewall(object):
    rules: List[Rule] = []

    def __str__(self):
        out_str = ""
        for rule in self.rules:
            out_str = out_str + str(rule) + "\n"
        return out_str

    def load_firewall_rules(self, fname: str) -> str:
        # TODO: Make this not use a constant
        firewall_metamodel = metamodel_from_file("firewall.tx", classes=[Rule, Port])
        firewall_model = firewall_metamodel.model_from_file(fname)
        self.rules = firewall_model.rules

    def get_rules_by_match(self, **kwargs):
        if kwargs is not None:
            # TODO: Lazy evaulation is probably fine but is a pain to debug
            results = list(filter(lambda x: x.match_check(kwargs), self.rules))
            return results
        return None


if __name__ == '__main__':
    fw: Firewall = Firewall()
    fw.load_firewall_rules(fname="example.fw")
    print(fw)
    print(fw.get_rules_by_match(src=Port(None, '/rosout'), max_bw=100, action="allow"))
    print("---------------------------------------------------------")
    print(fw.get_rules_by_match(src=Port(None, '/rosmaster'), action="drop"))
    print("---------------------------------------------------------")
    print(fw.get_rules_by_match(dst=Port(None, '/rosmaster')))
