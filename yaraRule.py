# -*- coding: utf-8 -*-

class YaraRule():
    """Class used to generate yara rules

    Attributes:
        str_rule_name (str): name of the yara rule
        dict_meta (dict): dictionnary holding the rule metadata
        dict_strings (dict): dictionnary holding the strings part of the rule
        str_condition (str): yara rule condition

    """

    def __init__(self, str_rule_name, dict_meta=None, dict_strings=None, str_condition="All of them"):
        """YaraRule constructor

        Args:
            str_rule_name (str): name of the yara rule
            dict_meta (dict): dictionnary holding the rule metadata
            dict_strings (dict): dictionnary holding the strings part of the rule
            str_condition (str): yara rule condition

        """
        self.str_rule_name = str_rule_name
        self.dict_meta = dict_meta
        self.dict_strings = dict_strings
        self.str_condition = str_condition

    def add_meta(self, str_keyname, str_value):
        """Add or replace a line in the rule metadata

        The metadata will be later generated in the following way :
        str_keyname = str_value

        Args:
            str_keyname(str): name of the metadata key
            str_value(str): value of the metadata

        """
        if not self.dict_meta: self.dict_meta = dict()

        self.dict_meta[str_keyname] = str_value


    def add_string(self, str_keyname, str_value):
        """Add or replace a line in the rule strings
        
        The string will be later generated in the following way :
        str_keyname = str_value
        That means, str_value can either be :
        - a basic string : str_value = '"Basic string"'
        - a regex        : str_value = '/md5: [0-9a-zA-Z]{32}/'
        - an hex string  : str_value = '{ DE AD BE EF }'

        Args:
            str_keyname(str): name of the string key
            str_value(str): value of the string value

        """
        if not self.dict_strings: self.dict_strings = dict()

        self.dict_strings[str_keyname] = str_value

    def add_string_group(self, str_key_prefix, list_values):
        """Add or replace a group of strings to the rule strings.

        It iterates over the list_values increment a value appended to str_key_prefix.
        Output example for add_string_group('s', ['"string1"','"foobar"','"string3"'])
        $s0 = "string1"
        $s1 = "foobar"
        $s3 = "string3"

        Args:
            str_key_prefix (str): prefix to use to name the string group
            list_value (list): list containing the string values

        """

        if not self.dict_strings: self.dict_strings = dict()

        for i, str_value in enumerate(list_values):
            self.add_string(str_key_prefix + str(i), str_value)

    def gen_rule(self):
        """Generate rule into a writable format.

        Generate a yara rule using dict_meta, dict_strings and str_condition.
        Ex:
        rulename {
            meta:
                metakey_1 = foo
                metakey_2 = bar
            strings:
                stringkey_1 = "VirtualAllocEx"
                stringkey_2 = { DE AD BE EF }
            condition:
                all of them
        }

        returns:
            String containing the yara generated yara rule
        
        """

        str_rule = "{} {{\n".format(self.str_rule_name)

        str_rule += "    meta:\n".format(self.str_rule_name)
        if self.dict_meta:
            for str_meta_key in self.dict_meta:
                str_rule += '        {} = {}\n'.format(str_meta_key, self.dict_meta[str_meta_key])

        str_rule += "    strings:\n".format(self.str_rule_name)
        if self.dict_strings:
            for str_strings_key in self.dict_strings:
                str_rule += '        {} = {}\n'.format(str_strings_key, self.dict_strings[str_strings_key])

        str_rule += "    condition:\n".format(self.str_rule_name)
        str_rule += "        {}\n".format(self.str_condition)
        str_rule += "}"

        return str_rule

