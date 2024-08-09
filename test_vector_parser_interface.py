import abc

class Parser(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, infile, outfile):
        pass

    @abc.abstractmethod
    def parse(self):
        pass

    @abc.abstractmethod
    def rsp_to_bin_parse(self):
        pass

    @abc.abstractmethod
    def json_to_bin_parse(self):
        pass

    @abc.abstractmethod
    def bin_to_json_parse(self):
        pass
