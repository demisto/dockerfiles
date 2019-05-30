from abc import ABC, abstractmethod


class Element(ABC):
    """ An element that will be inserted into the doc document.
        Usually a child of a wrapper.
    """
    def __init__(self, cell_object, section):
        self.cell_object = cell_object
        self.section = section

    @abstractmethod
    def insert(self):
        pass

    def __str__(self):
        return str(self)
