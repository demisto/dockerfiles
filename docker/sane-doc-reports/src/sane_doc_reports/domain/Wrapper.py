from abc import ABC, abstractmethod


class Wrapper(ABC):
    """ Insert elements and styles that wrap normal Element objects """

    def __init__(self, cell_object, section):
        self.cell_object = cell_object
        self.section = section

    @abstractmethod
    def wrap(self):
        """
        Inserts the start of the wrapping element, in a way that inserted
         Elements will be inside the wrapping element
        """
        pass

    def __str__(self):
        return str(self)
