import logging


class ModuleRegistry(type):

    _modules = {}

    def __new__(mcs, name, bases, class_dict):
        cls = type.__new__(mcs, name, bases, class_dict)
        ModuleRegistry.register(cls)
        return cls

    @classmethod
    def register(cls, value):
        name = value.module_name()
        # Prevent registering a unnamed modules (including the AutoMacTCModule base class)
        if not name:
            return

        if name in cls._modules:
            error = '{} module already exists'.format(name)
            raise ValueError(error)

        cls._modules[name] = value

    @classmethod
    def modules(cls):
        return cls._modules


class AutoMacTCModule(object):

    __metaclass__ = ModuleRegistry
    _mod_filename = ''

    def __init__(self, run_id, args):
        if not self._mod_filename:
            raise NotImplementedError('_mod_filename must be defined in module')

        self.options = args
        self.log = logging.getLogger(self.module_name())
        self.run_id = run_id

    @classmethod
    def module_name(cls):
        if not cls._mod_filename:
            return cls._mod_filename

        return cls._mod_filename.split('_')[-2]

    @classmethod
    def module_fullname(cls):
        if not cls._mod_filename:
            return cls._mod_filename

        return cls._mod_filename.split('.')[-1]

    def run(self):
        raise NotImplementedError("run method should be implemented in module")
