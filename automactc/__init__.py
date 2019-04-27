import importlib
import os

__version__ = '1.0.0.4'

# Import all files containing subclasses
for mod_file in os.listdir(os.path.join(os.path.dirname(__file__), 'modules')):
    # Skip the init or any non-py files
    if mod_file.startswith('__init__') or not mod_file.endswith('.py'):
        continue

    full_import = ['automactc', 'modules', os.path.splitext(mod_file)[0]]

    importlib.import_module('.'.join(full_import))
