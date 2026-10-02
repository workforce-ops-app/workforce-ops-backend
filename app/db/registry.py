"""Loading every feature's models, so Base.metadata knows every table.

Alembic compares Base.metadata with the database to generate migrations
(`alembic revision --autogenerate`). A model is only in Base.metadata once its file has
been imported, so migrations/env.py calls import_all_models() first.

A feature without a models.py is normal (it has no tables) and is skipped. But a
models.py that exists and fails to import (for example a misspelled import) must stop
Alembic with the error: skipping it would leave that feature's tables out of
Base.metadata, and a generated migration could then leave them out or even drop them.
This follows the same rule as router discovery in app/main.py.
"""

import importlib
import pkgutil

from app import modules


def import_all_models() -> list[str]:
    """Import app/modules/<feature>/models.py for every feature that has one.

    Returns the names of the modules imported, for example ["app.modules.shifts.models"].
    """
    imported = []

    # Look at everything directly inside the app/modules folder.
    for module_info in pkgutil.iter_modules(modules.__path__):
        # Features are packages (folders); a loose .py file there is not a feature.
        if not module_info.ispkg:
            continue

        # The full name of the feature's models file, e.g. "app.modules.shifts.models".
        module_name = f"app.modules.{module_info.name}.models"

        try:
            # Importing the file runs its class definitions, which registers each model's
            # table in Base.metadata.
            importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            # exc.name says which module could not be found. If it is the models file
            # itself, this feature simply has no tables: skip it.
            if exc.name == module_name:
                continue
            # Otherwise models.py exists but something it imports is missing: stop with
            # the original error instead of generating migrations from incomplete models.
            raise

        imported.append(module_name)

    return imported
