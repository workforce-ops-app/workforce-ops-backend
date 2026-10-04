"""Tenancy: keeping each company's data separate (decision 0016, docs/architecture/tenancy.md).

Many companies share one database. This package makes sure a request working for one
company can never read or change another company's rows:

- context.py: which company the current database session works for.
- filter.py: the CompanyOwned columns, and the automatic company filter added to every
  query and checked on every save.
"""
