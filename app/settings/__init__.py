"""Company settings: each company's own choices for configurable rules (data-model.md,
company_settings; decision 0025).

- registry.py: every setting the application knows, declared by the module that uses it,
  with its type, platform default, and platform limit.
- models.py: the company_settings table. A company has a row only for a setting it has
  changed; no row means the platform default.
- service.py: reading a company's value and changing it, always within the rules.
"""
