# Invoices disagree with the finance team's spreadsheet

Finance reported two problems with `billing`:

1. Tax is being charged on the undiscounted price. Discounts apply to the net price, so
   tax must be calculated after the discount. Mixed tax bands must still work.
2. Totals are sometimes a penny out. Money must round half-up to two decimal places,
   line by line for tax, and must not suffer from binary floating-point artefacts
   (1.005 must round to 1.01, and 0.125 to 0.13).

`python -m pytest -q` shows a failure. Fix the library. `subtotal()`, `tax()` and
`total()` must keep returning values that compare equal to plain numbers like `18.00`.
Do not change the tests.
