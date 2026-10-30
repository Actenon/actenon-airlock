from billing.invoice import Invoice, Line
from billing.money import round_money


def test_round_half_up():
    assert float(round_money(1.005)) == 1.01
    assert float(round_money(0.125)) == 0.13
    assert float(round_money(2.675)) == 2.68


def test_discount_before_tax_mixed_bands():
    invoice = Invoice([Line("a", 100.00, 1, "standard"), Line("b", 100.00, 1, "reduced")],
                      discount_percent=50)  # fmt: skip
    assert float(invoice.tax()) == 12.50
    assert float(invoice.total()) == 112.50


def test_tax_rounds_per_line():
    invoice = Invoice([Line("a", 0.03, 1, "standard"), Line("b", 0.03, 1, "standard")])
    # 0.006 rounds to 0.01 per line; a sum-then-round would give 0.01 as well, so use three.
    invoice.lines.append(Line("c", 0.03, 1, "standard"))
    assert float(invoice.tax()) == 0.03


def test_zero_band_and_no_lines():
    assert float(Invoice([Line("a", 9.99, 3, "zero")]).tax()) == 0.0
    assert float(Invoice().total()) == 0.0


def test_full_discount():
    assert float(Invoice([Line("a", 50.00, 2)], discount_percent=100).total()) == 0.0
