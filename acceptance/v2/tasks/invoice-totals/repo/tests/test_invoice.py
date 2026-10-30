from billing.invoice import Invoice, Line


def test_no_discount():
    invoice = Invoice([Line("widget", 10.00, 2)])
    assert invoice.subtotal() == 20.00
    assert invoice.tax() == 4.00
    assert invoice.total() == 24.00


def test_discount_reduces_the_taxable_amount():
    invoice = Invoice([Line("widget", 100.00, 1)], discount_percent=10)
    assert invoice.tax() == 18.00
    assert invoice.total() == 108.00
