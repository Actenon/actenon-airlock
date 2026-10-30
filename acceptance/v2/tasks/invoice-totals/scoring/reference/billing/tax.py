from decimal import Decimal

RATES = {"standard": Decimal("0.20"), "reduced": Decimal("0.05"), "zero": Decimal("0")}


def tax_for(amount, band):
    return amount * RATES[band]
