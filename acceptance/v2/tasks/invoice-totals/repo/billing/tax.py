RATES = {"standard": 0.20, "reduced": 0.05, "zero": 0.0}


def tax_for(amount, band):
    return amount * RATES[band]
