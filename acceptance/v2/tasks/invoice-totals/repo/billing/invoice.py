from dataclasses import dataclass, field

from .money import round_money
from .tax import tax_for


@dataclass
class Line:
    description: str
    unit_price: float
    quantity: int
    band: str = "standard"


@dataclass
class Invoice:
    lines: list = field(default_factory=list)
    discount_percent: float = 0.0

    def subtotal(self):
        return round_money(sum(line.unit_price * line.quantity for line in self.lines))

    def tax(self):
        return round_money(
            sum(tax_for(line.unit_price * line.quantity, line.band) for line in self.lines)
        )

    def total(self):
        gross = self.subtotal() + self.tax()
        return round_money(gross - gross * self.discount_percent / 100)
