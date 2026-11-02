from dataclasses import dataclass, field
from decimal import Decimal

from .money import round_money
from .tax import tax_for


@dataclass
class Line:
    description: str
    unit_price: float
    quantity: int
    band: str = "standard"

    def net(self):
        return Decimal(str(self.unit_price)) * self.quantity


@dataclass
class Invoice:
    lines: list = field(default_factory=list)
    discount_percent: float = 0.0

    def _keep(self):
        return 1 - Decimal(str(self.discount_percent)) / 100

    def subtotal(self):
        return round_money(sum((line.net() for line in self.lines), Decimal(0)))

    def tax(self):
        return sum(
            (round_money(tax_for(line.net() * self._keep(), line.band)) for line in self.lines),
            Decimal("0.00"),
        )

    def total(self):
        return round_money(self.subtotal() * self._keep() + self.tax())
