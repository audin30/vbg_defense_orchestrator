"""Inventory Agent: expertise = what an asset is and how much it matters.

Answers the question every other agent needs first: "given these hostnames,
what's their business criticality, exposure, and sensitivity?"
"""
from sqlalchemy.orm import Session

from app.agents.context import AssetFinding, InventoryReport
from app.models import Asset


class InventoryAgent:
    def get_context(self, db: Session, asset_ids: list[str]) -> InventoryReport:
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        return InventoryReport(
            assets=[
                AssetFinding(
                    asset_id=a.id,
                    hostname=a.hostname,
                    criticality=a.criticality,
                    exposure=a.exposure.value,
                    data_sensitivity=a.data_sensitivity,
                    business_unit=a.business_unit,
                )
                for a in assets
            ]
        )


inventory_agent = InventoryAgent()
