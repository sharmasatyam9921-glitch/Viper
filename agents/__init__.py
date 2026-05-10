"""VIPER Agents — specialized autonomous modules."""

from agents.lateral_agent import (
    CampaignStep,
    CredentialBundle,
    FootholdInfo,
    LateralAgent,
    LateralCampaign,
    LateralState,
)
from agents.post_exploit import PostExploitAgent

__all__ = [
    "CampaignStep",
    "CredentialBundle",
    "FootholdInfo",
    "LateralAgent",
    "LateralCampaign",
    "LateralState",
    "PostExploitAgent",
]
