"""
Module overview:
- Purpose: Define the data model for application metadata extracted via Jadx.
- Important classes: AppMetadata.
"""

import json
from typing import Optional
from pydantic import BaseModel

class AppMetadata(BaseModel):
    """
    Metadata about an Android app extracted from Jadx.
    """
    app_name: str
    package: str
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    
    def __str__(self) -> str:
        """
        Return a human-readable string representation of the AppMetadata.
        """
        fields = [
            f"App Name     : {self.app_name or 'N/A'}",
            f"Package      : {self.package}",
            f"Min SDK      : {self.min_sdk or 'N/A'}",
            f"Target SDK   : {self.target_sdk or 'N/A'}",
            f"Version Name : {self.version_name or 'N/A'}",
            f"Version Code : {self.version_code or 'N/A'}"
        ]
        return "AppMetadata : \n" + "\n".join(fields)
    
    def to_json(self, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False, ) -> str:
        """
        Serialize this AppMetadata to a JSON string.
        - exclude_none=True drops unset optional fields
        - indent provides pretty-printing
        """
        data = self.model_dump(exclude_none=exclude_none)
        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)