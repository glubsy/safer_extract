from typing import Optional

class ArchiveEntry():
    """Describes a generic archive entry."""

    __slots__ = ["name", "path", "error", "password", "updated_name"]

    def __init__(
        self, 
        name: str, 
        path_parts: Optional[list] = None
    ) -> None:
        # log.debug(f"ArchiveEntry({name}, {path_parts})")
        self.name: str = name
        self.path: Optional[str] = "/".join(path_parts) \
                    if path_parts is not None and len(path_parts) > 0 \
                    else None
        self.error: Optional[str] = None
        self.password: Optional[str] = None
        self.updated_name: Optional[str] = None

    def __hash__(self) -> int:
        if self.path is not None:
            return hash(self.path + "/" + self.name)
        return hash(self.name)
    
    def __repr__(self) -> str:
        if self.path is not None:
            return self.path + "/" + self.name
        return self.name
    
    def __eq__(self, other):
        return (isinstance(other, type(self))
                and hash(other) == hash(self))