"""Pagination utilities for SQLAlchemy async queries."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, List, Optional, TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


@dataclass
class PaginationParams:
    """Encapsulate page/size pagination parameters with validation."""

    page: int = 1
    size: int = 50

    @property
    def offset(self) -> int:
        """Return the SQL OFFSET for this page."""
        return (self.page - 1) * self.size

    def validate(self) -> None:
        """Raise :class:`ValueError` if parameters are out of range."""
        if self.page < 1:
            raise ValueError("page must be >= 1")
        if not (1 <= self.size <= 1000):
            raise ValueError("size must be between 1 and 1000")


@dataclass
class PaginatedResult(Generic[T]):
    """Container for a single page of query results with metadata."""

    items: List[T]
    total: int
    page: int
    size: int

    @property
    def pages(self) -> int:
        """Total number of pages available."""
        if self.size <= 0:
            return 1
        return max(1, (self.total + self.size - 1) // self.size)

    @property
    def has_next(self) -> bool:
        """``True`` when there is at least one more page after the current one."""
        return self.page < self.pages

    @property
    def has_prev(self) -> bool:
        """``True`` when the current page is not the first page."""
        return self.page > 1

    def to_dict(self) -> dict:
        """Serialise metadata (without items) to a plain dict."""
        return {
            "total": self.total,
            "page": self.page,
            "size": self.size,
            "pages": self.pages,
            "has_next": self.has_next,
            "has_prev": self.has_prev,
        }


async def paginate_query(
    session: AsyncSession,
    query: Any,
    params: PaginationParams,
    model_class: Optional[Any] = None,
) -> PaginatedResult:
    """Execute a paginated SQLAlchemy *select* statement.

    Parameters
    ----------
    session:
        An open :class:`~sqlalchemy.ext.asyncio.AsyncSession`.
    query:
        A SQLAlchemy ``select()`` statement (not yet executed).
    params:
        A :class:`PaginationParams` instance describing the desired page.
    model_class:
        Unused – kept for API compatibility.

    Returns
    -------
    PaginatedResult
        Contains the items for the requested page and pagination metadata.
    """
    params.validate()

    # Total count via a sub-query so we reuse the same filters
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total: int = total_result.scalar() or 0

    # Fetch the page
    paginated = query.offset(params.offset).limit(params.size)
    result = await session.execute(paginated)
    items = list(result.scalars().all())

    return PaginatedResult(
        items=items,
        total=total,
        page=params.page,
        size=params.size,
    )
