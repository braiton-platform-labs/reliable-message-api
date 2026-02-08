from __future__ import annotations


class NotFoundError(Exception):
    pass


class DuplicateError(Exception):
    pass


class IdempotencyConflictError(Exception):
    pass
