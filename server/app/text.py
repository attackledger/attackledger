"""Counted nouns in messages, logs and reports: "1 result", "2 results"."""


def plural(count: int, one: str, many: str | None = None) -> str:
    return f"{count} {one if count == 1 else (many or one + 's')}"
