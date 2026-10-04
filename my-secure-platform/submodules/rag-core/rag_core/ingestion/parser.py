"""Парсинг источников и извлечение main content (F-A-01, F-A-05).

Поддерживаются: text/plain, text/markdown, text/html (stdlib html.parser —
никаких внешних зависимостей и lazy-loading; в prod-контуре Scrapy/Playwright
работают ВНУТРЬ pipeline загрузки источников, сюда поступает готовый текст).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

# Теги, содержимое которых НЕ является main content (F-A-05).
_DROP_TAGS = {
    "script", "style", "noscript", "template", "svg", "iframe", "object",
    "nav", "header", "footer", "aside", "form", "button", "menu",
}
# Теги-контейнеры основного содержимого (эвристика приоритета).
_MAIN_TAGS = {"main", "article"}


class _MainContentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._drop_depth = 0
        self._main_depth = 0
        self._in_main_region = False
        self._main_parts: list[str] = []
        self._fallback_parts: list[str] = []
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _DROP_TAGS:
            self._drop_depth += 1
            return
        if tag in _MAIN_TAGS:
            self._main_depth += 1
            self._in_main_region = True
        if tag == "title":
            self._in_title = True
        if tag in ("p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6",
                   "td", "pre", "blockquote", "br"):
            self._emit("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _DROP_TAGS and self._drop_depth > 0:
            self._drop_depth -= 1
        elif tag in _MAIN_TAGS and self._main_depth > 0:
            self._main_depth -= 1
            if self._main_depth == 0:
                self._in_main_region = False
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._drop_depth:
            return
        if self._in_title:
            self.title += data
        self._emit(data)

    def _emit(self, text: str) -> None:
        if self._in_main_region:
            self._main_parts.append(text)
        self._fallback_parts.append(text)

    def get_text(self) -> str:
        parts = self._main_parts if self._main_parts else self._fallback_parts
        return "".join(parts)


@dataclass(frozen=True)
class ParsedDocument:
    text: str
    title: str
    mime: str


_WHITESPACE_RE = re.compile(r"[ \t\r\f\v]+")
_NEWLINES_RE = re.compile(r"\n{3,}")


def normalize_whitespace(text: str) -> str:
    text = _WHITESPACE_RE.sub(" ", text)
    text = _NEWLINES_RE.sub("\n\n", text)
    return text.strip()


def parse_html(raw: str) -> ParsedDocument:
    parser = _MainContentParser()
    parser.feed(raw)
    parser.close()
    return ParsedDocument(
        text=normalize_whitespace(parser.get_text()),
        title=parser.title.strip(),
        mime="text/html")


def parse_markdown(raw: str) -> ParsedDocument:
    """Лёгкая нормализация markdown: снятие разметки с сохранением текста."""
    text = raw
    text = re.sub(r"```.*?```", " ", text, flags=re.S)      # код-блоки — не контент KB
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)   # картинки → alt
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)    # ссылки → текст
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.M)
    text = re.sub(r"^\s{0,3}>\s?", "", text, flags=re.M)
    text = re.sub(r"(\*{1,3}|_{1,3})(?=\S)(.+?)(?<=\S)\1", r"\2", text)
    return ParsedDocument(text=normalize_whitespace(text),
                          title=_first_heading(raw), mime="text/markdown")


def _first_heading(raw: str) -> str:
    m = re.search(r"^\s{0,3}#\s+(.+)$", raw, flags=re.M)
    return m.group(1).strip() if m else ""


def parse_document(content: bytes | str, mime: Optional[str] = None,
                   source_uri: str = "") -> ParsedDocument:
    """Единая точка парсинга: mime (или эвристика по source_uri) → текст."""
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
    guessed = (mime or "").lower().split(";")[0].strip()
    if not guessed:
        low = source_uri.lower()
        if low.endswith((".html", ".htm", ".xhtml")):
            guessed = "text/html"
        elif low.endswith((".md", ".markdown")):
            guessed = "text/markdown"
        else:
            guessed = "text/plain"
    if guessed == "text/html" or text.lstrip()[:1] == "<":
        return parse_html(text)
    if guessed == "text/markdown":
        return parse_markdown(text)
    return ParsedDocument(text=normalize_whitespace(text), title="", mime=guessed)
