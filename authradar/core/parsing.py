"""Pure HTML parsing into typed models.

Uses BeautifulSoup with the standard-library ``html.parser`` backend (no extra
native dependency). All functions are pure: given HTML text they return
immutable models, performing no network I/O. Input HTML is untrusted and may be
malformed or hostile, so extraction is defensive and never raises.
"""

from __future__ import annotations

from urllib.parse import urldefrag, urljoin, urlsplit

from bs4 import BeautifulSoup, Tag
from pydantic import BaseModel, ConfigDict

_MAX_INLINE_SCRIPTS = 100
_MAX_INLINE_SCRIPT_CHARS = 200_000
_WEB_SCHEMES = frozenset({"http", "https"})


class FormInput(BaseModel):
    """A single ``<input>``/``<select>``/``<textarea>`` control in a form."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    type: str = "text"
    value: str = ""
    required: bool = False
    autocomplete: str | None = None
    max_length: int | None = None


class HtmlForm(BaseModel):
    """A parsed HTML ``<form>`` with its controls and resolved action URL."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    method: str = "get"
    inputs: tuple[FormInput, ...] = ()
    form_id: str | None = None
    name: str | None = None
    source_url: str = ""

    @property
    def input_names(self) -> tuple[str, ...]:
        """Lower-cased names of all controls."""
        return tuple(i.name.lower() for i in self.inputs)

    @property
    def has_password(self) -> bool:
        """Whether the form contains a password control."""
        return any(i.type.lower() == "password" for i in self.inputs)

    def input_by_type(self, input_type: str) -> FormInput | None:
        """Return the first control of ``input_type`` (case-insensitive)."""
        lowered = input_type.lower()
        return next((i for i in self.inputs if i.type.lower() == lowered), None)

    def get_input(self, name: str) -> FormInput | None:
        """Return the control whose name matches ``name`` (case-insensitive)."""
        lowered = name.lower()
        return next((i for i in self.inputs if i.name.lower() == lowered), None)


class ParsedPage(BaseModel):
    """The structural extract of a single HTML page."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    title: str | None = None
    forms: tuple[HtmlForm, ...] = ()
    links: tuple[str, ...] = ()
    script_srcs: tuple[str, ...] = ()
    inline_scripts: tuple[str, ...] = ()
    meta: dict[str, str] = {}


def _attr(tag: Tag, name: str) -> str | None:
    """Return a single string attribute value, coercing multi-valued ones."""
    raw = tag.get(name)
    if raw is None:
        return None
    if isinstance(raw, list):
        return " ".join(raw) if raw else None
    return str(raw)


def _int_attr(tag: Tag, name: str) -> int | None:
    value = _attr(tag, name)
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _normalise_link(base_url: str, href: str) -> str | None:
    """Resolve ``href`` against ``base_url`` and keep only web URLs."""
    href = href.strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absolute = urljoin(base_url, href)
    defragged, _ = urldefrag(absolute)
    if urlsplit(defragged).scheme not in _WEB_SCHEMES:
        return None
    return defragged


def _extract_inputs(form: Tag) -> tuple[FormInput, ...]:
    inputs: list[FormInput] = []
    for control in form.find_all(["input", "select", "textarea"]):
        if not isinstance(control, Tag):
            continue
        name = _attr(control, "name")
        if not name:
            continue
        if control.name == "input":
            control_type = (_attr(control, "type") or "text").lower()
        elif control.name == "select":
            control_type = "select"
        else:
            control_type = "textarea"
        inputs.append(
            FormInput(
                name=name,
                type=control_type,
                value=_attr(control, "value") or "",
                required=control.has_attr("required"),
                autocomplete=_attr(control, "autocomplete"),
                max_length=_int_attr(control, "maxlength"),
            )
        )
    return tuple(inputs)


def _extract_forms(base_url: str, soup: BeautifulSoup) -> tuple[HtmlForm, ...]:
    forms: list[HtmlForm] = []
    for form in soup.find_all("form"):
        if not isinstance(form, Tag):
            continue
        action_attr = _attr(form, "action")
        action = urljoin(base_url, action_attr) if action_attr else base_url
        method = (_attr(form, "method") or "get").strip().lower()
        forms.append(
            HtmlForm(
                action=action,
                method=method if method in {"get", "post"} else "get",
                inputs=_extract_inputs(form),
                form_id=_attr(form, "id"),
                name=_attr(form, "name"),
                source_url=base_url,
            )
        )
    return tuple(forms)


def _extract_links(base_url: str, soup: BeautifulSoup) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for anchor in soup.find_all("a"):
        if not isinstance(anchor, Tag):
            continue
        href = _attr(anchor, "href")
        if href is None:
            continue
        link = _normalise_link(base_url, href)
        if link is not None:
            seen.setdefault(link, None)
    return tuple(seen)


def _extract_scripts(base_url: str, soup: BeautifulSoup) -> tuple[tuple[str, ...], tuple[str, ...]]:
    srcs: list[str] = []
    inline: list[str] = []
    for script in soup.find_all("script"):
        if not isinstance(script, Tag):
            continue
        src = _attr(script, "src")
        if src:
            srcs.append(urljoin(base_url, src))
        elif len(inline) < _MAX_INLINE_SCRIPTS:
            text = script.get_text()
            if text.strip():
                inline.append(text[:_MAX_INLINE_SCRIPT_CHARS])
    return tuple(srcs), tuple(inline)


def _extract_meta(soup: BeautifulSoup) -> dict[str, str]:
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        if not isinstance(tag, Tag):
            continue
        key = _attr(tag, "name") or _attr(tag, "property") or _attr(tag, "http-equiv")
        content = _attr(tag, "content")
        if key and content is not None:
            meta[key.lower()] = content
    return meta


def parse_html(url: str, html: str) -> ParsedPage:
    """Parse an HTML document into a :class:`ParsedPage`."""
    soup = BeautifulSoup(html or "", "html.parser")
    title_tag = soup.find("title")
    title = title_tag.get_text().strip() if isinstance(title_tag, Tag) else None
    script_srcs, inline_scripts = _extract_scripts(url, soup)
    return ParsedPage(
        url=url,
        title=title or None,
        forms=_extract_forms(url, soup),
        links=_extract_links(url, soup),
        script_srcs=script_srcs,
        inline_scripts=inline_scripts,
        meta=_extract_meta(soup),
    )
