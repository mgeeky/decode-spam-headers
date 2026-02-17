from __future__ import annotations

import logging
import sys
from html import escape
from typing import Any, Callable


class Logger:
    colors_map = {
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "magenta": 35,
        "cyan": 36,
        "white": 37,
        "grey": 38,
    }

    html_colors_map = {
        "background": "rgb(40, 44, 52)",
        "grey": "rgb(132, 139, 149)",
        "cyan": "rgb(86, 182, 194)",
        "blue": "rgb(97, 175, 239)",
        "red": "rgb(224, 108, 117)",
        "magenta": "rgb(198, 120, 221)",
        "yellow": "rgb(229, 192, 123)",
        "white": "rgb(220, 223, 228)",
        "green": "rgb(108, 135, 94)",
    }

    colors_dict = {
        "error": colors_map["red"],
        "info": colors_map["green"],
        "info ": colors_map["green"],
        "debug": colors_map["grey"],
        "other": colors_map["grey"],
    }

    default_options: dict[str, Any] = {
        "debug": False,
        "verbose": False,
        "nocolor": False,
        "log": sys.stderr,
        "format": "text",
    }

    def __init__(self, opts: dict[str, Any] | None = None, name: str = "engine"):
        self.options = dict(Logger.default_options)
        if opts:
            self.options.update(opts)

        logger_name = f"web_header_analyzer.{name}.{id(self)}"
        self._logger = logging.getLogger(logger_name)
        self._logger.propagate = False
        self._configure_logger()

    def _configure_logger(self) -> None:
        self._logger.handlers.clear()
        handler = self._build_handler(self.options.get("log"))
        if handler is None:
            handler = logging.NullHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        if hasattr(handler, "terminator"):
            handler.terminator = ""
        self._logger.addHandler(handler)
        level = logging.DEBUG if self.options.get("debug") else logging.INFO
        self._logger.setLevel(level)

    @staticmethod
    def _build_handler(target: Any) -> logging.Handler | None:
        if target is None or target == "none":
            return None
        if isinstance(target, str):
            return logging.FileHandler(target, encoding="utf-8")
        if hasattr(target, "write"):
            return logging.StreamHandler(target)
        return logging.StreamHandler(sys.stderr)

    @staticmethod
    def with_color(c: int, s: str) -> str:
        return f"__COLOR_{c}__|{s}|__END_COLOR__"

    @staticmethod
    def replaceColors(s: str, colorizingFunc: Callable[[int, str], str]) -> str:
        pos = 0

        while pos < len(s):
            if s[pos:].startswith("__COLOR_"):
                pos += len("__COLOR_")
                pos1 = s[pos:].find("__|")

                if pos1 == -1:
                    raise ValueError(
                        "Output colors mismatch - could not find pos of end of "
                        "color number!"
                    )

                c = int(s[pos : pos + pos1])
                pos += pos1 + len("__|")
                pos2 = s[pos:].find("|__END_COLOR__")

                if pos2 == -1:
                    raise ValueError(
                        "Output colors mismatch - could not find end of color marker!"
                    )

                txt = s[pos : pos + pos2]
                pos += pos2 + len("|__END_COLOR__")

                patt = f"__COLOR_{c}__|{txt}|__END_COLOR__"

                colored = colorizingFunc(c, txt)

                if not colored:
                    raise ValueError(
                        f"Could not strip colors from phrase: ({patt})!"
                    )

                s = s.replace(patt, colored)
                pos = 0
                continue

            pos += 1

        return s

    @staticmethod
    def noColors(s: str) -> str:
        return Logger.replaceColors(s, lambda _c, txt: txt)

    @staticmethod
    def ansiColors(s: str) -> str:
        return Logger.replaceColors(s, lambda c, txt: f"\x1b[{c}m{txt}\x1b[0m")

    @staticmethod
    def htmlColors(s: str) -> str:
        def get_col(c: int, txt: str) -> str:
            text = escape(txt)

            for k, v in Logger.colors_map.items():
                if v == c:
                    return f'<font class="text-{k}">{text}</font>'

            return text

        return Logger.replaceColors(s, get_col)

    def colored(self, txt: str, col: str) -> str:
        if self.options["nocolor"]:
            return txt
        return Logger.with_color(Logger.colors_map[col], txt)

    def _level_for_mode(self, mode: str) -> int:
        normalized = mode.strip().lower()
        if normalized == "debug":
            return logging.DEBUG
        if normalized == "error":
            return logging.ERROR
        return logging.INFO

    def _emit(self, txt: Any, mode: str, **kwargs: Any) -> None:
        if txt is None:
            return

        args = {
            "color": None,
            "noprefix": False,
            "newline": True,
            "nocolor": self.options["nocolor"],
        }
        args.update(kwargs)

        if not isinstance(txt, str):
            txt = str(txt)
        txt = txt.replace("\t", " " * 4)

        if args["nocolor"]:
            col = None
        elif args["color"]:
            col = args["color"]
            if isinstance(col, str):
                col = Logger.colors_map.get(col, Logger.colors_map["grey"])
        else:
            col = Logger.colors_dict.get(mode, Logger.colors_map["grey"])

        prefix = ""
        if mode:
            mode_tag = f"[{mode}] "
            if not args["noprefix"]:
                if args["nocolor"]:
                    prefix = mode_tag.upper()
                else:
                    prefix = Logger.with_color(
                        Logger.colors_dict["other"], mode_tag.upper()
                    )

        if args["nocolor"] or col is None:
            to_write = prefix + txt
        else:
            to_write = prefix + Logger.with_color(col, txt)

        if args["newline"]:
            to_write += "\n"

        if args["nocolor"]:
            to_write = Logger.noColors(to_write)
        else:
            to_write = Logger.ansiColors(to_write)

        self._logger.log(self._level_for_mode(mode), to_write)

    @staticmethod
    def out(txt: Any, fd: Any, mode: str = "info", **kwargs: Any) -> None:
        temp = Logger({"log": fd, "nocolor": kwargs.get("nocolor", False)})
        temp._emit(txt, mode, **kwargs)

    def info(self, txt: Any, forced: bool = False, **kwargs: Any) -> None:
        if forced or self.options["verbose"] or self.options["debug"]:
            self._emit(txt, "info", **kwargs)
            return
        log_target = self.options.get("log")
        if isinstance(log_target, str) and log_target != "none":
            self._emit(txt, "info", **kwargs)

    def text(self, txt: Any, **kwargs: Any) -> None:
        kwargs["noprefix"] = True
        self._emit(txt, "", **kwargs)

    def dbg(self, txt: Any, **kwargs: Any) -> None:
        if not self.options["debug"]:
            return
        if self.options.get("format") == "html":
            txt = f"<!-- {txt} -->"
        self._emit(txt, "debug", **kwargs)

    def err(self, txt: Any, **kwargs: Any) -> None:
        self._emit(txt, "error", **kwargs)

    def fatal(self, txt: Any, **kwargs: Any) -> None:
        self._emit(txt, "error", **kwargs)
        raise SystemExit(1)


logger = Logger()
