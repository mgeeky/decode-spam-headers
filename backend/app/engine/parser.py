from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ParsedHeader:
    index: int
    name: str
    value: str


class HeaderParser:
    _headers_known_for_breaking_line: set[str] = {
        "Received",
        "Authentication-Results",
        "Received-SPF",
        "DKIM-Signature",
        "X-Google-DKIM-Signature",
        "X-GM-Message-State",
        "Subject",
        "X-MS-Exchange-Organization-ExpirationStartTime",
        "X-MS-Exchange-Organization-Network-Message-Id",
        "X-Forefront-Antispam-Report",
        "X-MS-Exchange-CrossTenant-OriginalArrivalTime",
        "X-Microsoft-Antispam-Mailbox-Delivery",
        "X-Microsoft-Antispam-Message-Info",
    }

    def parse(self, raw_text: str) -> list[ParsedHeader]:
        num = 0
        lines = raw_text.splitlines()
        boundary = ""
        in_boundary = False
        headers: list[ParsedHeader] = []

        i = 0
        while i < len(lines):
            line = lines[i].rstrip("\r")

            if boundary and f"--{boundary}" == line.strip():
                in_boundary = True
                i += 1
                continue

            if in_boundary and f"--{boundary}--" == line.strip():
                in_boundary = False
                i += 1
                continue

            if in_boundary:
                i += 1
                continue

            if line.startswith(" ") or line.startswith("\t"):
                if headers:
                    headers[-1].value += "\n" + line
                i += 1
                continue

            stripped = line.strip()
            if not stripped:
                i += 1
                continue

            match = re.match(r"^([^:]+)\s*:\s+(.+)\s*$", stripped, re.S)

            if match:
                headers.append(ParsedHeader(num, match.group(1), match.group(2)))
                num += 1
            else:
                match = re.match(r"^([^:]+)\s*:\s*$", stripped, re.S)

                if match:
                    header_name = match.group(1)
                    consider_next = header_name in self._headers_known_for_breaking_line
                    j = 1
                    value_lines: list[str] = []

                    if i + 1 < len(lines) and (
                        lines[i + 1].startswith(" ")
                        or lines[i + 1].startswith("\t")
                        or consider_next
                    ):
                        while i + j < len(lines):
                            current_line = lines[i + j].rstrip("\r")

                            if (
                                current_line.startswith(" ")
                                or current_line.startswith("\t")
                                or consider_next
                            ):
                                value_lines.append(current_line)
                                j += 1
                                consider_next = False
                            else:
                                break

                    value = "\n".join(value_lines).strip()
                    headers.append(ParsedHeader(num, header_name, value))
                    num += 1

                    if j > 1:
                        i += j - 1

            if headers and headers[-1].name.lower() == "content-type":
                boundary_match = re.search(
                    r'boundary="([^"]+)"', headers[-1].value, re.I
                )
                if boundary_match:
                    boundary = boundary_match.group(1)

            i += 1

        return headers
