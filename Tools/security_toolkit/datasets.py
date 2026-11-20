"""Small curated reference tables used by tools 061, 065 and 077.

These are lifecycle and naming facts, not vulnerability intelligence. Each row names its source.
They are a snapshot (``DATA_AS_OF``) and must be refreshed; tools report "end of support according
to the bundled table dated DATA_AS_OF", never "vulnerable".
"""
from __future__ import annotations

import re

DATA_AS_OF = "2026-11-10"

MS_LIFECYCLE = "https://learn.microsoft.com/lifecycle/"
ENDOFLIFE = "https://endoflife.date/"

# (id, product label, name regex, version regex applied to "name version" (group 1 = comparable version or None),
#  versions -> end-of-support date, source)
SOFTWARE_EOL = [
    ("python", "Python", r"^python\s", r"(\d+\.\d+)", {"2.7": "2020-01-01", "3.6": "2021-12-23", "3.7": "2023-06-27",
                                                        "3.8": "2024-10-07", "3.9": "2025-10-31"}, ENDOFLIFE + "python"),
    ("nodejs", "Node.js", r"^node\.?js\b", r"\b(\d+)\.\d+", {"12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11",
                                                            "18": "2025-04-30", "20": "2026-04-30"}, ENDOFLIFE + "nodejs"),
    ("php", "PHP", r"^php\b", r"(\d+\.\d+)", {"5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30",
                                              "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31"},
     ENDOFLIFE + "php"),
    ("openssl", "OpenSSL", r"^(?:win(?:32|64) )?openssl", r"\b(1\.0\.\d|1\.1\.[01]|3\.1)", {"1.0.2": "2019-12-31", "1.1.0": "2019-09-11",
                                                                                         "1.1.1": "2023-09-11", "3.1": "2025-03-14"},
     ENDOFLIFE + "openssl"),
    ("dotnet", ".NET runtime", r"^microsoft (?:\.net|asp\.net core|windows desktop) (?:runtime|core)", r"\b(\d+)\.\d+\.\d+",
     {"3": "2022-12-13", "5": "2022-05-10", "6": "2024-11-12", "7": "2024-05-14"}, MS_LIFECYCLE + "products/microsoft-net-and-net-core"),
    ("office2010", "Microsoft Office 2010", r"^microsoft office .*2010", None, {"*": "2020-10-13"}, MS_LIFECYCLE + "products/microsoft-office-2010"),
    ("office2013", "Microsoft Office 2013", r"^microsoft office .*2013", None, {"*": "2023-04-11"}, MS_LIFECYCLE + "products/microsoft-office-2013"),
    ("office2016", "Microsoft Office 2016", r"^microsoft office .*2016", None, {"*": "2025-10-14"}, MS_LIFECYCLE + "products/microsoft-office-2016"),
    ("office2019", "Microsoft Office 2019", r"^microsoft office .*2019", None, {"*": "2025-10-14"}, MS_LIFECYCLE + "products/office-2019"),
    ("flash", "Adobe Flash Player", r"^adobe flash player", None, {"*": "2020-12-31"}, "https://www.adobe.com/products/flashplayer/end-of-life.html"),
    ("silverlight", "Microsoft Silverlight", r"^microsoft silverlight", None, {"*": "2021-10-12"}, MS_LIFECYCLE + "products/silverlight-5"),
    ("quicktime", "QuickTime for Windows", r"^quicktime", None, {"*": "2016-01-01"}, "https://support.apple.com/HT205771"),
    ("reader-xi", "Adobe Reader XI", r"^adobe reader xi\b", None, {"*": "2017-10-15"}, "https://helpx.adobe.com/support/programs/eol-matrix.html"),
    ("acrobat2017", "Adobe Acrobat 2017", r"^adobe acrobat (?:reader )?2017\b", None, {"*": "2022-06-06"}, "https://helpx.adobe.com/support/programs/eol-matrix.html"),
    ("sql2012", "SQL Server 2012", r"^microsoft sql server 2012", None, {"*": "2022-07-12"}, MS_LIFECYCLE + "products/microsoft-sql-server-2012"),
    ("sql2014", "SQL Server 2014", r"^microsoft sql server 2014", None, {"*": "2024-07-09"}, MS_LIFECYCLE + "products/sql-server-2014"),
]

# Remote-access and remote-control tools: legitimate, but often abused (T1219); reported for awareness.
REMOTE_ACCESS = re.compile(r"(?i)^(?:teamviewer|anydesk|rustdesk|splashtop|screenconnect|connectwise control|logmein|"
                           r"ammyy|ultraviewer|supremo|radmin|tightvnc|ultravnc|realvnc|vnc server|atera|netsupport)")

# Windows client/server builds -> (label, Home/Pro end, Enterprise/Education/LTSC/Server end). Source: Microsoft lifecycle.
WINDOWS_BUILDS = {
    7601: ("Windows 7 / Server 2008 R2", "2020-01-14", "2020-01-14"),
    9600: ("Windows 8.1 / Server 2012 R2", "2023-01-10", "2023-10-10"),
    10240: ("Windows 10 1507 (LTSB 2015)", "2017-05-09", "2025-10-14"),
    14393: ("Windows 10 1607 / LTSB 2016 / Server 2016", "2018-04-10", "2027-01-12"),
    17763: ("Windows 10 1809 / LTSC 2019 / Server 2019", "2020-11-10", "2029-01-09"),
    19041: ("Windows 10 2004", "2021-12-14", "2021-12-14"),
    19042: ("Windows 10 20H2", "2022-05-10", "2023-05-09"),
    19043: ("Windows 10 21H1", "2022-12-13", "2022-12-13"),
    19044: ("Windows 10 21H2 / LTSC 2021", "2023-06-13", "2027-01-12"),
    19045: ("Windows 10 22H2", "2025-10-14", "2025-10-14"),
    20348: ("Windows Server 2022", "2031-10-14", "2031-10-14"),
    22000: ("Windows 11 21H2", "2023-10-10", "2024-10-08"),
    22621: ("Windows 11 22H2", "2024-10-08", "2025-10-14"),
    22631: ("Windows 11 23H2", "2025-11-11", "2026-11-10"),
    26100: ("Windows 11 24H2 / Server 2025", "2026-10-13", "2027-10-12"),
    26200: ("Windows 11 25H2", "2027-10-12", "2028-10-10"),
}

# Linux distributions: (os-release ID, VERSION_ID prefix) -> (label, end of standard/LTS security support, source)
LINUX_RELEASES = {
    ("ubuntu", "16.04"): ("Ubuntu 16.04 LTS", "2021-04-30", "https://ubuntu.com/about/release-cycle"),
    ("ubuntu", "18.04"): ("Ubuntu 18.04 LTS", "2023-05-31", "https://ubuntu.com/about/release-cycle"),
    ("ubuntu", "20.04"): ("Ubuntu 20.04 LTS", "2025-05-31", "https://ubuntu.com/about/release-cycle"),
    ("ubuntu", "22.04"): ("Ubuntu 22.04 LTS", "2027-06-01", "https://ubuntu.com/about/release-cycle"),
    ("ubuntu", "24.04"): ("Ubuntu 24.04 LTS", "2029-05-31", "https://ubuntu.com/about/release-cycle"),
    ("debian", "9"): ("Debian 9", "2022-06-30", "https://wiki.debian.org/LTS"),
    ("debian", "10"): ("Debian 10", "2024-06-30", "https://wiki.debian.org/LTS"),
    ("debian", "11"): ("Debian 11", "2026-08-31", "https://wiki.debian.org/LTS"),
    ("debian", "12"): ("Debian 12", "2028-06-30", "https://wiki.debian.org/LTS"),
    ("centos", "7"): ("CentOS 7", "2024-06-30", ENDOFLIFE + "centos"),
    ("centos", "8"): ("CentOS 8", "2021-12-31", ENDOFLIFE + "centos"),
    ("rhel", "7"): ("RHEL 7 (maintenance)", "2024-06-30", ENDOFLIFE + "rhel"),
}

# Cookie names set by widely deployed analytics/advertising scripts (vendor documentation). Prefix match on "*".
TRACKER_COOKIES = {
    "_ga": "Google Analytics", "_ga_*": "Google Analytics 4", "_gid": "Google Analytics", "_gat*": "Google Analytics",
    "__utma": "Google Analytics (legacy)", "__utmb": "Google Analytics (legacy)", "__utmz": "Google Analytics (legacy)",
    "_gcl_au": "Google Ads conversion linker", "_gcl_aw": "Google Ads", "IDE": "Google DoubleClick", "test_cookie": "Google DoubleClick",
    "NID": "Google", "_fbp": "Meta (Facebook) Pixel", "fr": "Meta (Facebook)", "_fbc": "Meta (Facebook)",
    "_uetsid": "Microsoft Advertising (Bing UET)", "_uetvid": "Microsoft Advertising (Bing UET)", "MUID": "Microsoft",
    "_clck": "Microsoft Clarity", "_clsk": "Microsoft Clarity", "_hjid": "Hotjar", "_hjSessionUser_*": "Hotjar",
    "_hjSession_*": "Hotjar", "ajs_anonymous_id": "Segment", "ajs_user_id": "Segment", "mp_*": "Mixpanel",
    "amplitude_id*": "Amplitude", "AMP_*": "Amplitude", "_pin_unauth": "Pinterest", "_tt_enable_cookie": "TikTok",
    "_ttp": "TikTok", "li_sugr": "LinkedIn", "bcookie": "LinkedIn", "UserMatchHistory": "LinkedIn", "personalization_id": "X (Twitter)",
    "_scid": "Snap", "__hstc": "HubSpot", "hubspotutk": "HubSpot", "_mkto_trk": "Marketo", "__qca": "Quantcast",
    "_parsely_visitor": "Parse.ly", "optimizelyEndUserId": "Optimizely", "_vwo_uuid*": "VWO", "_pk_id*": "Matomo",
    "_pk_ses*": "Matomo", "intercom-id-*": "Intercom", "_rdt_uuid": "Reddit",
}


def tracker_vendor(name: str) -> str | None:
    if name in TRACKER_COOKIES:
        return TRACKER_COOKIES[name]
    for pattern, vendor in TRACKER_COOKIES.items():
        if pattern.endswith("*") and name.startswith(pattern[:-1]):
            return vendor
    return None
