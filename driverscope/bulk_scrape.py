"""Bulk driver harvesting from vendor download portals via Playwright."""

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from playwright.async_api import async_playwright, Error as PWError
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    PWError = Exception

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


@dataclass
class VendorTarget:
    name: str
    url: str
    region: str = "global"
    category: str = "general"
    download_selector: Optional[str] = None
    follow_pattern: Optional[str] = None
    extract_sys: bool = True
    notes: str = ""


VENDOR_TARGETS: list[VendorTarget] = [
    # ===== Taiwan (TW) =====
    VendorTarget(name="MSI-Support",      url="https://www.msi.com/support",
                 region="TW", category="motherboard",
                 notes="MSI motherboard/GPU drivers"),
    VendorTarget(name="ASRock-Support",   url="https://www.asrock.com/support/download.asp",
                 region="TW", category="motherboard"),
    VendorTarget(name="Gigabyte-Support", url="https://www.gigabyte.com/Support",
                 region="TW", category="motherboard"),
    VendorTarget(name="Asus-Support",     url="https://www.asus.com/support/",
                 region="TW", category="motherboard"),
    VendorTarget(name="Acer-Support",     url="https://www.acer.com/us-en/support",
                 region="TW", category="laptop"),
    VendorTarget(name="Biostar",          url="https://www.biostar.com.tw/app/en/support_download.php",
                 region="TW", category="motherboard"),
    VendorTarget(name="ECS-Elitegroup",   url="https://www.ecs.com.tw/en/Support/Download",
                 region="TW", category="motherboard"),
    VendorTarget(name="Realtek-Audio",    url="https://www.realtek.com/en/component/zoo/category/pc-audio-codecs-high-definition-audio-codecs-software",
                 region="TW", category="audio"),
    VendorTarget(name="Foxconn-TW",       url="https://www.foxconn.com/en-us/support",
                 region="TW", category="motherboard"),
    VendorTarget(name="PowerColor",       url="https://www.powercolor.com/downloads",
                 region="TW", category="gpu"),

    # ===== Hong Kong (HK) =====
    VendorTarget(name="ZOTAC",            url="https://www.zotac.com/us/support",
                 region="HK", category="gpu"),
    VendorTarget(name="Sapphire",         url="https://www.sapphiretech.com/en/consumer/support",
                 region="HK", category="gpu"),

    # ===== China (CN) =====
    VendorTarget(name="Lenovo-Support",   url="https://support.lenovo.com/us/en",
                 region="CN", category="laptop"),
    VendorTarget(name="Huawei-Consumer",  url="https://consumer.huawei.com/en/support/",
                 region="CN", category="laptop"),
    VendorTarget(name="Xiaomi-Global",    url="https://www.mi.com/global/support",
                 region="CN", category="laptop"),
    VendorTarget(name="Colorful",         url="https://www.colorful.cn/Support/index.html",
                 region="CN", category="gpu"),
    VendorTarget(name="Yeston",           url="https://www.yeston.net/service/download",
                 region="CN", category="gpu"),
    VendorTarget(name="Galax-Global",     url="https://www.galax.com/en/support/",
                 region="CN", category="gpu"),
    VendorTarget(name="Onda",             url="https://www.onda.cn/Service/Download",
                 region="CN", category="motherboard"),
    VendorTarget(name="Foxconn-CN",       url="https://www.foxconn.com.cn/",
                 region="CN", category="motherboard"),
    VendorTarget(name="ZTE",              url="https://www.ztedevices.com/en/support/",
                 region="CN", category="mobile"),
    VendorTarget(name="MAXSUN",           url="http://www.maxsun.com.cn/service/download",
                 region="CN", category="gpu"),

    # ===== Korea (KR) =====
    VendorTarget(name="Samsung-Support",  url="https://www.samsung.com/sec/support/",
                 region="KR", category="laptop"),
    VendorTarget(name="LG-Support",       url="https://www.lg.com/kr/support",
                 region="KR", category="laptop"),
    VendorTarget(name="GIGABYTE-KR",      url="https://www.gigabyte.com/kr/Support",
                 region="KR", category="motherboard"),

    # ===== Japan (JP) =====
    VendorTarget(name="Buffalo-JP",       url="https://www.buffalo.jp/support/download/",
                 region="JP", category="peripheral"),
    VendorTarget(name="IO-Data",          url="https://www.iodata.jp/lib/",
                 region="JP", category="peripheral"),
    VendorTarget(name="Elecom",           url="https://www.elecom.co.jp/support/list/",
                 region="JP", category="peripheral"),
    VendorTarget(name="Logitec-JP",       url="https://www.logitec.co.jp/support/",
                 region="JP", category="peripheral",
                 notes="Japanese Logitec, not US Logitech"),
    VendorTarget(name="Sony-Support",     url="https://www.sony.jp/support/",
                 region="JP", category="laptop"),
    VendorTarget(name="NEC-JP",           url="https://121ware.com/support/",
                 region="JP", category="laptop"),
    VendorTarget(name="Panasonic-JP",     url="https://faq.panasonic.jp/app/home",
                 region="JP", category="laptop"),

    # ===== Russia (RU) =====
    VendorTarget(name="DriverPack-RU",    url="https://drp.su/en",
                 region="RU", category="driver-aggregator",
                 notes="DriverPack Solution: huge driver index"),
    VendorTarget(name="Driver-RU",        url="https://driver.ru/",
                 region="RU", category="driver-aggregator"),
    VendorTarget(name="Drp-Catalog",      url="https://catalog.drp.su/",
                 region="RU", category="driver-aggregator",
                 notes="DRP catalog with per-vendor archives"),
    VendorTarget(name="4PDA-Files",       url="https://4pda.to/forum/index.php?showforum=219",
                 region="RU", category="driver-community"),
    VendorTarget(name="Yandex-Drivers",   url="https://yandex.com/search/?text=driver+download+site%3Adriver.ru",
                 region="RU", category="driver-search"),

    # ===== Germany / EU =====
    VendorTarget(name="BeQuiet",          url="https://www.bequiet.com/en/support",
                 region="DE", category="psu-cooling"),
    VendorTarget(name="Endorfy",          url="https://endorfy.com/support",
                 region="DE", category="psu-cooling"),
    VendorTarget(name="Fujitsu-EU",      url="https://support.ts.fujitsu.com/",
                 region="DE", category="laptop"),
    VendorTarget(name="Medion-DE",        url="https://www.medion.com/de/service/start/",
                 region="DE", category="laptop"),

    # ===== United States (US) =====
    VendorTarget(name="EVGA",             url="https://www.evga.com/support/download/",
                 region="US", category="gpu"),
    VendorTarget(name="XFX",              url="https://www.xfxforce.com/support",
                 region="US", category="gpu"),
    VendorTarget(name="Dell-Support",     url="https://www.dell.com/support/home/",
                 region="US", category="laptop"),
    VendorTarget(name="HP-Support",       url="https://support.hp.com/us-en/drivers",
                 region="US", category="laptop"),
    VendorTarget(name="Intel-DSA",        url="https://www.intel.com/content/www/us/en/download-center/home.html",
                 region="US", category="chipset"),
    VendorTarget(name="AMD-Drivers",      url="https://www.amd.com/en/support",
                 region="US", category="gpu"),
    VendorTarget(name="Nvidia-Drivers",   url="https://www.nvidia.com/Download/index.aspx",
                 region="US", category="gpu"),

    # ===== India / SEA =====
    VendorTarget(name="Iball",            url="https://www.iball.co.in/Category/Drivers",
                 region="IN", category="peripheral"),

    # ===== Multi-vendor archives / catalogs =====
    VendorTarget(name="Station-Drivers",  url="https://www.station-drivers.com/index.php?option=com_remository&Itemid=353&func=select&id=72&lang=en",
                 region="global", category="driver-aggregator",
                 notes="Multi-vendor chipset/system driver archive"),
    VendorTarget(name="Catalog-Update",   url="https://www.catalog.update.microsoft.com/Search.aspx?q=driver",
                 region="global", category="signed-redist",
                 notes="MS Update Catalog: signed-driver redistributables"),
    VendorTarget(name="DriverGuide",      url="https://www.driverguide.com/driver/sub_directory/000.html",
                 region="global", category="driver-aggregator"),
    VendorTarget(name="TechSpot-Drivers", url="https://www.techspot.com/drivers/",
                 region="global", category="driver-aggregator"),
    VendorTarget(name="CNET-Drivers",     url="https://download.cnet.com/drivers/",
                 region="global", category="driver-aggregator"),
    VendorTarget(name="MajorGeeks",       url="https://www.majorgeeks.com/files/categories.html",
                 region="global", category="driver-aggregator"),
]


REGIONS = sorted({t.region for t in VENDOR_TARGETS})
CATEGORIES = sorted({t.category for t in VENDOR_TARGETS})


@dataclass
class ScrapeResult:
    vendor: str
    page_urls: list[str] = field(default_factory=list)
    download_urls: list[str] = field(default_factory=list)
    saved_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def _scrape_one(browser, target: VendorTarget, output_dir: Path,
                      max_pages: int = 5) -> ScrapeResult:
    result = ScrapeResult(vendor=target.name)
    page = await browser.new_page()
    page.set_default_timeout(20000)

    try:
        await page.goto(target.url, wait_until="domcontentloaded")
    except PWError as e:
        result.errors.append(f"goto failed: {e}")
        await page.close()
        return result

    visited = set()
    queue = [target.url]
    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            if url != target.url:
                await page.goto(url, wait_until="domcontentloaded")
        except PWError as e:
            result.errors.append(f"goto {url[:60]}: {e}")
            continue

        anchors = await page.eval_on_selector_all(
            "a[href]", "els => els.map(a => a.href)"
        )

        for href in anchors:
            if not href:
                continue
            if re.search(r"\.(exe|zip|cab|msi|7z)(\?|$)", href, re.I):
                if href not in result.download_urls:
                    result.download_urls.append(href)
            elif target.follow_pattern and re.search(target.follow_pattern, href):
                if href not in visited and href not in queue:
                    queue.append(href)
        result.page_urls.append(url)

    await page.close()
    return result


async def _download_one(client, url: str, output_dir: Path,
                        max_bytes: int = 200_000_000) -> Optional[Path]:
    fname = re.sub(r"[^\w.\-]+", "_", url.split("/")[-1].split("?")[0])
    if not fname or len(fname) > 200:
        fname = "download.bin"
    dest = output_dir / fname
    if dest.exists():
        return dest
    try:
        async with client.stream("GET", url, timeout=60.0, follow_redirects=True) as r:
            if r.status_code >= 400:
                return None
            with open(dest, "wb") as f:
                total = 0
                async for chunk in r.aiter_bytes(64_000):
                    total += len(chunk)
                    if total > max_bytes:
                        dest.unlink(missing_ok=True)
                        return None
                    f.write(chunk)
        return dest
    except Exception:
        return None


async def _download_results(results: list[ScrapeResult], output_dir: Path,
                            concurrency: int = 4):
    if not HAS_HTTPX:
        return
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient() as client:
        async def bounded(url, result):
            async with sem:
                dest = await _download_one(client, url, output_dir)
                if dest:
                    result.saved_files.append(dest)
        tasks = []
        for r in results:
            vendor_dir = output_dir / r.vendor
            vendor_dir.mkdir(parents=True, exist_ok=True)
            for url in r.download_urls[:25]:
                tasks.append(bounded(url, r))
        await asyncio.gather(*tasks)


async def _bulk_scrape_async(targets: list[VendorTarget], output_dir: Path,
                             max_pages_per_vendor: int, concurrency: int):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        sem = asyncio.Semaphore(concurrency)

        async def bounded(t):
            async with sem:
                return await _scrape_one(browser, t, output_dir, max_pages_per_vendor)

        results = await asyncio.gather(*[bounded(t) for t in targets])
        await browser.close()

    await _download_results(results, output_dir)
    return results


def bulk_scrape(vendors: Optional[list[str]] = None,
                category: Optional[str] = None,
                region: Optional[str] = None,
                output_dir: str = "./bulk_harvest",
                max_pages_per_vendor: int = 5,
                concurrency: int = 4) -> list[ScrapeResult]:
    if not HAS_PLAYWRIGHT:
        raise RuntimeError("pip install driverscope[bulk]  (playwright + httpx)")
    if not HAS_HTTPX:
        raise RuntimeError("pip install driverscope[bulk]  (playwright + httpx)")

    targets = VENDOR_TARGETS
    if vendors:
        names = {v.lower() for v in vendors}
        targets = [t for t in targets if t.name.lower() in names]
    if category:
        cats = {c.lower() for c in category.split(",")}
        targets = [t for t in targets if t.category.lower() in cats]
    if region:
        regions = {r.lower() for r in region.split(",")}
        targets = [t for t in targets if t.region.lower() in regions]

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    return asyncio.run(_bulk_scrape_async(targets, out, max_pages_per_vendor, concurrency))


def list_vendors() -> list[VendorTarget]:
    return list(VENDOR_TARGETS)
