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
    VendorTarget(
        name="Station-Drivers",
        url="https://www.station-drivers.com/index.php?option=com_remository&Itemid=353&func=select&id=72&lang=en",
        category="chipset",
        notes="Multi-vendor chipset/system driver archive",
    ),
    VendorTarget(
        name="MSI-Support",
        url="https://www.msi.com/support",
        category="motherboard",
        notes="MSI motherboard/GPU drivers",
    ),
    VendorTarget(
        name="ASRock-Support",
        url="https://www.asrock.com/support/download.asp",
        category="motherboard",
        notes="ASRock motherboard drivers",
    ),
    VendorTarget(
        name="Gigabyte-Support",
        url="https://www.gigabyte.com/Support",
        category="motherboard",
    ),
    VendorTarget(
        name="Asus-Support",
        url="https://www.asus.com/support/",
        category="motherboard",
    ),
    VendorTarget(
        name="Realtek-Audio",
        url="https://www.realtek.com/en/component/zoo/category/pc-audio-codecs-high-definition-audio-codecs-software",
        category="audio",
    ),
    VendorTarget(
        name="Intel-DSA",
        url="https://www.intel.com/content/www/us/en/download-center/home.html",
        category="chipset",
    ),
    VendorTarget(
        name="Catalog-Update",
        url="https://www.catalog.update.microsoft.com/Search.aspx?q=driver",
        category="signed-redist",
        notes="MS Update Catalog: signed-driver redistributables",
    ),
]


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
